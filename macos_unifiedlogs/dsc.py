# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse shared strings data (the file(s) in /private/var/db/uuidtext/dsc)."""

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Tuple

from .error import InvalidSignatureError
from .util import extract_string

logger = logging.getLogger(__name__)

# DSC signature: "hcsd" in little endian
DSC_SIGNATURE = 0x64736368


@dataclass
class RangeDescriptor:
    """Range descriptor for DSC shared cache strings."""
    range_offset: int = 0  # In Major version 2 this is 8 bytes, in version 1 it's 4 bytes
    data_offset: int = 0
    range_size: int = 0
    unknown_uuid_index: int = 0  # Unknown value, added in Major version 2. In version 1 the index is at start
    strings: bytes = b''


@dataclass
class UUIDDescriptor:
    """UUID descriptor for DSC shared cache strings."""
    text_offset: int = 0  # Size is 8 bytes in Major version 2, 4 bytes in version 1
    text_size: int = 0
    uuid: str = ""
    path_offset: int = 0
    path_string: str = ""  # Not part of format, populated after parsing


@dataclass
class SharedCacheStrings:
    """Shared cache strings (DSC) structure."""
    signature: int = 0
    major_version: int = 0  # Version 1 up to Big Sur. Monterey has Version 2!
    minor_version: int = 0
    number_ranges: int = 0
    number_uuids: int = 0
    ranges: List[RangeDescriptor] = field(default_factory=list)
    uuids: List[UUIDDescriptor] = field(default_factory=list)
    dsc_uuid: str = ""

    @staticmethod
    def parse_dsc(data: bytes) -> Tuple[bytes, 'SharedCacheStrings']:
        """Parse shared strings data (the file(s) in /private/var/db/uuidtext/dsc).

        Args:
            data: Raw bytes from DSC file

        Returns:
            Tuple of (remaining data, SharedCacheStrings)

        Raises:
            InvalidSignatureError: If the file signature is incorrect
        """
        if len(data) < 16:
            raise InvalidSignatureError(DSC_SIGNATURE, 0, "DSC")

        signature = struct.unpack_from('<I', data, 0)[0]

        if signature != DSC_SIGNATURE:
            logger.error(
                f"[macos-unifiedlogs] Incorrect DSC file signature. "
                f"Expected {DSC_SIGNATURE:#x}. Got: {signature:#x}"
            )
            raise InvalidSignatureError(DSC_SIGNATURE, signature, "DSC")

        shared_cache_strings = SharedCacheStrings(signature=signature)

        major_version = struct.unpack_from('<H', data, 4)[0]
        minor_version = struct.unpack_from('<H', data, 6)[0]
        number_ranges = struct.unpack_from('<I', data, 8)[0]
        number_uuids = struct.unpack_from('<I', data, 12)[0]

        shared_cache_strings.major_version = major_version
        shared_cache_strings.minor_version = minor_version
        shared_cache_strings.number_ranges = number_ranges
        shared_cache_strings.number_uuids = number_uuids

        offset = 16

        # Parse ranges
        for _ in range(number_ranges):
            remaining, range_data = SharedCacheStrings._get_ranges(data[offset:], major_version)
            shared_cache_strings.ranges.append(range_data)
            offset = len(data) - len(remaining)

        # Parse UUIDs
        for _ in range(number_uuids):
            remaining, uuid_data = SharedCacheStrings._get_uuids(data[offset:], major_version)
            shared_cache_strings.uuids.append(uuid_data)
            offset = len(data) - len(remaining)

        # Get path strings for each UUID
        for uuid_desc in shared_cache_strings.uuids:
            _, path_string = SharedCacheStrings._get_paths(data, uuid_desc.path_offset)
            uuid_desc.path_string = path_string

        # Get strings for each range
        for range_desc in shared_cache_strings.ranges:
            _, strings = SharedCacheStrings._get_strings(
                data, range_desc.data_offset, range_desc.range_size
            )
            range_desc.strings = strings

        return (data[offset:], shared_cache_strings)

    @staticmethod
    def _get_ranges(data: bytes, version: int) -> Tuple[bytes, RangeDescriptor]:
        """Get range data, used by log entries to determine where the base string entry is located.

        Args:
            data: Raw bytes starting at range descriptor
            version: DSC major version

        Returns:
            Tuple of (remaining data, RangeDescriptor)
        """
        range_data = RangeDescriptor()
        offset = 0

        # Version 2 (Monterey and higher) changed the Range format
        # range offset is now 8 bytes (vs 4 bytes) and starts at beginning
        # The uuid index was moved to end
        if version == 2:
            range_data.range_offset = struct.unpack_from('<Q', data, offset)[0]
            offset += 8
        else:
            # Version 1: UUID index at start, then 4-byte range offset
            range_data.unknown_uuid_index = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            range_data.range_offset = struct.unpack_from('<I', data, offset)[0]
            offset += 4

        range_data.data_offset = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        range_data.range_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # UUID index is now located at the end of the format (instead of beginning) in v2
        if version == 2:
            range_data.unknown_uuid_index = struct.unpack_from('<Q', data, offset)[0]
            offset += 8

        return (data[offset:], range_data)

    @staticmethod
    def _get_uuids(data: bytes, version: int) -> Tuple[bytes, UUIDDescriptor]:
        """Get UUID entries related to ranges.

        Args:
            data: Raw bytes starting at UUID descriptor
            version: DSC major version

        Returns:
            Tuple of (remaining data, UUIDDescriptor)
        """
        uuid_data = UUIDDescriptor()
        offset = 0

        if version == 2:
            uuid_data.text_offset = struct.unpack_from('<Q', data, offset)[0]
            offset += 8
        else:
            uuid_data.text_offset = struct.unpack_from('<I', data, offset)[0]
            offset += 4

        uuid_data.text_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # UUID is 128-bit big endian
        uuid_high = struct.unpack_from('>Q', data, offset)[0]
        uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
        uuid_data.uuid = f"{(uuid_high << 64) | uuid_low:032X}"
        offset += 16

        uuid_data.path_offset = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        return (data[offset:], uuid_data)

    @staticmethod
    def _get_paths(data: bytes, path_offset: int) -> Tuple[bytes, str]:
        """Get path string at the given offset.

        Args:
            data: Full DSC file data
            path_offset: Offset to path string

        Returns:
            Tuple of (remaining data at offset, path string)
        """
        _, path = extract_string(data[path_offset:])
        return (data[path_offset:], path)

    @staticmethod
    def _get_strings(data: bytes, string_offset: int, string_range: int) -> Tuple[bytes, bytes]:
        """After parsing the ranges and UUIDs remaining data are the base log entry strings.

        Args:
            data: Full DSC file data
            string_offset: Offset to string data
            string_range: Size of string data

        Returns:
            Tuple of (empty bytes, string data)
        """
        strings = data[string_offset:string_offset + string_range]
        return (b'', strings)
