# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse Statedump log entries containing plist, custom objects, or protocol buffers."""

import json
import logging
import plistlib
import struct
from dataclasses import dataclass
from typing import Tuple

from ..util import clean_uuid, encode_standard, extract_string

logger = logging.getLogger(__name__)


@dataclass
class Statedump:
    """Statedump log entry structure.

    Statedumps are special log entries that may contain a plist file,
    custom object, or protocol buffer.
    """
    chunk_tag: int = 0
    chunk_subtag: int = 0
    chunk_data_size: int = 0
    first_proc_id: int = 0
    second_proc_id: int = 0
    ttl: int = 0
    unknown_reserved: bytes = b''  # 3 bytes
    continuous_time: int = 0
    activity_id: int = 0
    uuid: str = ""
    unknown_data_type: int = 0  # 1 = plist, 3 = custom object, 2 = protocol buffer?
    unknown_data_size: int = 0  # Size of statedump data
    decoder_library: str = ""
    decoder_type: str = ""
    title_name: str = ""
    statedump_data: bytes = b''

    @staticmethod
    def parse_statedump(data: bytes) -> Tuple[bytes, 'Statedump']:
        """Parse Statedump log entry.

        Args:
            data: Raw bytes starting at statedump entry

        Returns:
            Tuple of (remaining data, Statedump)
        """
        statedump_results = Statedump()
        offset = 0

        statedump_results.chunk_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        statedump_results.chunk_subtag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        statedump_results.chunk_data_size = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        statedump_results.first_proc_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        statedump_results.second_proc_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        statedump_results.ttl = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        statedump_results.unknown_reserved = data[offset:offset + 3]
        offset += 3
        statedump_results.continuous_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        statedump_results.activity_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8

        # UUID (16 bytes, big endian)
        uuid_high = struct.unpack_from('>Q', data, offset)[0]
        uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
        statedump_results.uuid = f"{(uuid_high << 64) | uuid_low:032X}"
        offset += 16

        statedump_results.unknown_data_type = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        statedump_results.unknown_data_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        CUSTOM_DECODER = 3
        STRING_SIZE = 64

        # Handle different data types
        if statedump_results.unknown_data_type != CUSTOM_DECODER:
            # Skip unknown data for non-custom types
            offset += STRING_SIZE  # Skip first 64-byte block
            offset += STRING_SIZE  # Skip second 64-byte block
        else:
            # Custom decoder - extract library and type names
            library_data = data[offset:offset + STRING_SIZE]
            offset += STRING_SIZE
            type_data = data[offset:offset + STRING_SIZE]
            offset += STRING_SIZE

            _, statedump_results.decoder_library = extract_string(library_data)
            _, statedump_results.decoder_type = extract_string(type_data)

        # Extract title name
        title_data = data[offset:offset + STRING_SIZE]
        offset += STRING_SIZE
        _, statedump_results.title_name = extract_string(title_data)

        # Extract statedump data
        statedump_results.statedump_data = data[offset:offset + statedump_results.unknown_data_size]
        offset += statedump_results.unknown_data_size

        return (data[offset:], statedump_results)

    @staticmethod
    def parse_statedump_plist(plist_data: bytes) -> str:
        """Parse the binary plist file in the log.

        Args:
            plist_data: Raw plist bytes

        Returns:
            JSON string representation of the plist
        """
        if not plist_data:
            logger.info("[macos-unifiedlogs] Empty plist data in statedump")
            return "Empty plist data"

        try:
            data = plistlib.loads(plist_data)
            return json.dumps(data)
        except Exception as err:
            logger.error(f"[macos-unifiedlogs] Failed to parse statedump plist data: {err}")
            return "Failed to get plist data"

    @staticmethod
    def parse_statedump_object(object_data: bytes, name: str) -> str:
        """Parse custom Apple objects.

        Args:
            object_data: Raw object data
            name: Name of the object type

        Returns:
            String representation of the parsed object
        """
        # For now, just base64 encode unsupported objects
        # TODO: Implement specific decoders for:
        # - CLDaemonStatusStateTracker
        # - CLClientManagerStateTracker
        # - CLLocationManagerStateTracker
        # - DNS Configuration
        # - Network information
        return f"Unsupported Statedump object: {name}-{encode_standard(object_data)}"
