# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse the UUID files in uuidinfo directory. Contains the base log message string."""

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Tuple

from .error import InvalidSignatureError

logger = logging.getLogger(__name__)

# UUIDText signature
UUIDTEXT_SIGNATURE = 0x66778899


@dataclass
class UUIDTextEntry:
    """UUIDText entry descriptor."""
    range_start_offset: int = 0
    entry_size: int = 0


@dataclass
class UUIDText:
    """UUIDText file structure."""
    uuid: str = ""
    signature: int = 0
    unknown_major_version: int = 0
    unknown_minor_version: int = 0
    number_entries: int = 0
    entry_descriptors: List[UUIDTextEntry] = field(default_factory=list)
    footer_data: bytes = b''  # Collection of strings containing sender process/library

    @staticmethod
    def parse_uuidtext(data: bytes) -> Tuple[bytes, 'UUIDText']:
        """Parse the UUID files in uuidinfo directory.

        Args:
            data: Raw bytes from UUIDText file

        Returns:
            Tuple of (remaining data, UUIDText)

        Raises:
            InvalidSignatureError: If the file signature is incorrect
        """
        if len(data) < 16:
            raise InvalidSignatureError(UUIDTEXT_SIGNATURE, 0, "UUIDText")

        uuidtext_data = UUIDText()

        # signature: u32, major_version: u32, minor_version: u32, num_entries: u32
        signature = struct.unpack_from('<I', data, 0)[0]

        if signature != UUIDTEXT_SIGNATURE:
            logger.error(
                f"[macos-unifiedlogs] Incorrect UUIDText header signature. "
                f"Expected {UUIDTEXT_SIGNATURE:#x}. Got: {signature:#x}"
            )
            raise InvalidSignatureError(UUIDTEXT_SIGNATURE, signature, "UUIDText")

        unknown_major_version = struct.unpack_from('<I', data, 4)[0]
        unknown_minor_version = struct.unpack_from('<I', data, 8)[0]
        number_entries = struct.unpack_from('<I', data, 12)[0]

        uuidtext_data.signature = signature
        uuidtext_data.unknown_major_version = unknown_major_version
        uuidtext_data.unknown_minor_version = unknown_minor_version
        uuidtext_data.number_entries = number_entries

        offset = 16
        for _ in range(number_entries):
            if offset + 8 > len(data):
                break
            range_start_offset = struct.unpack_from('<I', data, offset)[0]
            entry_size = struct.unpack_from('<I', data, offset + 4)[0]

            entry = UUIDTextEntry(
                range_start_offset=range_start_offset,
                entry_size=entry_size,
            )
            uuidtext_data.entry_descriptors.append(entry)
            offset += 8

        uuidtext_data.footer_data = data[offset:]

        return (data[offset:], uuidtext_data)
