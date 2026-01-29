# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse Simpledump log entries. Introduced in macOS Monterey (12)."""

import struct
from dataclasses import dataclass
from typing import Tuple

from ..util import clean_uuid, extract_string


@dataclass
class SimpleDump:
    """Simpledump log entry structure.

    Introduced in macOS Monterey (12). Appears to be a "simpler" version
    of Statedump - so far contains just a single string.
    """
    chunk_tag: int = 0
    chunk_subtag: int = 0
    chunk_data_size: int = 0
    first_proc_id: int = 0
    second_proc_id: int = 0
    continous_time: int = 0
    thread_id: int = 0
    unknown_offset: int = 0
    unknown_ttl: int = 0
    unknown_type: int = 0
    sender_uuid: str = ""
    dsc_uuid: str = ""
    unknown_number_message_strings: int = 0
    unknown_size_subsystem_string: int = 0
    unknown_size_message_string: int = 0
    subsystem: str = ""
    message_string: str = ""

    @staticmethod
    def parse_simpledump(data: bytes) -> Tuple[bytes, 'SimpleDump']:
        """Parse Simpledump log entry.

        Args:
            data: Raw bytes starting at simpledump entry

        Returns:
            Tuple of (remaining data, SimpleDump)
        """
        simpledump_results = SimpleDump()
        offset = 0

        simpledump_results.chunk_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        simpledump_results.chunk_subtag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        simpledump_results.chunk_data_size = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        simpledump_results.first_proc_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        simpledump_results.second_proc_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        simpledump_results.continous_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        simpledump_results.thread_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        simpledump_results.unknown_offset = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        simpledump_results.unknown_ttl = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        simpledump_results.unknown_type = struct.unpack_from('<H', data, offset)[0]
        offset += 2

        # Sender UUID (16 bytes, big endian)
        sender_uuid_high = struct.unpack_from('>Q', data, offset)[0]
        sender_uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
        simpledump_results.sender_uuid = f"{(sender_uuid_high << 64) | sender_uuid_low:032X}"
        offset += 16

        # DSC UUID (16 bytes, big endian)
        dsc_uuid_high = struct.unpack_from('>Q', data, offset)[0]
        dsc_uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
        simpledump_results.dsc_uuid = f"{(dsc_uuid_high << 64) | dsc_uuid_low:032X}"
        offset += 16

        simpledump_results.unknown_number_message_strings = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        simpledump_results.unknown_size_subsystem_string = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        simpledump_results.unknown_size_message_string = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Extract subsystem string
        subsystem_size = simpledump_results.unknown_size_subsystem_string
        subsystem_data = data[offset:offset + subsystem_size]
        offset += subsystem_size

        # Extract message string
        message_size = simpledump_results.unknown_size_message_string
        message_data = data[offset:offset + message_size]
        offset += message_size

        if subsystem_data:
            _, simpledump_results.subsystem = extract_string(subsystem_data)

        if message_data:
            _, simpledump_results.message_string = extract_string(message_data)

        return (data[offset:], simpledump_results)
