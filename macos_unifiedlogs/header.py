# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse the Unified Log tracev3 header data."""

import logging
import struct
from dataclasses import dataclass
from typing import Tuple

logger = logging.getLogger(__name__)

# Header chunk tag
HEADER_CHUNK_TAG = 0x1000


@dataclass
class HeaderChunk:
    """TraceV3 header chunk structure."""
    chunk_tag: int = 0
    chunk_sub_tag: int = 0
    chunk_data_size: int = 0
    mach_time_numerator: int = 0
    mach_time_denominator: int = 0
    continous_time: int = 0
    unknown_time: int = 0  # possibly start time
    unknown: int = 0
    bias_min: int = 0
    daylight_savings: int = 0  # 0 no DST, 1 DST
    unknown_flags: int = 0
    sub_chunk_tag: int = 0  # 0x6100
    sub_chunk_data_size: int = 0
    sub_chunk_continous_time: int = 0
    sub_chunk_tag_2: int = 0  # 0x6101
    sub_chunk_tag_data_size_2: int = 0
    unknown_2: int = 0
    unknown_3: int = 0
    build_version_string: str = ""
    hardware_model_string: str = ""
    sub_chunk_tag_3: int = 0  # 0x6102
    sub_chunk_tag_data_size_3: int = 0
    boot_uuid: str = ""
    logd_pid: int = 0
    logd_exit_status: int = 0
    sub_chunk_tag_4: int = 0  # 0x6103
    sub_chunk_tag_data_size_4: int = 0
    timezone_path: str = ""

    @staticmethod
    def parse_header(data: bytes) -> Tuple[bytes, 'HeaderChunk']:
        """Parse the Unified Log tracev3 header data.

        Args:
            data: Raw bytes starting at header chunk

        Returns:
            Tuple of (remaining data, HeaderChunk)
        """
        header_chunk = HeaderChunk()

        offset = 0

        # Parse main header fields
        header_chunk.chunk_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.chunk_sub_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.chunk_data_size = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        header_chunk.mach_time_numerator = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.mach_time_denominator = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.continous_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        header_chunk.unknown_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        header_chunk.unknown = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.bias_min = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.daylight_savings = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.unknown_flags = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Sub-chunk 1 (0x6100)
        header_chunk.sub_chunk_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.sub_chunk_data_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.sub_chunk_continous_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8

        # Sub-chunk 2 (0x6101)
        header_chunk.sub_chunk_tag_2 = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.sub_chunk_tag_data_size_2 = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.unknown_2 = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.unknown_3 = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Build version string (16 bytes)
        build_version_bytes = data[offset:offset + 16]
        offset += 16
        try:
            header_chunk.build_version_string = build_version_bytes.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError as err:
            logger.warning(f"[macos-unifiedlogs] Failed to get build version from header: {err}")

        # Hardware model string (32 bytes)
        hardware_model_bytes = data[offset:offset + 32]
        offset += 32
        try:
            header_chunk.hardware_model_string = hardware_model_bytes.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError as err:
            logger.warning(f"[macos-unifiedlogs] Failed to get hardware info from header: {err}")

        # Sub-chunk 3 (0x6102)
        header_chunk.sub_chunk_tag_3 = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.sub_chunk_tag_data_size_3 = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Boot UUID (16 bytes, big endian)
        uuid_high = struct.unpack_from('>Q', data, offset)[0]
        uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
        header_chunk.boot_uuid = f"{(uuid_high << 64) | uuid_low:032X}"
        offset += 16

        header_chunk.logd_pid = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.logd_exit_status = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Sub-chunk 4 (0x6103)
        header_chunk.sub_chunk_tag_4 = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        header_chunk.sub_chunk_tag_data_size_4 = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Timezone path (48 bytes)
        timezone_path_bytes = data[offset:offset + 48]
        offset += 48
        try:
            header_chunk.timezone_path = timezone_path_bytes.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError as err:
            logger.warning(f"[macos-unifiedlogs] Failed to get timezone path from header: {err}")

        return (data[offset:], header_chunk)
