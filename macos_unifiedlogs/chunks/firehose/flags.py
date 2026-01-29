# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Identify formatter flags associated with the log entry."""

import logging
import struct
from dataclasses import dataclass
from typing import Tuple

logger = logging.getLogger(__name__)


@dataclass
class FirehoseFormatters:
    """Formatter flags determine the file where the base format string is located."""
    main_exe: bool = False
    shared_cache: bool = False
    has_large_offset: int = 0
    large_shared_cache: int = 0
    absolute: bool = False
    uuid_relative: str = ""
    main_plugin: bool = False  # Not seen yet
    pc_style: bool = False  # Not seen yet
    main_exe_alt_index: int = 0  # If log entry uses an alternative uuid file index

    @staticmethod
    def firehose_formatter_flags(
        data: bytes, firehose_flags: int
    ) -> Tuple[bytes, 'FirehoseFormatters']:
        """Identify formatter flags associated with the log entry.

        Formatter flags determine the file where the base format string is located.

        Flags:
            0x20 - has_large_offset flag. Offset to format string is larger than normal
            0xc - has_large_shared_cache flag. Offset to format string is larger than normal
            0x8 - absolute flag. The log uses an alternative index number that points to
                  the UUID file name in the Catalog which contains the format string
            0x2 - main_exe flag. A UUID file contains the format string
            0x4 - shared_cache flag. DSC file contains the format string
            0xa - uuid_relative flag. The UUID file name is in the log data (instead of Catalog)

        Args:
            data: Raw bytes after log entry header
            firehose_flags: Flag value from log entry

        Returns:
            Tuple of (remaining data, FirehoseFormatters)
        """
        formatter_flags = FirehoseFormatters()
        offset = 0

        message_strings_uuid = 0x2  # main_exe flag
        large_shared_cache = 0xc  # large_shared_cache flag
        large_offset = 0x20  # has_large_offset flag
        flag_check = 0xe

        flag_value = firehose_flags & flag_check

        if flag_value == 0x20:
            # has_large_offset flag
            logger.debug("[macos-unifiedlogs] Firehose flag: has_large_offset")
            formatter_flags.has_large_offset = struct.unpack_from('<H', data, offset)[0]
            offset += 2

            if (firehose_flags & large_shared_cache) != 0:
                logger.debug(
                    "[macos-unifiedlogs] Firehose flag: large_shared_cache and has_large_offset"
                )
                formatter_flags.large_shared_cache = struct.unpack_from('<H', data, offset)[0]
                offset += 2

        elif flag_value == 0xc:
            # large_shared_cache flag
            logger.debug("[macos-unifiedlogs] Firehose flag: large_shared_cache")

            if (firehose_flags & large_offset) != 0:
                formatter_flags.has_large_offset = struct.unpack_from('<H', data, offset)[0]
                offset += 2

            formatter_flags.large_shared_cache = struct.unpack_from('<H', data, offset)[0]
            offset += 2

        elif flag_value == 0x8:
            # absolute flag
            logger.debug("[macos-unifiedlogs] Firehose flag: absolute")
            formatter_flags.absolute = True

            if (firehose_flags & message_strings_uuid) == 0:
                logger.debug("[macos-unifiedlogs] Firehose flag: alt index absolute flag")
                formatter_flags.main_exe_alt_index = struct.unpack_from('<H', data, offset)[0]
                offset += 2

        elif flag_value == 0x2:
            # main_exe flag
            logger.debug("[macos-unifiedlogs] Firehose flag: main_exe")
            formatter_flags.main_exe = True

        elif flag_value == 0x4:
            # shared_cache flag
            logger.debug("[macos-unifiedlogs] Firehose flag: shared_cache")
            formatter_flags.shared_cache = True

            if (firehose_flags & large_offset) != 0:
                formatter_flags.has_large_offset = struct.unpack_from('<H', data, offset)[0]
                offset += 2

        elif flag_value == 0xa:
            # uuid_relative flag
            logger.debug("[macos-unifiedlogs] Firehose flag: uuid_relative")
            uuid_high = struct.unpack_from('>Q', data, offset)[0]
            uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
            formatter_flags.uuid_relative = f"{(uuid_high << 64) | uuid_low:032X}"
            offset += 16

        else:
            logger.error(f"[macos-unifiedlogs] Unknown Firehose formatter flag: {firehose_flags}")
            logger.debug(f"[macos-unifiedlogs] Firehose data: {data[:32].hex()}")
            raise ValueError(f"Unknown Firehose formatter flag: {firehose_flags}")

        return (data[offset:], formatter_flags)
