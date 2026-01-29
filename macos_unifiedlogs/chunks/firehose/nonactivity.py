# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse non-activity log type (0x4) - standard logs."""

import logging
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Tuple

from .flags import FirehoseFormatters

if TYPE_CHECKING:
    from ...catalog import CatalogChunk
    from ...traits import FileProvider

logger = logging.getLogger(__name__)


@dataclass
class FirehoseNonActivity:
    """Non-activity log type structure - standard logs like log default, log error, etc."""
    unknown_activity_id: int = 0
    unknown_sentinal: int = 0
    private_strings_offset: int = 0
    private_strings_size: int = 0
    unknown_message_string_ref: int = 0
    subsystem_value: int = 0
    ttl_value: int = 0
    data_ref_value: int = 0
    firehose_formatters: FirehoseFormatters = None

    def __post_init__(self):
        if self.firehose_formatters is None:
            self.firehose_formatters = FirehoseFormatters()

    @staticmethod
    def parse_non_activity(data: bytes, firehose_flags: int) -> Tuple[bytes, 'FirehoseNonActivity']:
        """Parse non-activity log type entry.

        Args:
            data: Raw bytes starting at non-activity data
            firehose_flags: Flags from firehose entry

        Returns:
            Tuple of (remaining data, FirehoseNonActivity)
        """
        non_activity = FirehoseNonActivity()
        offset = 0

        non_activity.unknown_activity_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        non_activity.unknown_sentinal = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Check for private strings
        private_string_range = 0x100
        if (firehose_flags & private_string_range) != 0:
            non_activity.private_strings_offset = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            non_activity.private_strings_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2

        # Check for subsystem
        has_subsystem = 0x200
        if (firehose_flags & has_subsystem) != 0:
            non_activity.subsystem_value = struct.unpack_from('<H', data, offset)[0]
            offset += 2

        # Check for TTL
        has_ttl = 0x400
        if (firehose_flags & has_ttl) != 0:
            non_activity.ttl_value = struct.unpack_from('<B', data, offset)[0]
            offset += 1

        # Check for data ref (oversize entry reference)
        has_data_ref = 0x800
        if (firehose_flags & has_data_ref) != 0:
            non_activity.data_ref_value = struct.unpack_from('<I', data, offset)[0]
            offset += 4

        remaining, formatter_flags = FirehoseFormatters.firehose_formatter_flags(
            data[offset:], firehose_flags
        )
        non_activity.firehose_formatters = formatter_flags

        return (remaining, non_activity)

    @staticmethod
    def get_firehose_nonactivity_strings(
        non_activity: 'FirehoseNonActivity',
        provider: 'FileProvider',
        format_string_location: int,
        first_proc_id: int,
        second_proc_id: int,
        catalog: 'CatalogChunk',
    ) -> Tuple[bytes, 'MessageData']:
        """Get format strings for non-activity log entry.

        Args:
            non_activity: The parsed FirehoseNonActivity
            provider: File provider for accessing UUIDText/DSC files
            format_string_location: Offset to format string
            first_proc_id: First process ID
            second_proc_id: Second process ID
            catalog: Catalog chunk with process info

        Returns:
            Tuple of (empty bytes, MessageData with format string info)
        """
        from ...message import MessageData, get_format_string

        return get_format_string(
            non_activity.firehose_formatters,
            provider,
            format_string_location,
            first_proc_id,
            second_proc_id,
            catalog,
        )
