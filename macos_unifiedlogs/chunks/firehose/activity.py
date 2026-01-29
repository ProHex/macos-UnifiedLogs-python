# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse activity log type (0x2)."""

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
class FirehoseActivity:
    """Activity log type structure."""
    unknown_activity_id: int = 0
    unknown_sentinal: int = 0
    pid: int = 0
    unknown_activity_id_2: int = 0
    unknown_sentinal_2: int = 0
    unknown_message_string_ref: int = 0
    firehose_formatters: FirehoseFormatters = None

    def __post_init__(self):
        if self.firehose_formatters is None:
            self.firehose_formatters = FirehoseFormatters()

    @staticmethod
    def parse_activity(
        data: bytes, firehose_flags: int, firehose_log_type: int
    ) -> Tuple[bytes, 'FirehoseActivity']:
        """Parse activity log type entry.

        Args:
            data: Raw bytes starting at activity data
            firehose_flags: Flags from firehose entry
            firehose_log_type: Log type value

        Returns:
            Tuple of (remaining data, FirehoseActivity)
        """
        activity = FirehoseActivity()
        offset = 0

        activity.unknown_activity_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Activity Create has the most data
        activity_create = 0x1
        if firehose_log_type == activity_create:
            activity.unknown_sentinal = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            activity.pid = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            activity.unknown_activity_id_2 = struct.unpack_from('<Q', data, offset)[0]
            offset += 8
            activity.unknown_sentinal_2 = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            activity.unknown_message_string_ref = struct.unpack_from('<I', data, offset)[0]
            offset += 4

        remaining, formatter_flags = FirehoseFormatters.firehose_formatter_flags(
            data[offset:], firehose_flags
        )
        activity.firehose_formatters = formatter_flags

        return (remaining, activity)

    @staticmethod
    def get_firehose_activity_strings(
        activity: 'FirehoseActivity',
        provider: 'FileProvider',
        format_string_location: int,
        first_proc_id: int,
        second_proc_id: int,
        catalog: 'CatalogChunk',
    ) -> Tuple[bytes, 'MessageData']:
        """Get format strings for activity log entry.

        Args:
            activity: The parsed FirehoseActivity
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
            activity.firehose_formatters,
            provider,
            format_string_location,
            first_proc_id,
            second_proc_id,
            catalog,
        )
