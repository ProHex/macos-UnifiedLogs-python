# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse trace log type (0x3)."""

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
class FirehoseTrace:
    """Trace log type structure."""
    unknown_pc_id: int = 0
    message_data: bytes = b''
    firehose_formatters: FirehoseFormatters = None

    def __post_init__(self):
        if self.firehose_formatters is None:
            self.firehose_formatters = FirehoseFormatters()

    @staticmethod
    def parse_firehose_trace(data: bytes, firehose_flags: int) -> Tuple[bytes, 'FirehoseTrace']:
        """Parse trace log type entry.

        Args:
            data: Raw bytes starting at trace data
            firehose_flags: Flags from firehose entry

        Returns:
            Tuple of (remaining data, FirehoseTrace)
        """
        trace = FirehoseTrace()
        offset = 0

        trace.unknown_pc_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        remaining, formatter_flags = FirehoseFormatters.firehose_formatter_flags(
            data[offset:], firehose_flags
        )
        trace.firehose_formatters = formatter_flags
        trace.message_data = remaining

        return (remaining, trace)

    @staticmethod
    def get_firehose_trace_strings(
        trace: 'FirehoseTrace',
        provider: 'FileProvider',
        format_string_location: int,
        first_proc_id: int,
        second_proc_id: int,
        catalog: 'CatalogChunk',
    ) -> Tuple[bytes, 'MessageData']:
        """Get format strings for trace log entry.

        Args:
            trace: The parsed FirehoseTrace
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
            trace.firehose_formatters,
            provider,
            format_string_location,
            first_proc_id,
            second_proc_id,
            catalog,
        )
