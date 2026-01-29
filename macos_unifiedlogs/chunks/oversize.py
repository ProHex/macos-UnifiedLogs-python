# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse oversize log entries containing strings too large for normal Firehose entries."""

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .firehose.firehose_log import FirehoseItemData, FirehoseItemInfo

logger = logging.getLogger(__name__)


@dataclass
class Oversize:
    """Oversize log entry structure."""
    chunk_tag: int = 0
    chunk_subtag: int = 0
    chunk_data_size: int = 0
    first_proc_id: int = 0
    second_proc_id: int = 0
    ttl: int = 0
    unknown_reserved: bytes = b''  # 3 bytes
    continuous_time: int = 0
    data_ref_index: int = 0
    public_data_size: int = 0
    private_data_size: int = 0
    message_items: 'FirehoseItemData' = None

    def __post_init__(self):
        if self.message_items is None:
            from .firehose.firehose_log import FirehoseItemData
            self.message_items = FirehoseItemData()

    @staticmethod
    def parse_oversize(data: bytes) -> Tuple[bytes, 'Oversize']:
        """Parse the oversize log entry.

        Oversize entries contain strings that are too large to fit in
        a normal Firehose log entry.

        Args:
            data: Raw bytes starting at oversize entry

        Returns:
            Tuple of (remaining data, Oversize)
        """
        from .firehose.firehose_log import FirehosePreamble

        oversize_results = Oversize()
        offset = 0

        oversize_results.chunk_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        oversize_results.chunk_subtag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        oversize_results.chunk_data_size = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        oversize_results.first_proc_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        oversize_results.second_proc_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        oversize_results.ttl = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        oversize_results.unknown_reserved = data[offset:offset + 3]
        offset += 3
        oversize_results.continuous_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        oversize_results.data_ref_index = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        oversize_results.public_data_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        oversize_results.private_data_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2

        oversize_data_size = oversize_results.public_data_size + oversize_results.private_data_size

        # Sanity check
        remaining = len(data) - offset
        if oversize_data_size > remaining:
            logger.warning(
                "[macos-unifiedlogs] Oversize data size greater than remaining string size. "
                "Using remaining string size"
            )
            oversize_data_size = remaining

        pub_data = data[offset:offset + oversize_data_size]
        offset += oversize_data_size

        # Parse message items (skip first byte, get item count from second)
        if len(pub_data) >= 2:
            item_count = pub_data[1]
            message_data = pub_data[2:]

            empty_flags = 0
            remaining, firehose_item_data = FirehosePreamble.collect_items(
                message_data, item_count, empty_flags
            )

            # Parse private data
            FirehosePreamble._parse_private_data(remaining, firehose_item_data)
            oversize_results.message_items = firehose_item_data

        return (data[offset:], oversize_results)

    @staticmethod
    def get_oversize_strings(
        data_ref: int,
        first_proc_id: int,
        second_proc_id: int,
        oversize_data: List['Oversize'],
    ) -> List['FirehoseItemInfo']:
        """Get firehose item info from oversize log entry based on IDs.

        Args:
            data_ref: Data reference index
            first_proc_id: First process ID
            second_proc_id: Second process ID
            oversize_data: List of parsed Oversize entries

        Returns:
            List of FirehoseItemInfo from matching oversize entry
        """
        from .firehose.firehose_log import FirehoseItemInfo

        message_strings: List[FirehoseItemInfo] = []

        for oversize in oversize_data:
            if (data_ref == oversize.data_ref_index
                    and first_proc_id == oversize.first_proc_id
                    and second_proc_id == oversize.second_proc_id):
                for message in oversize.message_items.item_info:
                    oversize_firehose = FirehoseItemInfo(
                        message_strings=message.message_strings,
                        item_type=message.item_type,
                        item_size=message.item_size,
                    )
                    message_strings.append(oversize_firehose)
                return message_strings

        logger.info(
            f"Did not find any oversize log entries from Data Ref ID: {data_ref}, "
            f"First Proc ID: {first_proc_id}, and Second Proc ID: {second_proc_id}"
        )
        return message_strings
