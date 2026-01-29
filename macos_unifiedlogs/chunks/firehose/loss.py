# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse loss log type (0x7)."""

import logging
import struct
from dataclasses import dataclass
from typing import Tuple

logger = logging.getLogger(__name__)


@dataclass
class FirehoseLoss:
    """Loss log type structure - indicates log data was lost."""
    start_time: int = 0
    end_time: int = 0
    count: int = 0

    @staticmethod
    def parse_firehose_loss(data: bytes) -> Tuple[bytes, 'FirehoseLoss']:
        """Parse loss log type entry.

        Loss entries indicate that log data was lost due to high volume
        or other reasons.

        Args:
            data: Raw bytes starting at loss data

        Returns:
            Tuple of (remaining data, FirehoseLoss)
        """
        loss = FirehoseLoss()
        offset = 0

        loss.start_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        loss.end_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        loss.count = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        return (data[offset:], loss)
