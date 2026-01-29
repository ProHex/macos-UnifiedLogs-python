# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse the preamble (first 16 bytes of all Unified Log entries/chunks)."""

import struct
from dataclasses import dataclass
from typing import Tuple


@dataclass
class LogPreamble:
    """Log preamble structure - first 16 bytes of all Unified Log entries (chunks)."""
    chunk_tag: int = 0
    chunk_sub_tag: int = 0
    chunk_data_size: int = 0

    @staticmethod
    def detect_preamble(data: bytes) -> Tuple[bytes, 'LogPreamble']:
        """Get the preamble to detect the log (chunk) type.

        Ex: Firehose, Statedump, Simpledump, Catalog, etc.
        Does not consume the input.

        Args:
            data: Raw bytes starting at chunk preamble

        Returns:
            Tuple of (original data unchanged, LogPreamble)
        """
        _, preamble = LogPreamble.parse(data)
        return (data, preamble)

    @staticmethod
    def parse(data: bytes) -> Tuple[bytes, 'LogPreamble']:
        """Get the preamble and consume the input.

        Args:
            data: Raw bytes starting at chunk preamble

        Returns:
            Tuple of (remaining data after preamble, LogPreamble)
        """
        if len(data) < 16:
            raise ValueError(f"Not enough data for preamble, need 16 bytes, got {len(data)}")

        # chunk_tag: u32, chunk_sub_tag: u32, chunk_data_size: u64
        chunk_tag = struct.unpack_from('<I', data, 0)[0]
        chunk_sub_tag = struct.unpack_from('<I', data, 4)[0]
        chunk_data_size = struct.unpack_from('<Q', data, 8)[0]

        preamble = LogPreamble(
            chunk_tag=chunk_tag,
            chunk_sub_tag=chunk_sub_tag,
            chunk_data_size=chunk_data_size,
        )

        return (data[16:], preamble)
