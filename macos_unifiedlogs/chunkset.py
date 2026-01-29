# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse the Chunkset data that contains the actual log entries."""

import logging
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Tuple

import lz4.block

from .error import DecompressionError, InvalidSignatureError
from .preamble import LogPreamble

if TYPE_CHECKING:
    from .unified_log import UnifiedLogCatalogData

logger = logging.getLogger(__name__)

# Chunkset chunk tag
CHUNKSET_CHUNK_TAG = 0x600d

# Chunkset signatures
BV41_SIGNATURE = 0x31347662  # "bv41" compressed
BV41_UNCOMPRESSED_SIGNATURE = 0x2D347662  # "bv41-" uncompressed

# Chunk types
FIREHOSE_CHUNK = 0x6001
OVERSIZE_CHUNK = 0x6002
STATEDUMP_CHUNK = 0x6003
SIMPLEDUMP_CHUNK = 0x6004


@dataclass
class ChunksetChunk:
    """Chunkset chunk structure containing compressed log entries."""
    chunk_tag: int = 0
    chunk_sub_tag: int = 0
    chunk_data_size: int = 0
    signature: int = 0  # should be "bv41"
    uncompress_size: int = 0
    block_size: int = 0
    decompressed_data: bytes = b''
    footer: int = 0  # should be "bv4$"

    @staticmethod
    def parse_chunkset(data: bytes) -> Tuple[bytes, 'ChunksetChunk']:
        """Parse the Chunkset data that contains the actual log entries.

        Args:
            data: Raw bytes starting at chunkset chunk

        Returns:
            Tuple of (remaining data, ChunksetChunk)
        """
        chunkset_chunk = ChunksetChunk()
        offset = 0

        chunkset_chunk.chunk_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        chunkset_chunk.chunk_sub_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        chunkset_chunk.chunk_data_size = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        chunkset_chunk.signature = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        chunkset_chunk.uncompress_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Data is already decompressed (Observed in tracev3 files in /var/db/diagnostics/Special)
        if chunkset_chunk.signature == BV41_UNCOMPRESSED_SIGNATURE:
            chunkset_chunk.decompressed_data = data[offset:offset + chunkset_chunk.uncompress_size]
            offset += chunkset_chunk.uncompress_size
            chunkset_chunk.footer = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            return (data[offset:], chunkset_chunk)

        # Compressed data signature should be bv41
        if chunkset_chunk.signature != BV41_SIGNATURE:
            logger.error(
                f"[macos-unifiedlogs] Incorrect compression signature expected bv41, "
                f"got: {chunkset_chunk.signature:#x}"
            )
            raise InvalidSignatureError(BV41_SIGNATURE, chunkset_chunk.signature, "Chunkset")

        chunkset_chunk.block_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        compressed_data = data[offset:offset + chunkset_chunk.block_size]
        offset += chunkset_chunk.block_size

        try:
            chunkset_chunk.decompressed_data = lz4.block.decompress(
                compressed_data, uncompressed_size=chunkset_chunk.uncompress_size
            )
        except Exception as err:
            logger.error(f"[macos-unifiedlogs] Failed to decompress log data: {err}")
            raise DecompressionError(f"Failed to decompress log data: {err}")

        chunkset_chunk.footer = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        return (data[offset:], chunkset_chunk)

    @staticmethod
    def parse_chunkset_data(
        data: bytes, unified_log_data: 'UnifiedLogCatalogData'
    ) -> Tuple[bytes, None]:
        """Parse each log (chunk) in the decompressed Chunkset data.

        Args:
            data: Decompressed chunkset data
            unified_log_data: UnifiedLogCatalogData to populate with parsed entries

        Returns:
            Tuple of (remaining data, None)
        """
        # Import here to avoid circular imports
        from .chunks.firehose.firehose_log import FirehosePreamble
        from .chunks.oversize import Oversize
        from .chunks.simpledump import SimpleDump
        from .chunks.statedump import Statedump

        chunk_preamble_size = 16
        offset = 0

        while offset < len(data):
            if len(data) - offset < chunk_preamble_size:
                logger.warning(
                    f"[macos-unifiedlogs] Not enough data for Chunkset preamble header, "
                    f"needed 16 bytes. Got: {len(data) - offset}"
                )
                break

            _, preamble = LogPreamble.detect_preamble(data[offset:])
            chunk_size = preamble.chunk_data_size

            # Grab all data associated with log (chunk) data
            chunk_data = data[offset:offset + chunk_size + chunk_preamble_size]
            offset += chunk_size + chunk_preamble_size

            # Parse based on chunk type
            ChunksetChunk._get_chunkset_data(chunk_data, preamble.chunk_tag, unified_log_data)

            # Skip zero padding
            while offset < len(data) and data[offset] == 0:
                offset += 1

        return (data[offset:], None)

    @staticmethod
    def _get_chunkset_data(
        data: bytes, chunk_type: int, unified_log_data: 'UnifiedLogCatalogData'
    ) -> None:
        """Parse the log entry (chunk) based on type.

        Args:
            data: Chunk data
            chunk_type: Type of chunk (firehose, oversize, etc.)
            unified_log_data: UnifiedLogCatalogData to populate
        """
        # Import here to avoid circular imports
        from .chunks.firehose.firehose_log import FirehosePreamble
        from .chunks.oversize import Oversize
        from .chunks.simpledump import SimpleDump
        from .chunks.statedump import Statedump

        if chunk_type == FIREHOSE_CHUNK:
            try:
                _, firehose_data = FirehosePreamble.parse_firehose_preamble(data)
                unified_log_data.firehose.append(firehose_data)
            except Exception as err:
                logger.error(
                    f"[macos-unifiedlogs] Failed to parse firehose log entry (chunk): {err}"
                )
        elif chunk_type == OVERSIZE_CHUNK:
            try:
                _, oversize = Oversize.parse_oversize(data)
                unified_log_data.oversize.append(oversize)
            except Exception as err:
                logger.error(
                    f"[macos-unifiedlogs] Failed to parse oversize log entry (chunk): {err}"
                )
        elif chunk_type == STATEDUMP_CHUNK:
            try:
                _, statedump = Statedump.parse_statedump(data)
                unified_log_data.statedump.append(statedump)
            except Exception as err:
                logger.error(
                    f"[macos-unifiedlogs] Failed to parse statedump log entry (chunk): {err}"
                )
        elif chunk_type == SIMPLEDUMP_CHUNK:
            try:
                _, simpledump = SimpleDump.parse_simpledump(data)
                unified_log_data.simpledump.append(simpledump)
            except Exception as err:
                logger.error(
                    f"[macos-unifiedlogs] Failed to parse simpledump log entry (chunk): {err}"
                )
        else:
            logger.error(f"[macos-unifiedlogs] Unknown chunkset type: {chunk_type:#x}")
