# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Chunk-by-chunk iteration for macOS Unified Logs."""

import logging
from dataclasses import dataclass, field
from typing import Iterator, Optional, Tuple

from .catalog import CatalogChunk
from .chunks.firehose.firehose_log import FirehosePreamble
from .chunks.oversize import Oversize
from .chunks.simpledump import SimpleDump
from .chunks.statedump import Statedump
from .chunkset import ChunksetChunk
from .header import HeaderChunk
from .preamble import LogPreamble
from .util import padding_size_8

logger = logging.getLogger(__name__)


@dataclass
class UnifiedLogIteratorCatalogData:
    """Catalog data collected during iteration."""
    catalog: CatalogChunk = field(default_factory=CatalogChunk)
    firehose: list = field(default_factory=list)
    simpledump: list = field(default_factory=list)
    statedump: list = field(default_factory=list)
    oversize: list = field(default_factory=list)


@dataclass
class UnifiedLogIteratorData:
    """Data yielded by the iterator for each catalog."""
    header: list = field(default_factory=list)
    catalog_data: list = field(default_factory=list)
    oversize: list = field(default_factory=list)


class UnifiedLogIterator:
    """Iterator for processing tracev3 files chunk by chunk.

    This allows processing large log files without loading everything into memory.
    """

    HEADER_CHUNK = 0x1000
    CATALOG_CHUNK = 0x600b
    CHUNKSET_CHUNK = 0x600d
    CHUNK_PREAMBLE_SIZE = 16

    def __init__(self, data: bytes):
        """Initialize the iterator.

        Args:
            data: Raw bytes from tracev3 file
        """
        self._data = data
        self._offset = 0
        self._headers: list = []
        self._current_catalog: Optional[UnifiedLogIteratorCatalogData] = None
        self._global_oversize: list = []

    def __iter__(self) -> Iterator[UnifiedLogIteratorData]:
        """Return the iterator."""
        return self

    def __next__(self) -> UnifiedLogIteratorData:
        """Get the next complete catalog with its data.

        Returns:
            UnifiedLogIteratorData containing header, catalog data, and oversize entries

        Raises:
            StopIteration: When all data has been processed
        """
        while self._offset + self.CHUNK_PREAMBLE_SIZE <= len(self._data):
            try:
                _, preamble = LogPreamble.detect_preamble(self._data[self._offset:])
            except Exception as e:
                logger.warning(f"Failed to detect preamble at offset {self._offset}: {e}")
                raise StopIteration

            chunk_size = preamble.chunk_data_size
            total_size = chunk_size + self.CHUNK_PREAMBLE_SIZE

            if self._offset + total_size > len(self._data):
                logger.warning(f"Not enough data for chunk at offset {self._offset}")
                raise StopIteration

            chunk_data = self._data[self._offset:self._offset + total_size]
            self._offset += total_size

            if preamble.chunk_tag == self.HEADER_CHUNK:
                self._process_header(chunk_data)

            elif preamble.chunk_tag == self.CATALOG_CHUNK:
                # If we have a previous catalog, yield it
                result = None
                if self._current_catalog is not None and self._current_catalog.catalog.chunk_tag != 0:
                    result = UnifiedLogIteratorData(
                        header=self._headers[:],
                        catalog_data=[self._current_catalog],
                        oversize=self._global_oversize[:],
                    )

                # Start a new catalog
                self._current_catalog = UnifiedLogIteratorCatalogData()
                self._process_catalog(chunk_data)

                # Handle padding
                padding = padding_size_8(preamble.chunk_data_size)
                if self._offset + padding <= len(self._data):
                    self._offset += padding

                if result is not None:
                    return result

            elif preamble.chunk_tag == self.CHUNKSET_CHUNK:
                if self._current_catalog is None:
                    self._current_catalog = UnifiedLogIteratorCatalogData()
                self._process_chunkset(chunk_data)

            else:
                logger.error(f"[macos-unifiedlogs] Unknown chunk type: {preamble.chunk_tag}")

            # Handle padding
            padding = padding_size_8(preamble.chunk_data_size)
            if self._offset + padding <= len(self._data):
                self._offset += padding

        # Yield the last catalog if we have one
        if self._current_catalog is not None and self._current_catalog.catalog.chunk_tag != 0:
            result = UnifiedLogIteratorData(
                header=self._headers[:],
                catalog_data=[self._current_catalog],
                oversize=self._global_oversize[:],
            )
            self._current_catalog = None
            return result

        raise StopIteration

    def _process_header(self, data: bytes) -> None:
        """Process a header chunk.

        Args:
            data: Raw header chunk data
        """
        try:
            _, header_data = HeaderChunk.parse_header(data)
            self._headers.append(header_data)
        except Exception as e:
            logger.error(f"[macos-unifiedlogs] Failed to parse header data: {e}")

    def _process_catalog(self, data: bytes) -> None:
        """Process a catalog chunk.

        Args:
            data: Raw catalog chunk data
        """
        if self._current_catalog is None:
            return

        try:
            _, catalog = CatalogChunk.parse_catalog(data)
            self._current_catalog.catalog = catalog
        except Exception as e:
            logger.error(f"[macos-unifiedlogs] Failed to parse catalog data: {e}")

    def _process_chunkset(self, data: bytes) -> None:
        """Process a chunkset chunk.

        Args:
            data: Raw chunkset chunk data
        """
        if self._current_catalog is None:
            return

        try:
            _, chunkset_data = ChunksetChunk.parse_chunkset(data)

            # Create a temporary catalog data object for parsing
            from .unified_log import UnifiedLogCatalogData
            temp_catalog = UnifiedLogCatalogData()
            temp_catalog.catalog = self._current_catalog.catalog

            ChunksetChunk.parse_chunkset_data(chunkset_data.decompressed_data, temp_catalog)

            # Copy the parsed data back
            self._current_catalog.firehose.extend(temp_catalog.firehose)
            self._current_catalog.simpledump.extend(temp_catalog.simpledump)
            self._current_catalog.statedump.extend(temp_catalog.statedump)
            self._current_catalog.oversize.extend(temp_catalog.oversize)

            # Also add to global oversize for cross-catalog lookups
            self._global_oversize.extend(temp_catalog.oversize)

        except Exception as e:
            logger.error(f"[macos-unifiedlogs] Failed to parse chunkset data: {e}")
