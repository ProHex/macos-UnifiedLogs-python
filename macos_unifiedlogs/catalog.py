# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse log Catalog data containing metadata related to log entries."""

import logging
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .preamble import LogPreamble
from .util import anticipated_padding_size_8, extract_string

logger = logging.getLogger(__name__)

# Catalog chunk tag
CATALOG_CHUNK_TAG = 0x600b

# LZ4 compression algorithm identifier
LZ4_COMPRESSION = 256


@dataclass
class ProcessInfoSubsystem:
    """Part of ProcessInfoEntry - subsystem metadata."""
    identifier: int = 0
    subsystem_offset: int = 0  # Offset to subsystem from start of subsystem entries
    category_offset: int = 0  # Offset to category from start of subsystem entries


@dataclass
class ProcessUUIDEntry:
    """Part of ProcessInfoEntry - UUID metadata."""
    size: int = 0
    unknown: int = 0
    catalog_uuid_index: int = 0
    load_address: int = 0
    uuid: str = ""


@dataclass
class ProcessInfoEntry:
    """Catalog process information entry."""
    index: int = 0
    unknown: int = 0  # flags?
    catalog_main_uuid_index: int = 0
    catalog_dsc_uuid_index: int = 0
    first_number_proc_id: int = 0
    second_number_proc_id: int = 0
    pid: int = 0
    effective_user_id: int = 0  # euid
    unknown2: int = 0
    number_uuids_entries: int = 0
    unknown3: int = 0
    uuid_info_entries: List[ProcessUUIDEntry] = field(default_factory=list)
    number_subsystems: int = 0
    unknown4: int = 0
    subsystem_entries: List[ProcessInfoSubsystem] = field(default_factory=list)
    main_uuid: str = ""  # From catalog_uuids, points to UUIDinfo file
    dsc_uuid: str = ""  # From catalog_uuids, points to dsc shared string file


@dataclass
class CatalogSubchunk:
    """Part of CatalogChunk - metadata related to compressed Chunkset data."""
    start: int = 0
    end: int = 0
    uncompressed_size: int = 0
    compression_algorithm: int = 0  # Should always be LZ4 (value 0x100)
    number_index: int = 0
    indexes: List[int] = field(default_factory=list)  # size = number_index * u16
    number_string_offsets: int = 0
    string_offsets: List[int] = field(default_factory=list)  # size = number_string_offsets * u16


@dataclass
class SubsystemInfo:
    """Subsystem and category information."""
    subsystem: str = ""
    category: str = ""


@dataclass
class CatalogChunk:
    """Catalog chunk structure containing metadata for log entries."""
    chunk_tag: int = 0
    chunk_sub_tag: int = 0
    chunk_data_size: int = 0
    catalog_subsystem_strings_offset: int = 0  # offset relative to start of catalog UUIDs
    catalog_process_info_entries_offset: int = 0  # offset relative to start of catalog UUIDs
    number_process_information_entries: int = 0
    catalog_offset_sub_chunks: int = 0  # offset relative to start of catalog UUIDs
    number_sub_chunks: int = 0
    unknown: bytes = b''  # unknown 6 bytes, padding? alignment?
    earliest_firehose_timestamp: int = 0
    catalog_uuids: List[str] = field(default_factory=list)  # array of UUIDs in big endian
    catalog_subsystem_strings: bytes = b''  # array of strings with end-of-string character
    catalog_process_info_entries: Dict[str, ProcessInfoEntry] = field(default_factory=dict)
    catalog_subchunks: List[CatalogSubchunk] = field(default_factory=list)

    @staticmethod
    def parse_catalog(data: bytes) -> Tuple[bytes, 'CatalogChunk']:
        """Parse log Catalog data.

        The log Catalog contains metadata related to log entries such as Process info,
        Subsystem info, and the compressed log entries.

        Args:
            data: Raw bytes starting at catalog chunk

        Returns:
            Tuple of (remaining data, CatalogChunk)
        """
        remaining, preamble = LogPreamble.parse(data)

        offset = 16  # After preamble

        # Parse catalog header
        catalog_subsystem_strings_offset = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        catalog_process_info_entries_offset = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        number_process_information_entries = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        catalog_offset_sub_chunks = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        number_sub_chunks = struct.unpack_from('<H', data, offset)[0]
        offset += 2

        # Unknown 6 bytes
        unknown = data[offset:offset + 6]
        offset += 6

        earliest_firehose_timestamp = struct.unpack_from('<Q', data, offset)[0]
        offset += 8

        # Parse UUIDs (each is 16 bytes, big endian)
        uuid_length = 16
        number_catalog_uuids = catalog_subsystem_strings_offset // uuid_length
        catalog_uuids = []
        for _ in range(number_catalog_uuids):
            uuid_high = struct.unpack_from('>Q', data, offset)[0]
            uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
            catalog_uuids.append(f"{(uuid_high << 64) | uuid_low:032X}")
            offset += 16

        # Parse subsystem strings
        subsystems_strings_length = catalog_process_info_entries_offset - catalog_subsystem_strings_offset
        catalog_subsystem_strings = data[offset:offset + subsystems_strings_length]
        offset += subsystems_strings_length

        # Parse process info entries
        catalog_process_info_entries = {}
        for _ in range(number_process_information_entries):
            remaining_data, entry = CatalogChunk._parse_catalog_process_entry(
                data[offset:], catalog_uuids
            )
            key = f"{entry.first_number_proc_id}_{entry.second_number_proc_id}"
            catalog_process_info_entries[key] = entry
            offset = len(data) - len(remaining_data)

        # Parse subchunks
        catalog_subchunks = []
        for _ in range(number_sub_chunks):
            remaining_data, subchunk = CatalogChunk._parse_catalog_subchunk(data[offset:])
            catalog_subchunks.append(subchunk)
            offset = len(data) - len(remaining_data)

        catalog = CatalogChunk(
            chunk_tag=preamble.chunk_tag,
            chunk_sub_tag=preamble.chunk_sub_tag,
            chunk_data_size=preamble.chunk_data_size,
            catalog_subsystem_strings_offset=catalog_subsystem_strings_offset,
            catalog_process_info_entries_offset=catalog_process_info_entries_offset,
            number_process_information_entries=number_process_information_entries,
            catalog_offset_sub_chunks=catalog_offset_sub_chunks,
            number_sub_chunks=number_sub_chunks,
            unknown=unknown,
            earliest_firehose_timestamp=earliest_firehose_timestamp,
            catalog_uuids=catalog_uuids,
            catalog_subsystem_strings=catalog_subsystem_strings,
            catalog_process_info_entries=catalog_process_info_entries,
            catalog_subchunks=catalog_subchunks,
        )

        return (data[offset:], catalog)

    @staticmethod
    def _parse_catalog_process_entry(
        data: bytes, uuids: List[str]
    ) -> Tuple[bytes, ProcessInfoEntry]:
        """Parse the Catalog Process Information entry.

        Args:
            data: Raw bytes starting at process entry
            uuids: List of UUIDs from catalog

        Returns:
            Tuple of (remaining data, ProcessInfoEntry)
        """
        offset = 0

        index = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        unknown = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        catalog_main_uuid_index = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        catalog_dsc_uuid_index = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        first_number_proc_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        second_number_proc_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        pid = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        effective_user_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        unknown2 = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        number_uuids_entries = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        unknown3 = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Parse UUID info entries
        uuid_info_entries = []
        for _ in range(number_uuids_entries):
            remaining, uuid_entry = CatalogChunk._parse_process_info_uuid_entry(
                data[offset:], uuids
            )
            uuid_info_entries.append(uuid_entry)
            offset = len(data) - len(remaining)

        number_subsystems = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        unknown4 = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Parse subsystem entries
        subsystem_entries = []
        for _ in range(number_subsystems):
            remaining, subsystem_entry = CatalogChunk._parse_process_info_subsystem(data[offset:])
            subsystem_entries.append(subsystem_entry)
            offset = len(data) - len(remaining)

        # Get UUIDs from catalog array
        main_uuid = ""
        if catalog_main_uuid_index < len(uuids):
            main_uuid = uuids[catalog_main_uuid_index]
        else:
            logger.warning("[macos-unifiedlogs] Could not find main UUID in catalog")

        dsc_uuid = ""
        if catalog_dsc_uuid_index < len(uuids):
            dsc_uuid = uuids[catalog_dsc_uuid_index]

        # Calculate and skip padding
        subsystem_size = 6
        padding = anticipated_padding_size_8(number_subsystems, subsystem_size)
        offset += padding

        entry = ProcessInfoEntry(
            index=index,
            unknown=unknown,
            catalog_main_uuid_index=catalog_main_uuid_index,
            catalog_dsc_uuid_index=catalog_dsc_uuid_index,
            first_number_proc_id=first_number_proc_id,
            second_number_proc_id=second_number_proc_id,
            pid=pid,
            effective_user_id=effective_user_id,
            unknown2=unknown2,
            number_uuids_entries=number_uuids_entries,
            unknown3=unknown3,
            uuid_info_entries=uuid_info_entries,
            number_subsystems=number_subsystems,
            unknown4=unknown4,
            subsystem_entries=subsystem_entries,
            main_uuid=main_uuid,
            dsc_uuid=dsc_uuid,
        )

        return (data[offset:], entry)

    @staticmethod
    def _parse_process_info_uuid_entry(
        data: bytes, uuids: List[str]
    ) -> Tuple[bytes, ProcessUUIDEntry]:
        """Parse the UUID metadata in the Catalog Process Entry.

        Args:
            data: Raw bytes starting at UUID entry
            uuids: List of UUIDs from catalog

        Returns:
            Tuple of (remaining data, ProcessUUIDEntry)
        """
        offset = 0

        size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        unknown = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        catalog_uuid_index = struct.unpack_from('<H', data, offset)[0]
        offset += 2

        # Load address is 6 bytes (48 bits)
        load_address_bytes = data[offset:offset + 6] + b'\x00\x00'
        load_address = struct.unpack('<Q', load_address_bytes)[0]
        offset += 6

        uuid = ""
        if catalog_uuid_index < len(uuids):
            uuid = uuids[catalog_uuid_index]

        entry = ProcessUUIDEntry(
            size=size,
            unknown=unknown,
            catalog_uuid_index=catalog_uuid_index,
            load_address=load_address,
            uuid=uuid,
        )

        return (data[offset:], entry)

    @staticmethod
    def _parse_process_info_subsystem(data: bytes) -> Tuple[bytes, ProcessInfoSubsystem]:
        """Parse the Catalog Subsystem metadata.

        Args:
            data: Raw bytes starting at subsystem entry

        Returns:
            Tuple of (remaining data, ProcessInfoSubsystem)
        """
        offset = 0

        identifier = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        subsystem_offset = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        category_offset = struct.unpack_from('<H', data, offset)[0]
        offset += 2

        entry = ProcessInfoSubsystem(
            identifier=identifier,
            subsystem_offset=subsystem_offset,
            category_offset=category_offset,
        )

        return (data[offset:], entry)

    @staticmethod
    def _parse_catalog_subchunk(data: bytes) -> Tuple[bytes, CatalogSubchunk]:
        """Parse the Catalog Subchunk metadata.

        Args:
            data: Raw bytes starting at subchunk

        Returns:
            Tuple of (remaining data, CatalogSubchunk)
        """
        offset = 0

        start = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        end = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        uncompressed_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        compression_algorithm = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        if compression_algorithm != LZ4_COMPRESSION:
            raise ValueError(f"Unsupported compression algorithm: {compression_algorithm}")

        number_index = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Parse indexes
        indexes = []
        for _ in range(number_index):
            indexes.append(struct.unpack_from('<H', data, offset)[0])
            offset += 2

        number_string_offsets = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Parse string offsets
        string_offsets = []
        for _ in range(number_string_offsets):
            string_offsets.append(struct.unpack_from('<H', data, offset)[0])
            offset += 2

        # Calculate and skip padding
        offset_size = 2
        padding = anticipated_padding_size_8(number_index + number_string_offsets, offset_size)
        offset += padding

        subchunk = CatalogSubchunk(
            start=start,
            end=end,
            uncompressed_size=uncompressed_size,
            compression_algorithm=compression_algorithm,
            number_index=number_index,
            indexes=indexes,
            number_string_offsets=number_string_offsets,
            string_offsets=string_offsets,
        )

        return (data[offset:], subchunk)

    def get_subsystem(
        self, subsystem_value: int, first_proc_id: int, second_proc_id: int
    ) -> Optional[SubsystemInfo]:
        """Get subsystem and category based on the log entry.

        Args:
            subsystem_value: Subsystem ID from log entry
            first_proc_id: First process ID from log entry
            second_proc_id: Second process ID from log entry

        Returns:
            SubsystemInfo with subsystem and category, or None if not found
        """
        key = f"{first_proc_id}_{second_proc_id}"
        entry = self.catalog_process_info_entries.get(key)

        if entry is not None:
            for subsystem in entry.subsystem_entries:
                if subsystem_value == subsystem.identifier:
                    subsystem_data = self.catalog_subsystem_strings

                    # Get subsystem string
                    _, subsystem_string = extract_string(
                        subsystem_data[subsystem.subsystem_offset:]
                    )

                    # Get category string
                    _, category_string = extract_string(
                        subsystem_data[subsystem.category_offset:]
                    )

                    return SubsystemInfo(
                        subsystem=subsystem_string,
                        category=category_string,
                    )

        return SubsystemInfo(subsystem="Unknown subsystem", category="")

    def get_pid(self, first_proc_id: int, second_proc_id: int) -> int:
        """Get the actual Process ID associated with log entry.

        Args:
            first_proc_id: First process ID from log entry
            second_proc_id: Second process ID from log entry

        Returns:
            Process ID or 0 if not found
        """
        key = f"{first_proc_id}_{second_proc_id}"
        entry = self.catalog_process_info_entries.get(key)

        if entry is not None:
            return entry.pid

        logger.warning("[macos-unifiedlogs] Did not find PID in log Catalog")
        return 0

    def get_euid(self, first_proc_id: int, second_proc_id: int) -> int:
        """Get the effective user id associated with log entry.

        Can be mapped to an account name.

        Args:
            first_proc_id: First process ID from log entry
            second_proc_id: Second process ID from log entry

        Returns:
            Effective user ID or 0 if not found
        """
        key = f"{first_proc_id}_{second_proc_id}"
        entry = self.catalog_process_info_entries.get(key)

        if entry is not None:
            return entry.effective_user_id

        logger.warning("[macos-unifiedlogs] Did not find EUID in log Catalog")
        return 0
