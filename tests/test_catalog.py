# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for catalog parsing."""

import pytest

from macos_unifiedlogs.catalog import (
    CatalogChunk,
    CatalogSubchunk,
    ProcessInfoEntry,
    ProcessInfoSubsystem,
    ProcessUUIDEntry,
)


class TestCatalogChunk:
    """Test CatalogChunk data structure."""

    def test_catalog_chunk_creation(self):
        """Test creating CatalogChunk with default values."""
        catalog = CatalogChunk()
        assert catalog.chunk_tag == 0
        assert catalog.chunk_sub_tag == 0
        assert catalog.chunk_data_size == 0
        assert catalog.earliest_firehose_timestamp == 0
        assert catalog.catalog_process_info_entries == {}
        assert catalog.catalog_subchunks == []
        assert catalog.number_process_information_entries == 0

    def test_catalog_chunk_with_entries(self):
        """Test CatalogChunk with process info entries."""
        process_entry = ProcessInfoEntry(
            index=0,
            unknown=0,
            pid=42,
            effective_user_id=0,
            first_number_proc_id=1,
            second_number_proc_id=0,
            main_uuid="ABCD1234EF567890ABCD1234EF567890",
        )

        catalog = CatalogChunk(
            chunk_tag=0x600b,
            number_process_information_entries=1,
            catalog_process_info_entries={"1_0": process_entry},
        )

        assert len(catalog.catalog_process_info_entries) == 1
        assert catalog.catalog_process_info_entries["1_0"].pid == 42


class TestProcessInfoEntry:
    """Test ProcessInfoEntry data structure."""

    def test_process_info_entry_creation(self):
        """Test creating ProcessInfoEntry."""
        entry = ProcessInfoEntry(
            index=0,
            unknown=0,
            pid=1234,
            effective_user_id=501,
            first_number_proc_id=5,
            second_number_proc_id=0,
            catalog_main_uuid_index=0,
            catalog_dsc_uuid_index=1,
            main_uuid="12345678ABCDEF0012345678ABCDEF00",
            dsc_uuid="DSCUUID12345678901234567890ABCD",
        )

        assert entry.pid == 1234
        assert entry.effective_user_id == 501
        assert entry.main_uuid == "12345678ABCDEF0012345678ABCDEF00"


class TestProcessUUIDEntry:
    """Test ProcessUUIDEntry data structure."""

    def test_process_uuid_entry_creation(self):
        """Test creating ProcessUUIDEntry."""
        entry = ProcessUUIDEntry(
            size=48,
            unknown=0,
            catalog_uuid_index=5,
            load_address=0x7fff00000000,
            uuid="FEDCBA9876543210FEDCBA9876543210",
        )

        assert entry.load_address == 0x7fff00000000
        assert entry.uuid == "FEDCBA9876543210FEDCBA9876543210"
        assert entry.catalog_uuid_index == 5


class TestProcessInfoSubsystem:
    """Test ProcessInfoSubsystem data structure."""

    def test_process_info_subsystem_creation(self):
        """Test creating ProcessInfoSubsystem."""
        subsystem = ProcessInfoSubsystem(
            identifier=1,
            subsystem_offset=100,
            category_offset=150,
        )

        assert subsystem.identifier == 1
        assert subsystem.subsystem_offset == 100
        assert subsystem.category_offset == 150


class TestCatalogSubchunk:
    """Test CatalogSubchunk data structure."""

    def test_catalog_subchunk_creation(self):
        """Test creating CatalogSubchunk."""
        subchunk = CatalogSubchunk(
            start=0,
            end=100,
            uncompressed_size=1000,
            compression_algorithm=0x100,
            number_index=5,
            indexes=[0, 1, 2, 3, 4],
            number_string_offsets=3,
            string_offsets=[10, 20, 30],
        )

        assert subchunk.start == 0
        assert subchunk.end == 100
        assert subchunk.uncompressed_size == 1000
        assert subchunk.number_index == 5
        assert subchunk.number_string_offsets == 3

    def test_catalog_subchunk_with_data(self):
        """Test CatalogSubchunk with indexes and offsets."""
        subchunk = CatalogSubchunk(
            start=0,
            end=50,
            uncompressed_size=500,
            compression_algorithm=0x100,
            number_index=2,
            indexes=[0, 1],
            number_string_offsets=2,
            string_offsets=[0, 50],
        )

        assert len(subchunk.indexes) == 2
        assert len(subchunk.string_offsets) == 2
        assert subchunk.indexes == [0, 1]
        assert subchunk.string_offsets == [0, 50]
