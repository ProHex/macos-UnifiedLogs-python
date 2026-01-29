# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for filesystem providers."""

import tempfile
from pathlib import Path

import pytest

from macos_unifiedlogs.filesystem import (
    FileSourceFile,
    LiveSystemProvider,
    LogarchiveProvider,
)
from macos_unifiedlogs.traits import FileProvider, SourceFile


class TestFileSourceFile:
    """Test FileSourceFile class."""

    def test_file_source_file_creation(self):
        """Test creating FileSourceFile."""
        source = FileSourceFile("/path/to/file.tracev3")
        assert source.source_path() == "/path/to/file.tracev3"

    def test_file_source_file_reader(self):
        """Test FileSourceFile reader with actual file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            source = FileSourceFile(temp_path)
            with source.reader() as reader:
                content = reader.read()
                assert content == b"test content"
        finally:
            Path(temp_path).unlink()


class TestLogarchiveProvider:
    """Test LogarchiveProvider class."""

    def test_logarchive_provider_creation(self):
        """Test creating LogarchiveProvider."""
        provider = LogarchiveProvider("/path/to/test.logarchive")
        assert isinstance(provider, FileProvider)

    def test_logarchive_provider_with_temp_dir(self):
        """Test LogarchiveProvider with temporary directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create logarchive structure
            archive_path = Path(tmpdir) / "test.logarchive"
            archive_path.mkdir()

            persist_dir = archive_path / "Persist"
            persist_dir.mkdir()

            highvolume_dir = archive_path / "HighVolume"
            highvolume_dir.mkdir()

            uuidtext_dir = archive_path / "uuidtext"
            uuidtext_dir.mkdir()

            dsc_dir = archive_path / "dsc"
            dsc_dir.mkdir()

            timesync_dir = archive_path / "timesync"
            timesync_dir.mkdir()

            # Create some test files
            (persist_dir / "0000000000000001.tracev3").touch()
            (persist_dir / "0000000000000002.tracev3").touch()

            uuid_subdir = uuidtext_dir / "AB"
            uuid_subdir.mkdir()
            (uuid_subdir / "CD1234567890").touch()

            (dsc_dir / "test.dsc").touch()
            (timesync_dir / "test.timesync").touch()

            provider = LogarchiveProvider(str(archive_path))

            # Test tracev3_files
            tracev3_files = list(provider.tracev3_files())
            assert len(tracev3_files) == 2

            # Test uuidtext_files
            uuidtext_files = list(provider.uuidtext_files())
            assert len(uuidtext_files) == 1

            # Test dsc_files
            dsc_files = list(provider.dsc_files())
            assert len(dsc_files) == 1

            # Test timesync_files
            timesync_files = list(provider.timesync_files())
            assert len(timesync_files) == 1

    def test_logarchive_provider_uuidtext_cache(self):
        """Test LogarchiveProvider UUIDText caching."""
        provider = LogarchiveProvider("/path/to/test.logarchive")

        # Initially no cache
        assert provider.get_uuidtext("TEST_UUID") is None

        # Set cache
        from macos_unifiedlogs.uuidtext import UUIDText

        test_uuidtext = UUIDText(
            uuid="TEST",
            signature=0x66778899,
            number_entries=0,
            entry_descriptors=[],
            footer_data=b'/test\x00',
        )
        provider.set_uuidtext("TEST_UUID", test_uuidtext)

        # Retrieve from cache
        cached = provider.get_uuidtext("TEST_UUID")
        assert cached is not None
        assert cached.uuid == "TEST"

    def test_logarchive_provider_dsc_cache(self):
        """Test LogarchiveProvider DSC caching."""
        provider = LogarchiveProvider("/path/to/test.logarchive")

        # Initially no cache
        assert provider.get_dsc("TEST_UUID") is None

        # Set cache
        from macos_unifiedlogs.dsc import SharedCacheStrings

        test_dsc = SharedCacheStrings(
            signature=0x64736368,
            major_version=2,
            minor_version=0,
            number_ranges=0,
            number_uuids=0,
            ranges=[],
            uuids=[],
            dsc_uuid="TEST_DSC",
        )
        provider.set_dsc("TEST_UUID", test_dsc)

        # Retrieve from cache
        cached = provider.get_dsc("TEST_UUID")
        assert cached is not None
        assert cached.dsc_uuid == "TEST_DSC"


class TestLiveSystemProvider:
    """Test LiveSystemProvider class."""

    def test_live_system_provider_creation(self):
        """Test creating LiveSystemProvider."""
        provider = LiveSystemProvider()
        assert isinstance(provider, FileProvider)

    def test_live_system_provider_uuidtext_cache(self):
        """Test LiveSystemProvider UUIDText caching."""
        provider = LiveSystemProvider()

        # Initially no cache
        assert provider.get_uuidtext("TEST_UUID") is None

        # Set cache
        from macos_unifiedlogs.uuidtext import UUIDText

        test_uuidtext = UUIDText(
            uuid="TEST",
            signature=0x66778899,
            number_entries=0,
            entry_descriptors=[],
            footer_data=b'/test\x00',
        )
        provider.set_uuidtext("TEST_UUID", test_uuidtext)

        # Retrieve from cache
        cached = provider.get_uuidtext("TEST_UUID")
        assert cached is not None
        assert cached.uuid == "TEST"

    def test_live_system_provider_dsc_cache(self):
        """Test LiveSystemProvider DSC caching."""
        provider = LiveSystemProvider()

        # Initially no cache
        assert provider.get_dsc("TEST_UUID") is None

        # Set cache
        from macos_unifiedlogs.dsc import SharedCacheStrings

        test_dsc = SharedCacheStrings(
            signature=0x64736368,
            major_version=2,
            minor_version=0,
            number_ranges=0,
            number_uuids=0,
            ranges=[],
            uuids=[],
            dsc_uuid="TEST_DSC",
        )
        provider.set_dsc("TEST_UUID", test_dsc)

        # Retrieve from cache
        cached = provider.get_dsc("TEST_UUID")
        assert cached is not None
        assert cached.dsc_uuid == "TEST_DSC"


class TestSourceFileAbstraction:
    """Test SourceFile abstraction."""

    def test_source_file_is_abstract(self):
        """Test that SourceFile is an abstract base class."""
        from abc import ABC

        assert issubclass(SourceFile, ABC)

    def test_file_provider_is_abstract(self):
        """Test that FileProvider is an abstract base class."""
        from abc import ABC

        assert issubclass(FileProvider, ABC)
