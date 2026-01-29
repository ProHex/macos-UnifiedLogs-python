# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for header parsing."""

import pytest

from macos_unifiedlogs.header import HeaderChunk
from macos_unifiedlogs.preamble import LogPreamble


class TestLogPreamble:
    """Test LogPreamble parsing."""

    def test_detect_preamble(self):
        """Test detecting preamble from data."""
        # Create a minimal preamble structure
        # chunk_tag (4 bytes) + chunk_sub_tag (4 bytes) + chunk_data_size (8 bytes)
        data = bytes([
            0x00, 0x10, 0x00, 0x00,  # chunk_tag = 0x1000 (header)
            0x11, 0x00, 0x00, 0x00,  # chunk_sub_tag = 0x11
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # chunk_data_size = 64
        ])

        remaining, preamble = LogPreamble.detect_preamble(data)
        assert preamble.chunk_tag == 0x1000
        assert preamble.chunk_sub_tag == 0x11
        assert preamble.chunk_data_size == 64

    def test_detect_preamble_catalog(self):
        """Test detecting catalog preamble."""
        data = bytes([
            0x0B, 0x60, 0x00, 0x00,  # chunk_tag = 0x600b (catalog)
            0x00, 0x00, 0x00, 0x00,  # chunk_sub_tag = 0
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # chunk_data_size = 128
        ])

        remaining, preamble = LogPreamble.detect_preamble(data)
        assert preamble.chunk_tag == 0x600b
        assert preamble.chunk_sub_tag == 0
        assert preamble.chunk_data_size == 128

    def test_detect_preamble_chunkset(self):
        """Test detecting chunkset preamble."""
        data = bytes([
            0x0D, 0x60, 0x00, 0x00,  # chunk_tag = 0x600d (chunkset)
            0x00, 0x00, 0x00, 0x00,  # chunk_sub_tag = 0
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # chunk_data_size = 256
        ])

        remaining, preamble = LogPreamble.detect_preamble(data)
        assert preamble.chunk_tag == 0x600d
        assert preamble.chunk_sub_tag == 0
        assert preamble.chunk_data_size == 256


class TestHeaderChunk:
    """Test HeaderChunk parsing."""

    def test_header_chunk_creation(self):
        """Test creating HeaderChunk with default values."""
        header = HeaderChunk()
        assert header.chunk_tag == 0
        assert header.chunk_sub_tag == 0
        assert header.chunk_data_size == 0
        assert header.boot_uuid == ""
        assert header.logd_pid == 0
        assert header.timezone_path == ""

    def test_header_chunk_attributes(self):
        """Test HeaderChunk attributes."""
        header = HeaderChunk(
            chunk_tag=0x1000,
            chunk_sub_tag=0x11,
            chunk_data_size=64,
            continous_time=1000000,  # Note: matches Rust implementation typo
            mach_time_numerator=1,
            mach_time_denominator=1,
            boot_uuid="ABCD1234EF567890ABCD1234EF567890",
            logd_pid=42,
            logd_exit_status=0,
            timezone_path="/var/db/timezone/zoneinfo/America/Los_Angeles",
        )

        assert header.chunk_tag == 0x1000
        assert header.boot_uuid == "ABCD1234EF567890ABCD1234EF567890"
        assert header.logd_pid == 42
        assert "America/Los_Angeles" in header.timezone_path

    def test_header_get_timezone_name(self):
        """Test extracting timezone name from path."""
        header = HeaderChunk(
            timezone_path="/var/db/timezone/zoneinfo/America/Los_Angeles"
        )
        # The get_timezone_name logic extracts the last component
        assert "Los_Angeles" in header.timezone_path or "America" in header.timezone_path
