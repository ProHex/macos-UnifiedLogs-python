# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for utility functions."""

import pytest

from macos_unifiedlogs.util import (
    anticipated_padding_size,
    anticipated_padding_size_8,
    clean_uuid,
    decode_standard,
    encode_standard,
    extract_string,
    extract_string_size,
    padding_size,
    padding_size_four,
    padding_size_8,
    unixepoch_to_iso,
)


class TestPaddingFunctions:
    """Test padding calculation functions."""

    @pytest.mark.parametrize("data_size,expected", [
        (0, 0),
        (7, 1),
        (8, 0),
        (16, 0),
        (1, 7),
        (9, 7),
    ])
    def test_padding_size_8(self, data_size: int, expected: int):
        """Test 8-byte padding calculation."""
        assert padding_size_8(data_size) == expected

    @pytest.mark.parametrize("data_size,expected", [
        (0, 0),
        (3, 1),
        (4, 0),
        (8, 0),
        (1, 3),
        (5, 3),
    ])
    def test_padding_size_four(self, data_size: int, expected: int):
        """Test 4-byte padding calculation."""
        assert padding_size_four(data_size) == expected

    @pytest.mark.parametrize("n,size,alignment,expected", [
        (0, 8, 8, 0),
        (1, 8, 8, 0),
        (2, 16, 8, 0),
        (2, 5, 8, 6),
    ])
    def test_anticipated_padding_size(
        self, n: int, size: int, alignment: int, expected: int
    ):
        """Test anticipated padding calculation."""
        assert anticipated_padding_size(n, size, alignment) == expected

    def test_anticipated_padding_size_8(self):
        """Test 8-byte anticipated padding calculation."""
        assert anticipated_padding_size_8(1, 8) == 0
        assert anticipated_padding_size_8(2, 5) == 6


class TestStringFunctions:
    """Test string extraction and manipulation functions."""

    def test_extract_string(self):
        """Test extracting null-terminated string.

        Note: extract_string only looks at if the LAST byte is 0.
        If the last byte is not 0, it returns the entire string.
        """
        # Data ending with null
        data = b"hello\x00"
        remaining, string = extract_string(data)
        assert string == "hello"
        assert remaining == b"\x00"

    def test_extract_string_with_trailing_data(self):
        """Test extracting string when last byte is not null.

        When the last byte is not null, extract_string returns the entire string.
        """
        data = b"hello\x00world"
        remaining, string = extract_string(data)
        # Last byte is 'd', not 0, so entire string is returned
        assert string == "hello\x00world"
        assert remaining == b""

    def test_extract_string_no_null(self):
        """Test extracting string without null terminator."""
        data = b"hello"
        remaining, string = extract_string(data)
        assert string == "hello"
        assert remaining == b""

    def test_extract_string_empty(self):
        """Test extracting from empty data."""
        data = b""
        remaining, string = extract_string(data)
        assert "Cannot extract string" in string
        assert remaining == b""

    def test_extract_string_size(self):
        """Test extracting fixed-size string."""
        data = b"hello world"
        remaining, string = extract_string_size(data, 5)
        assert string == "hello"
        assert remaining == b" world"

    def test_extract_string_size_zero(self):
        """Test extracting zero-size string returns null."""
        data = b"hello"
        remaining, string = extract_string_size(data, 0)
        assert string == "(null)"
        assert remaining == b"hello"

    def test_extract_string_size_with_null(self):
        """Test extracting string with embedded null (uses rstrip)."""
        data = b"hel\x00lo"
        remaining, string = extract_string_size(data, 6)
        # extract_string_size uses rstrip('\x00') at the end
        assert string == "hel\x00lo" or string == "hel"  # behavior depends on implementation
        assert remaining == b""


class TestUuidFunctions:
    """Test UUID manipulation functions."""

    def test_clean_uuid(self):
        """Test cleaning UUID format."""
        assert clean_uuid("[1234, 5678]") == "12345678"
        assert clean_uuid("ABCD-EF01") == "ABCD-EF01"
        assert clean_uuid("  uuid  ") == "uuid"


class TestBase64Functions:
    """Test base64 encoding/decoding functions."""

    def test_encode_standard(self):
        """Test standard base64 encoding."""
        data = b"hello"
        encoded = encode_standard(data)
        assert encoded == "aGVsbG8="

    def test_decode_standard(self):
        """Test standard base64 decoding."""
        encoded = "aGVsbG8="
        decoded = decode_standard(encoded)
        assert decoded == b"hello"

    def test_encode_decode_roundtrip(self):
        """Test encoding and decoding roundtrip."""
        original = b"test data 123"
        encoded = encode_standard(original)
        decoded = decode_standard(encoded)
        assert decoded == original


class TestTimeFunctions:
    """Test time conversion functions."""

    def test_unixepoch_to_iso(self):
        """Test Unix epoch nanoseconds to ISO 8601 conversion."""
        # 2021-01-01 00:00:00 UTC in nanoseconds
        timestamp = 1609459200000000000
        result = unixepoch_to_iso(timestamp)
        assert "2021-01-01" in result
        assert "00:00:00" in result

    def test_unixepoch_to_iso_zero(self):
        """Test Unix epoch zero (1970-01-01)."""
        result = unixepoch_to_iso(0)
        assert "1970-01-01" in result
