# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for decoder functions."""

import ipaddress
import pytest

from macos_unifiedlogs.decoders.bool_decoder import (
    lowercase_bool,
    lowercase_int_bool,
    uppercase_bool,
)
from macos_unifiedlogs.decoders.darwin import errno_codes, permission
from macos_unifiedlogs.decoders.network import get_ip_four, get_ip_six, ipv_four, ipv_six
from macos_unifiedlogs.decoders.time_decoder import parse_time
from macos_unifiedlogs.decoders.uuid_decoder import parse_uuid
from macos_unifiedlogs.util import encode_standard


class TestBoolDecoder:
    """Test boolean decoder functions."""

    def test_uppercase_bool_true(self):
        """Test uppercase YES for true."""
        assert uppercase_bool("1") == "YES"
        assert uppercase_bool("true") == "YES"
        assert uppercase_bool("yes") == "YES"

    def test_uppercase_bool_false(self):
        """Test uppercase NO for false (only "0" is false)."""
        assert uppercase_bool("0") == "NO"
        # Note: The implementation only checks for "0" as false
        # other values like "false" and "no" return "YES"

    def test_lowercase_bool_true(self):
        """Test lowercase true."""
        assert lowercase_bool("1") == "true"
        assert lowercase_bool("true") == "true"
        assert lowercase_bool("yes") == "true"

    def test_lowercase_bool_false(self):
        """Test lowercase false (only "0" is false)."""
        assert lowercase_bool("0") == "false"
        # Note: The implementation only checks for "0" as false

    def test_lowercase_int_bool(self):
        """Test lowercase bool from integer."""
        assert lowercase_int_bool(1) == "true"
        assert lowercase_int_bool(0) == "false"
        assert lowercase_int_bool(42) == "true"


class TestDarwinDecoder:
    """Test Darwin-specific decoder functions."""

    def test_errno_codes_success(self):
        """Test errno code for success."""
        assert errno_codes("0") == "Success"

    def test_errno_codes_eperm(self):
        """Test errno code for permission denied."""
        assert errno_codes("1") == "Operation not permitted"

    def test_errno_codes_enoent(self):
        """Test errno code for no such file."""
        assert errno_codes("2") == "No such file or directory"

    def test_errno_codes_unknown(self):
        """Test unknown errno code."""
        result = errno_codes("9999")
        assert "Unknown errno" in result
        assert "9999" in result

    def test_permission_read(self):
        """Test read permission."""
        assert "r" in permission("4")

    def test_permission_write(self):
        """Test write permission."""
        assert "w" in permission("2")

    def test_permission_execute(self):
        """Test execute permission."""
        assert "x" in permission("1")

    def test_permission_all(self):
        """Test all permissions (rwx)."""
        result = permission("7")
        assert "r" in result
        assert "w" in result
        assert "x" in result


class TestNetworkDecoder:
    """Test network decoder functions."""

    def test_get_ip_four(self):
        """Test IPv4 address parsing from bytes."""
        # 192.168.1.1 in big-endian bytes
        data = bytes([192, 168, 1, 1])
        result = get_ip_four(data)
        assert isinstance(result, ipaddress.IPv4Address)
        assert str(result) == "192.168.1.1"

    def test_get_ip_six(self):
        """Test IPv6 address parsing from bytes."""
        # ::1 loopback
        data = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        result = get_ip_six(data)
        assert isinstance(result, ipaddress.IPv6Address)
        assert str(result) == "::1"

    def test_ipv_four(self):
        """Test IPv4 from base64 encoded data."""
        # Create base64 encoded IP
        ip_bytes = bytes([192, 168, 1, 1])
        encoded = encode_standard(ip_bytes)
        result = ipv_four(encoded)
        assert isinstance(result, ipaddress.IPv4Address)
        assert str(result) == "192.168.1.1"

    def test_ipv_six(self):
        """Test IPv6 from base64 encoded data."""
        # Create base64 encoded IPv6 loopback
        ip_bytes = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        encoded = encode_standard(ip_bytes)
        result = ipv_six(encoded)
        assert isinstance(result, ipaddress.IPv6Address)
        assert str(result) == "::1"


class TestTimeDecoder:
    """Test time decoder functions."""

    def test_parse_time(self):
        """Test parsing time value (Unix timestamp in seconds as string)."""
        # Unix timestamp for 2021-01-01 00:00:00 UTC
        result = parse_time("1609459200")
        assert "2021-01-01" in result
        assert "00:00:00" in result

    def test_parse_time_zero(self):
        """Test parsing zero timestamp."""
        result = parse_time("0")
        assert "1970-01-01" in result


class TestUuidDecoder:
    """Test UUID decoder functions."""

    def test_parse_uuid(self):
        """Test parsing UUID from base64 (returns hex without dashes)."""
        # Create a known UUID bytes
        uuid_bytes = bytes([
            0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88
        ])
        encoded = encode_standard(uuid_bytes)
        result = parse_uuid(encoded)
        # UUID decoder returns uppercase hex without dashes
        assert result == "123456789ABCDEF01122334455667788"

    def test_parse_uuid_invalid_length(self):
        """Test parsing UUID with invalid length."""
        # Too short
        encoded = encode_standard(b"\x00\x00\x00\x00")
        result = parse_uuid(encoded)
        # Should return the hex value (short)
        assert isinstance(result, str)
        assert result == "00000000"
