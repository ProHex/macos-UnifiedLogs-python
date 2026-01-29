# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for message formatting functions."""

import pytest

from macos_unifiedlogs.chunks.firehose.firehose_log import FirehoseItemInfo
from macos_unifiedlogs.message import (
    format_alignment_left,
    format_alignment_left_space,
    format_alignment_right,
    format_alignment_right_space,
    format_firehose_log_message,
    format_left,
    format_right,
    parse_float,
    parse_formatter,
    parse_int,
    parse_type_formatter,
)


class TestParseFormatter:
    """Test parse_formatter function."""

    def test_parse_formatter_integer(self):
        """Test parsing integer formatter."""
        test_message = [
            FirehoseItemInfo(
                message_strings="42",
                item_type=0,
                item_size=4,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%d",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "42"

    def test_parse_formatter_unsigned_integer(self):
        """Test parsing unsigned integer formatter."""
        test_message = [
            FirehoseItemInfo(
                message_strings="100",
                item_type=0,
                item_size=4,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%u",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "100"

    def test_parse_formatter_hex_lowercase(self):
        """Test parsing lowercase hex formatter.

        Note: Current implementation uses uppercase for all hex output.
        """
        test_message = [
            FirehoseItemInfo(
                message_strings="255",
                item_type=0,
                item_size=4,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%x",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        # Implementation uses uppercase for both %x and %X
        assert result == "FF"

    def test_parse_formatter_hex_uppercase(self):
        """Test parsing uppercase hex formatter."""
        test_message = [
            FirehoseItemInfo(
                message_strings="255",
                item_type=0,
                item_size=4,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%X",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "FF"

    def test_parse_formatter_float(self):
        """Test parsing float formatter with encoded value."""
        test_message = [
            FirehoseItemInfo(
                message_strings="4611911198408756429",
                item_type=0,
                item_size=8,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%f",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "2.1"

    def test_parse_formatter_float_negative(self):
        """Test parsing negative float formatter.

        Note: Implementation includes decimal point for float formatting.
        """
        test_message = [
            FirehoseItemInfo(
                message_strings="-4611686018427387904",
                item_type=0,
                item_size=8,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%f",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        # Float formatting includes decimal point
        assert result == "-2.0"

    def test_parse_formatter_string(self):
        """Test parsing string formatter."""
        test_message = [
            FirehoseItemInfo(
                message_strings="The big red dog jumped over the crab",
                item_type=2,
                item_size=36,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%s",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "The big red dog jumped over the crab"

    def test_parse_formatter_precision(self):
        """Test parsing formatter with precision."""
        test_message = [
            FirehoseItemInfo(
                message_strings="aaabbbb",
                item_type=0,
                item_size=7,
            )
        ]
        item_index = 0
        result = parse_formatter(
            "%.2@",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "aa"


class TestParseTypeFormatter:
    """Test parse_type_formatter function."""

    def test_parse_type_formatter_public_string(self):
        """Test parsing public string formatter."""
        test_message = [
            FirehoseItemInfo(
                message_strings="test",
                item_type=2,
                item_size=4,
            )
        ]
        item_index = 0
        result = parse_type_formatter(
            "%{public}s",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "test"

    def test_parse_type_formatter_signpost(self):
        """Test parsing signpost formatter."""
        test_message = [
            FirehoseItemInfo(
                message_strings="1",
                item_type=2,
                item_size=4,
            )
        ]
        item_index = 0
        result = parse_type_formatter(
            "%{public, signpost.description:begin_time}llu",
            test_message,
            test_message[0].item_type,
            item_index,
        )
        assert result == "1 (signpost.description:begin_time)"


class TestFormatAlignment:
    """Test format alignment functions."""

    def test_format_alignment_left(self):
        """Test left alignment with zero padding."""
        result = format_alignment_left("2", 4, 0, "d", False, False)
        assert result == "2000"

    def test_format_alignment_right(self):
        """Test right alignment with zero padding."""
        result = format_alignment_right("2", 4, 0, "d", False, False)
        assert result == "0002"

    def test_format_alignment_left_space(self):
        """Test left alignment with space padding."""
        result = format_alignment_left_space("2", 4, 0, "d", False, False)
        assert result == "2   "

    def test_format_alignment_right_space(self):
        """Test right alignment with space padding."""
        result = format_alignment_right_space("2", 4, 0, "d", False, False)
        assert result == "   2"


class TestFormatFunctions:
    """Test basic format functions."""

    def test_format_left(self):
        """Test left format."""
        result = format_left("2", 0, "d", False, False)
        assert result == "2"

    def test_format_right(self):
        """Test right format."""
        result = format_right("2", 0, "d", False, False)
        assert result == "2"


class TestParseFunctions:
    """Test parse functions."""

    def test_parse_float(self):
        """Test parsing float from IEEE 754 representation."""
        value = "4611911198408756429"
        result = parse_float(value)
        assert result == 2.1

    def test_parse_int(self):
        """Test parsing integer."""
        value = "2"
        result = parse_int(value)
        assert result == 2

    def test_parse_int_negative(self):
        """Test parsing negative integer."""
        value = "-42"
        result = parse_int(value)
        assert result == -42


class TestFormatFirehoseLogMessage:
    """Test the main format_firehose_log_message function."""

    def test_simple_string(self):
        """Test formatting a simple string message."""
        format_string = "Hello %s"
        item_message = [
            FirehoseItemInfo(
                message_strings="World",
                item_type=2,
                item_size=5,
            )
        ]
        result = format_firehose_log_message(format_string, item_message)
        assert result == "Hello World"

    def test_multiple_formatters(self):
        """Test formatting with multiple format specifiers."""
        format_string = "Count: %d, Name: %s"
        item_message = [
            FirehoseItemInfo(
                message_strings="42",
                item_type=0,
                item_size=4,
            ),
            FirehoseItemInfo(
                message_strings="test",
                item_type=2,
                item_size=4,
            ),
        ]
        result = format_firehose_log_message(format_string, item_message)
        assert result == "Count: 42, Name: test"

    def test_no_formatters(self):
        """Test formatting with no format specifiers."""
        format_string = "No placeholders here"
        item_message = []
        result = format_firehose_log_message(format_string, item_message)
        assert result == "No placeholders here"

    def test_escaped_percent(self):
        """Test escaped percent sign."""
        format_string = "100%% complete"
        item_message = []
        result = format_firehose_log_message(format_string, item_message)
        assert result == "100% complete"

    def test_public_private_annotations(self):
        """Test public/private annotations are handled."""
        format_string = "Value: %{public}s"
        item_message = [
            FirehoseItemInfo(
                message_strings="public_data",
                item_type=2,
                item_size=11,
            )
        ]
        result = format_firehose_log_message(format_string, item_message)
        assert result == "Value: public_data"
