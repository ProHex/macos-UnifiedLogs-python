# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for firehose log parsing."""

import pytest

from macos_unifiedlogs.chunks.firehose.activity import FirehoseActivity
from macos_unifiedlogs.chunks.firehose.firehose_log import (
    Firehose,
    FirehoseItemData,
    FirehoseItemInfo,
    FirehosePreamble,
)
from macos_unifiedlogs.chunks.firehose.flags import FirehoseFormatters
from macos_unifiedlogs.chunks.firehose.loss import FirehoseLoss
from macos_unifiedlogs.chunks.firehose.nonactivity import FirehoseNonActivity
from macos_unifiedlogs.chunks.firehose.signpost import FirehoseSignpost
from macos_unifiedlogs.chunks.firehose.trace import FirehoseTrace


class TestFirehosePreamble:
    """Test FirehosePreamble data structure."""

    def test_firehose_preamble_creation(self):
        """Test creating FirehosePreamble."""
        preamble = FirehosePreamble(
            chunk_tag=0x6001,
            chunk_sub_tag=0,
            chunk_data_size=1000,
            first_number_proc_id=1,
            second_number_proc_id=2,
            collapsed=0,
            ttl=15,
            unknown=b'\x00\x00',
            public_data_size=500,
            private_data_virtual_offset=0x1000,
            base_continous_time=1000000000,
        )

        assert preamble.chunk_tag == 0x6001
        assert preamble.chunk_data_size == 1000
        assert preamble.ttl == 15
        assert preamble.public_data_size == 500
        assert preamble.private_data_virtual_offset == 0x1000


class TestFirehose:
    """Test Firehose data structure."""

    def test_firehose_creation(self):
        """Test creating Firehose log entry."""
        firehose = Firehose(
            unknown_log_activity_type=0,
            unknown_log_type=0,
            flags=0x0002,
            format_string_location=0x1000,
            thread_id=12345,
            continous_time_delta=500000,
            continous_time_delta_upper=0,
            data_size=50,
        )

        assert firehose.flags == 0x0002
        assert firehose.format_string_location == 0x1000
        assert firehose.thread_id == 12345


class TestFirehoseItemInfo:
    """Test FirehoseItemInfo data structure."""

    def test_firehose_item_info_creation(self):
        """Test creating FirehoseItemInfo."""
        item = FirehoseItemInfo(
            message_strings="Test message",
            item_type=0x02,
            item_size=12,
        )

        assert item.message_strings == "Test message"
        assert item.item_type == 0x02
        assert item.item_size == 12


class TestFirehoseItemData:
    """Test FirehoseItemData data structure."""

    def test_firehose_item_data_creation(self):
        """Test creating FirehoseItemData."""
        item = FirehoseItemData(
            item_info=[
                FirehoseItemInfo(message_strings="value1", item_type=0x02, item_size=6),
                FirehoseItemInfo(message_strings="42", item_type=0x00, item_size=4),
            ],
            backtrace_strings=[],
        )

        assert len(item.item_info) == 2
        assert item.item_info[0].message_strings == "value1"


class TestFirehoseNonActivity:
    """Test FirehoseNonActivity data structure."""

    def test_firehose_nonactivity_creation(self):
        """Test creating FirehoseNonActivity."""
        nonactivity = FirehoseNonActivity(
            unknown_activity_id=0,
            unknown_sentinal=0,
            private_strings_offset=0,
            private_strings_size=0,
            unknown_message_string_ref=0,
            subsystem_value=1,
            ttl_value=15,
            data_ref_value=0,
            firehose_formatters=FirehoseFormatters(),
        )

        assert nonactivity.subsystem_value == 1
        assert nonactivity.ttl_value == 15


class TestFirehoseActivity:
    """Test FirehoseActivity data structure."""

    def test_firehose_activity_creation(self):
        """Test creating FirehoseActivity."""
        activity = FirehoseActivity(
            unknown_activity_id=0,
            unknown_sentinal=0,
            pid=1234,
            unknown_activity_id_2=0,
            unknown_sentinal_2=0,
            unknown_message_string_ref=0,
            firehose_formatters=FirehoseFormatters(),
        )

        assert activity.unknown_activity_id == 0
        assert activity.pid == 1234


class TestFirehoseSignpost:
    """Test FirehoseSignpost data structure."""

    def test_firehose_signpost_creation(self):
        """Test creating FirehoseSignpost."""
        signpost = FirehoseSignpost(
            unknown_activity_id=0,
            unknown_sentinal=0,
            subsystem_value=1,
            signpost_id=99999,
            signpost_name=12345,
            private_strings_offset=0,
            private_strings_size=0,
            ttl_value=15,
            data_ref_value=0,
            firehose_formatters=FirehoseFormatters(),
        )

        assert signpost.signpost_id == 99999
        assert signpost.signpost_name == 12345
        assert signpost.ttl_value == 15


class TestFirehoseTrace:
    """Test FirehoseTrace data structure."""

    def test_firehose_trace_creation(self):
        """Test creating FirehoseTrace."""
        trace = FirehoseTrace(
            unknown_pc_id=0,
            message_data=FirehoseItemData(item_info=[], backtrace_strings=[]),
        )

        assert trace.unknown_pc_id == 0


class TestFirehoseLoss:
    """Test FirehoseLoss data structure."""

    def test_firehose_loss_creation(self):
        """Test creating FirehoseLoss."""
        loss = FirehoseLoss(
            start_time=1000000000,
            end_time=2000000000,
            count=50,
        )

        assert loss.start_time == 1000000000
        assert loss.end_time == 2000000000
        assert loss.count == 50


class TestFirehoseFormatters:
    """Test FirehoseFormatters class."""

    def test_firehose_formatters_defaults(self):
        """Test FirehoseFormatters default values."""
        formatters = FirehoseFormatters()
        assert formatters.main_exe is False
        assert formatters.shared_cache is False
        assert formatters.has_large_offset == 0
        assert formatters.large_shared_cache == 0
        assert formatters.absolute is False
        assert formatters.uuid_relative == ""
        assert formatters.main_plugin is False
        assert formatters.pc_style is False
        assert formatters.main_exe_alt_index == 0

    def test_firehose_formatters_custom(self):
        """Test FirehoseFormatters with custom values."""
        formatters = FirehoseFormatters(
            main_exe=True,
            shared_cache=False,
            has_large_offset=0x1000,
            large_shared_cache=0,
            absolute=False,
            uuid_relative="",
            main_plugin=False,
            pc_style=False,
            main_exe_alt_index=0,
        )
        assert formatters.main_exe is True
        assert formatters.has_large_offset == 0x1000
