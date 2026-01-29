# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for unified log data structures."""

import pytest

from macos_unifiedlogs.unified_log import (
    EventType,
    LogData,
    LogType,
    UnifiedLogCatalogData,
    UnifiedLogData,
)


class TestLogType:
    """Test LogType enum."""

    def test_log_type_values(self):
        """Test LogType enum values."""
        assert LogType.Debug.value == "Debug"
        assert LogType.Info.value == "Info"
        assert LogType.Default.value == "Default"
        assert LogType.Error.value == "Error"
        assert LogType.Fault.value == "Fault"
        assert LogType.Create.value == "Create"
        assert LogType.Useraction.value == "Useraction"

    def test_log_type_signpost_values(self):
        """Test LogType signpost enum values."""
        assert LogType.ProcessSignpostEvent.value == "ProcessSignpostEvent"
        assert LogType.ProcessSignpostStart.value == "ProcessSignpostStart"
        assert LogType.ProcessSignpostEnd.value == "ProcessSignpostEnd"
        assert LogType.SystemSignpostEvent.value == "SystemSignpostEvent"
        assert LogType.SystemSignpostStart.value == "SystemSignpostStart"
        assert LogType.SystemSignpostEnd.value == "SystemSignpostEnd"
        assert LogType.ThreadSignpostEvent.value == "ThreadSignpostEvent"
        assert LogType.ThreadSignpostStart.value == "ThreadSignpostStart"
        assert LogType.ThreadSignpostEnd.value == "ThreadSignpostEnd"

    def test_log_type_other_values(self):
        """Test LogType other enum values."""
        assert LogType.Simpledump.value == "Simpledump"
        assert LogType.Statedump.value == "Statedump"
        assert LogType.Loss.value == "Loss"


class TestEventType:
    """Test EventType enum."""

    def test_event_type_values(self):
        """Test EventType enum values."""
        assert EventType.Unknown.value == "Unknown"
        assert EventType.Log.value == "Log"
        assert EventType.Activity.value == "Activity"
        assert EventType.Trace.value == "Trace"
        assert EventType.Signpost.value == "Signpost"
        assert EventType.Simpledump.value == "Simpledump"
        assert EventType.Statedump.value == "Statedump"
        assert EventType.Loss.value == "Loss"


class TestLogData:
    """Test LogData data structure."""

    def test_log_data_creation(self):
        """Test creating LogData."""
        log = LogData(
            subsystem="com.apple.test",
            thread_id=12345,
            pid=1234,
            euid=501,
            library="/usr/lib/libtest.dylib",
            library_uuid="ABCD1234ABCD1234ABCD1234ABCD1234",
            activity_id=0,
            time=1609459200000000000.0,
            event_type=EventType.Log,
            log_type=LogType.Default,
            process="/usr/bin/testapp",
            process_uuid="1234ABCD1234ABCD1234ABCD1234ABCD",
            message="Test log message",
            raw_message="Test log message",
            boot_uuid="BOOT1234BOOT1234BOOT1234BOOT1234",
            timezone_name="America/Los_Angeles",
            category="default",
        )

        assert log.subsystem == "com.apple.test"
        assert log.pid == 1234
        assert log.message == "Test log message"
        assert log.event_type == EventType.Log
        assert log.log_type == LogType.Default

    def test_log_data_signpost(self):
        """Test creating LogData for signpost."""
        log = LogData(
            subsystem="com.apple.signpost",
            thread_id=99999,
            pid=5678,
            euid=0,
            library="/System/Library/Frameworks/os.framework/os",
            library_uuid="SIGN1234SIGN1234SIGN1234SIGN1234",
            activity_id=1000,
            time=1609459200000000000.0,
            event_type=EventType.Signpost,
            log_type=LogType.ProcessSignpostStart,
            process="/usr/bin/signpostapp",
            process_uuid="PROC1234PROC1234PROC1234PROC1234",
            message="Signpost begin",
            raw_message="Signpost begin",
            boot_uuid="BOOT5678BOOT5678BOOT5678BOOT5678",
            timezone_name="UTC",
            category="signpost",
        )

        assert log.event_type == EventType.Signpost
        assert log.log_type == LogType.ProcessSignpostStart


class TestUnifiedLogCatalogData:
    """Test UnifiedLogCatalogData data structure."""

    def test_unified_log_catalog_data_creation(self):
        """Test creating UnifiedLogCatalogData."""
        from macos_unifiedlogs.catalog import CatalogChunk

        catalog_data = UnifiedLogCatalogData(
            catalog=CatalogChunk(),
            firehose=[],
            simpledump=[],
            statedump=[],
            oversize=[],
        )

        assert catalog_data.firehose == []
        assert catalog_data.simpledump == []
        assert catalog_data.statedump == []
        assert catalog_data.oversize == []

    def test_unified_log_catalog_data_defaults(self):
        """Test UnifiedLogCatalogData default values."""
        catalog_data = UnifiedLogCatalogData()
        assert catalog_data.firehose == []
        assert catalog_data.simpledump == []
        assert catalog_data.statedump == []
        assert catalog_data.oversize == []


class TestUnifiedLogData:
    """Test UnifiedLogData data structure."""

    def test_unified_log_data_creation(self):
        """Test creating UnifiedLogData."""
        log_data = UnifiedLogData(
            header=[],
            catalog_data=[],
            oversize=[],
        )

        assert log_data.header == []
        assert log_data.catalog_data == []
        assert log_data.oversize == []

    def test_unified_log_data_defaults(self):
        """Test UnifiedLogData default values."""
        log_data = UnifiedLogData()
        assert log_data.header == []
        assert log_data.catalog_data == []
        assert log_data.oversize == []

    def test_unified_log_data_with_content(self):
        """Test UnifiedLogData with actual content."""
        from macos_unifiedlogs.header import HeaderChunk

        header = HeaderChunk(
            chunk_tag=0x1000,
            boot_uuid="TEST1234TEST1234TEST1234TEST1234",
            timezone_path="/var/db/timezone/zoneinfo/UTC",
        )

        catalog_data = UnifiedLogCatalogData()

        log_data = UnifiedLogData(
            header=[header],
            catalog_data=[catalog_data],
            oversize=[],
        )

        assert len(log_data.header) == 1
        assert log_data.header[0].boot_uuid == "TEST1234TEST1234TEST1234TEST1234"
        assert len(log_data.catalog_data) == 1
