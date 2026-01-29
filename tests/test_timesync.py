# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for timesync parsing."""

import pytest

from macos_unifiedlogs.timesync import Timesync, TimesyncBoot


class TestTimesync:
    """Test Timesync data structure."""

    def test_timesync_creation(self):
        """Test creating Timesync record."""
        ts = Timesync(
            kernel_time=1000000000,
            signature=0x207354,
            walltime=1609459200000000000,
            timezone=0,
            daylight_savings=0,
        )

        assert ts.kernel_time == 1000000000
        assert ts.signature == 0x207354
        assert ts.walltime == 1609459200000000000

    def test_timesync_defaults(self):
        """Test Timesync default values."""
        ts = Timesync()
        assert ts.kernel_time == 0
        assert ts.signature == 0
        assert ts.walltime == 0
        assert ts.timezone == 0
        assert ts.daylight_savings == 0


class TestTimesyncBoot:
    """Test TimesyncBoot data structure."""

    def test_timesync_boot_creation(self):
        """Test creating TimesyncBoot record."""
        boot = TimesyncBoot(
            boot_uuid="ABCD1234EF567890ABCD1234EF567890",
            timesync=[],
            signature=0xbbb0,
            header_size=48,
            unknown=0,
        )

        assert boot.boot_uuid == "ABCD1234EF567890ABCD1234EF567890"
        assert boot.signature == 0xbbb0
        assert boot.timesync == []

    def test_timesync_boot_with_records(self):
        """Test TimesyncBoot with timesync records."""
        ts1 = Timesync(
            kernel_time=1000000000,
            signature=0x207354,
            walltime=1609459200000000000,
            timezone=0,
            daylight_savings=0,
        )
        ts2 = Timesync(
            kernel_time=2000000000,
            signature=0x207354,
            walltime=1609459201000000000,
            timezone=0,
            daylight_savings=0,
        )

        boot = TimesyncBoot(
            boot_uuid="12345678901234567890123456789012",
            timesync=[ts1, ts2],
            signature=0xbbb0,
            header_size=48,
            unknown=0,
        )

        assert len(boot.timesync) == 2
        assert boot.timesync[0].kernel_time == 1000000000
        assert boot.timesync[1].kernel_time == 2000000000


class TestTimesyncBootGetTimestamp:
    """Test TimesyncBoot.get_timestamp method."""

    def test_get_timestamp_basic(self):
        """Test basic timestamp calculation."""
        ts = Timesync(
            kernel_time=0,
            signature=0x207354,
            walltime=1609459200000000000,  # 2021-01-01 00:00:00 UTC
            timezone=0,
            daylight_savings=0,
        )

        boot = TimesyncBoot(
            boot_uuid="ABCD1234EF567890ABCD1234EF567890",
            timesync=[ts],
            signature=0xbbb0,
            header_size=48,
            unknown=0,
        )

        timesync_data = {"ABCD1234EF567890ABCD1234EF567890": boot}

        # Calculate timestamp with delta of 1 second (in nanoseconds)
        result = TimesyncBoot.get_timestamp(
            timesync_data,
            "ABCD1234EF567890ABCD1234EF567890",
            1000000000,  # delta_time
            0,  # preamble_time
        )

        # Should be approximately 2021-01-01 00:00:01 UTC
        expected = 1609459201000000000.0
        assert abs(result - expected) < 1000000000  # Within 1 second

    def test_get_timestamp_no_boot(self):
        """Test timestamp calculation with missing boot UUID.

        When boot UUID is not found, the function still performs
        the calculation using the delta_time as the continuous time.
        """
        timesync_data = {}

        result = TimesyncBoot.get_timestamp(
            timesync_data,
            "NONEXISTENT",
            1000000000,  # delta_time
            0,  # preamble_time
        )

        # When boot not found, returns delta_time (timebase 1.0)
        # continuous_time = delta_time * 1.0 - 0 = 1000000000
        # return continuous_time + 0 = 1000000000
        assert result == 1000000000.0

    def test_get_timestamp_with_preamble(self):
        """Test timestamp calculation with preamble time."""
        ts = Timesync(
            kernel_time=500000000,
            signature=0x207354,
            walltime=1609459200000000000,
            timezone=0,
            daylight_savings=0,
        )

        boot = TimesyncBoot(
            boot_uuid="TEST",
            timesync=[ts],
            signature=0xbbb0,
            header_size=48,
            unknown=0,
        )

        timesync_data = {"TEST": boot}

        result = TimesyncBoot.get_timestamp(
            timesync_data,
            "TEST",
            1000000000,  # delta_time
            500000000,   # preamble_time
        )

        # Result should be calculated based on both delta and preamble
        assert result > 0
