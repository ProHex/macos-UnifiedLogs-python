# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse the Unified Log timesync files."""

import logging
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .error import InvalidSignatureError

logger = logging.getLogger(__name__)

# Timesync signatures
TIMESYNC_BOOT_SIGNATURE = 0xbbb0
TIMESYNC_RECORD_SIGNATURE = 0x207354


@dataclass
class Timesync:
    """Timesync record structure. Timestamps are in UTC."""
    signature: int = 0
    unknown_flags: int = 0
    kernel_time: int = 0  # Mach continuous timestamp
    walltime: int = 0  # Number of nanoseconds since UNIXEPOCH
    timezone: int = 0
    daylight_savings: int = 0  # 0 is no DST, 1 is DST


@dataclass
class TimesyncBoot:
    """Timesync boot structure."""
    signature: int = 0
    header_size: int = 0
    unknown: int = 0
    boot_uuid: str = ""
    timebase_numerator: int = 0
    timebase_denominator: int = 0
    boot_time: int = 0  # Number of nanoseconds since UNIXEPOCH
    timezone_offset_mins: int = 0
    daylight_savings: int = 0  # 0 is no DST, 1 is DST
    timesync: List[Timesync] = field(default_factory=list)

    @staticmethod
    def parse_timesync_data(data: bytes) -> Tuple[bytes, Dict[str, 'TimesyncBoot']]:
        """Parse the Unified Log timesync files.

        Args:
            data: Raw bytes from timesync file

        Returns:
            Tuple of (remaining data, dict mapping boot_uuid to TimesyncBoot)
        """
        timesync_data: Dict[str, TimesyncBoot] = {}
        offset = 0
        timesync_boot = TimesyncBoot()

        while offset < len(data):
            # Peek at the signature (first 4 bytes for record, first 2 for boot)
            if offset + 4 > len(data):
                break

            timesync_signature = struct.unpack_from('<I', data, offset)[0]

            if timesync_signature == TIMESYNC_RECORD_SIGNATURE:
                # Parse timesync record
                remaining, timesync = TimesyncBoot._parse_timesync(data[offset:])
                timesync_boot.timesync.append(timesync)
                offset = len(data) - len(remaining)
            else:
                # Save current boot data if we have one
                if timesync_boot.signature != 0:
                    if timesync_boot.boot_uuid in timesync_data:
                        timesync_data[timesync_boot.boot_uuid].timesync.extend(timesync_boot.timesync)
                    else:
                        timesync_data[timesync_boot.boot_uuid] = timesync_boot

                # Parse new boot record
                remaining, timesync_boot = TimesyncBoot._parse_timesync_boot(data[offset:])
                offset = len(data) - len(remaining)

        # Add the last boot data
        if timesync_boot.boot_uuid in timesync_data:
            timesync_data[timesync_boot.boot_uuid].timesync.extend(timesync_boot.timesync)
        else:
            timesync_data[timesync_boot.boot_uuid] = timesync_boot

        return (b'', timesync_data)

    @staticmethod
    def _parse_timesync_boot(data: bytes) -> Tuple[bytes, 'TimesyncBoot']:
        """Parse a timesync boot header.

        Args:
            data: Raw bytes starting at boot header

        Returns:
            Tuple of (remaining data, TimesyncBoot)
        """
        if len(data) < 48:
            raise InvalidSignatureError(TIMESYNC_BOOT_SIGNATURE, 0, "Timesync boot")

        # signature: u16, header_size: u16, unknown: u32, boot_uuid: u128 (big endian)
        # timebase_num: u32, timebase_denom: u32, boot_time: i64, tz_offset: u32, dst: u32
        signature = struct.unpack_from('<H', data, 0)[0]

        if signature != TIMESYNC_BOOT_SIGNATURE:
            logger.error(
                f"[macos-unifiedlogs] Incorrect Timesync boot header signature. "
                f"Expected {TIMESYNC_BOOT_SIGNATURE:#x}. Got: {signature:#x}"
            )
            raise InvalidSignatureError(TIMESYNC_BOOT_SIGNATURE, signature, "Timesync boot")

        header_size = struct.unpack_from('<H', data, 2)[0]
        unknown = struct.unpack_from('<I', data, 4)[0]
        boot_uuid_bytes = struct.unpack_from('>QQ', data, 8)  # 128-bit big endian
        boot_uuid = f"{(boot_uuid_bytes[0] << 64) | boot_uuid_bytes[1]:032X}"
        timebase_numerator = struct.unpack_from('<I', data, 24)[0]
        timebase_denominator = struct.unpack_from('<I', data, 28)[0]
        boot_time = struct.unpack_from('<q', data, 32)[0]  # signed 64-bit
        timezone_offset_mins = struct.unpack_from('<I', data, 40)[0]
        daylight_savings = struct.unpack_from('<I', data, 44)[0]

        timesync_boot = TimesyncBoot(
            signature=signature,
            header_size=header_size,
            unknown=unknown,
            boot_uuid=boot_uuid,
            timebase_numerator=timebase_numerator,
            timebase_denominator=timebase_denominator,
            boot_time=boot_time,
            timezone_offset_mins=timezone_offset_mins,
            daylight_savings=daylight_savings,
            timesync=[],
        )

        return (data[48:], timesync_boot)

    @staticmethod
    def _parse_timesync(data: bytes) -> Tuple[bytes, Timesync]:
        """Parse a timesync record.

        Args:
            data: Raw bytes starting at timesync record

        Returns:
            Tuple of (remaining data, Timesync)
        """
        if len(data) < 32:
            raise InvalidSignatureError(TIMESYNC_RECORD_SIGNATURE, 0, "Timesync record")

        # signature: u32, unknown_flags: u32, kernel_time: u64, walltime: i64, timezone: u32, dst: u32
        signature = struct.unpack_from('<I', data, 0)[0]

        if signature != TIMESYNC_RECORD_SIGNATURE:
            logger.error(
                f"[macos-unifiedlogs] Incorrect Timesync record header signature. "
                f"Expected {TIMESYNC_RECORD_SIGNATURE:#x}. Got: {signature:#x}"
            )
            raise InvalidSignatureError(TIMESYNC_RECORD_SIGNATURE, signature, "Timesync record")

        unknown_flags = struct.unpack_from('<I', data, 4)[0]
        kernel_time = struct.unpack_from('<Q', data, 8)[0]
        walltime = struct.unpack_from('<q', data, 16)[0]
        timezone = struct.unpack_from('<I', data, 24)[0]
        daylight_savings = struct.unpack_from('<I', data, 28)[0]

        timesync = Timesync(
            signature=signature,
            unknown_flags=unknown_flags,
            kernel_time=kernel_time,
            walltime=walltime,
            timezone=timezone,
            daylight_savings=daylight_savings,
        )

        return (data[32:], timesync)

    @staticmethod
    def get_timestamp(
        timesync_data: Dict[str, 'TimesyncBoot'],
        boot_uuid: str,
        firehose_log_delta_time: int,
        firehose_preamble_time: int,
    ) -> float:
        """Calculate timestamp for firehose log entry.

        Timestamp calculation logic:
        - Firehose Log entry timestamp is calculated using firehose_preamble_time,
          firehose.continous_time_delta, and timesync timestamps
        - Firehose log header/preamble contains a base timestamp
        - All log entries following the header are continuous from that base
        - EXCEPT when the base time is zero. If the base time is zero the TimeSync
          boot record boot time is used

        For Apple Silicon (ARM), we need to multiply timesync_cont_time and
        firehose_log_delta_time by the timebase 125.0/3.0 to get the nanosecond
        representation.

        Args:
            timesync_data: Dictionary mapping boot UUID to TimesyncBoot
            boot_uuid: Boot UUID from the tracev3 header
            firehose_log_delta_time: Combined continuous time delta from firehose
            firehose_preamble_time: Base continuous time from firehose preamble

        Returns:
            Unix epoch timestamp in nanoseconds (as float)
        """
        timesync_continuous_time = 0
        timesync_walltime = 0

        # Apple Intel uses 1/1 as the timebase
        timebase_adjustment = 1.0

        timesync = timesync_data.get(boot_uuid)
        if timesync is not None:
            # For Apple Silicon (ARM) we need to adjust the mach time by multiplying
            # by 125.0/3.0 to get the accurate nanosecond count
            if timesync.timebase_numerator == 125 and timesync.timebase_denominator == 3:
                timebase_adjustment = 125.0 / 3.0

            # A preamble time of 0 means we need to use the timesync header boot time
            # as our minimum value. We also set the timesync_continuous_time to zero
            if firehose_preamble_time == 0:
                timesync_continuous_time = 0
                timesync_walltime = timesync.boot_time

            for timesync_record in timesync.timesync:
                if timesync_record.kernel_time > firehose_log_delta_time:
                    if timesync_continuous_time == 0 and timesync_walltime == 0:
                        timesync_continuous_time = timesync_record.kernel_time
                        timesync_walltime = timesync_record.walltime
                    break

                timesync_continuous_time = timesync_record.kernel_time
                timesync_walltime = timesync_record.walltime

        continuous_time = (
            firehose_log_delta_time * timebase_adjustment
            - timesync_continuous_time * timebase_adjustment
        )
        return continuous_time + timesync_walltime
