# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Core data structures and log assembly for macOS Unified Logs."""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .catalog import CatalogChunk
from .chunks.firehose.firehose_log import Firehose, FirehoseItemInfo, FirehosePreamble
from .chunks.firehose.activity import FirehoseActivity
from .chunks.firehose.nonactivity import FirehoseNonActivity
from .chunks.firehose.signpost import FirehoseSignpost
from .chunks.firehose.trace import FirehoseTrace
from .chunks.oversize import Oversize
from .chunks.simpledump import SimpleDump
from .chunks.statedump import Statedump
from .chunkset import ChunksetChunk
from .header import HeaderChunk
from .message import format_firehose_log_message
from .preamble import LogPreamble
from .timesync import TimesyncBoot
from .traits import FileProvider
from .util import padding_size_8, unixepoch_to_iso, encode_standard, extract_string

logger = logging.getLogger(__name__)


class LogType(Enum):
    """Log entry type enumeration."""
    Debug = "Debug"
    Info = "Info"
    Default = "Default"
    Error = "Error"
    Fault = "Fault"
    Create = "Create"
    Useraction = "Useraction"
    ProcessSignpostEvent = "ProcessSignpostEvent"
    ProcessSignpostStart = "ProcessSignpostStart"
    ProcessSignpostEnd = "ProcessSignpostEnd"
    SystemSignpostEvent = "SystemSignpostEvent"
    SystemSignpostStart = "SystemSignpostStart"
    SystemSignpostEnd = "SystemSignpostEnd"
    ThreadSignpostEvent = "ThreadSignpostEvent"
    ThreadSignpostStart = "ThreadSignpostStart"
    ThreadSignpostEnd = "ThreadSignpostEnd"
    Simpledump = "Simpledump"
    Statedump = "Statedump"
    Loss = "Loss"


class EventType(Enum):
    """Event type enumeration."""
    Unknown = "Unknown"
    Log = "Log"
    Activity = "Activity"
    Trace = "Trace"
    Signpost = "Signpost"
    Simpledump = "Simpledump"
    Statedump = "Statedump"
    Loss = "Loss"


@dataclass
class UnifiedLogCatalogData:
    """Catalog data with associated firehose, simpledump, statedump, and oversize entries."""
    catalog: CatalogChunk = field(default_factory=CatalogChunk)
    firehose: List[FirehosePreamble] = field(default_factory=list)
    simpledump: List[SimpleDump] = field(default_factory=list)
    statedump: List[Statedump] = field(default_factory=list)
    oversize: List[Oversize] = field(default_factory=list)


@dataclass
class UnifiedLogData:
    """Complete unified log data structure."""
    header: List[HeaderChunk] = field(default_factory=list)
    catalog_data: List[UnifiedLogCatalogData] = field(default_factory=list)
    oversize: List[Oversize] = field(default_factory=list)


@dataclass
class LogData:
    """Reconstructed log entry."""
    subsystem: str = ""
    thread_id: int = 0
    pid: int = 0
    euid: int = 0
    library: str = ""
    library_uuid: str = ""
    activity_id: int = 0
    time: float = 0.0
    category: str = ""
    event_type: EventType = EventType.Unknown
    log_type: LogType = LogType.Default
    process: str = ""
    process_uuid: str = ""
    message: str = ""
    raw_message: str = ""
    boot_uuid: str = ""
    timezone_name: str = ""
    message_entries: List[FirehoseItemInfo] = field(default_factory=list)
    timestamp: str = ""

    @staticmethod
    def get_log_type(log_type: int, activity_type: int) -> LogType:
        """Return log type based on parsed log data.

        Args:
            log_type: Log type code
            activity_type: Activity type code

        Returns:
            LogType enum value
        """
        if log_type == 0x1:
            if activity_type == 2:
                return LogType.Create
            return LogType.Info
        elif log_type == 0x2:
            return LogType.Debug
        elif log_type == 0x3:
            return LogType.Useraction
        elif log_type == 0x10:
            return LogType.Error
        elif log_type == 0x11:
            return LogType.Fault
        elif log_type == 0x80:
            return LogType.ProcessSignpostEvent
        elif log_type == 0x81:
            return LogType.ProcessSignpostStart
        elif log_type == 0x82:
            return LogType.ProcessSignpostEnd
        elif log_type == 0xc0:
            return LogType.SystemSignpostEvent
        elif log_type == 0xc1:
            return LogType.SystemSignpostStart
        elif log_type == 0xc2:
            return LogType.SystemSignpostEnd
        elif log_type == 0x40:
            return LogType.ThreadSignpostEvent
        elif log_type == 0x41:
            return LogType.ThreadSignpostStart
        elif log_type == 0x42:
            return LogType.ThreadSignpostEnd
        else:
            return LogType.Default

    @staticmethod
    def get_event_type(event_type: int) -> EventType:
        """Return the log event type based on parsed log data.

        Args:
            event_type: Event type code

        Returns:
            EventType enum value
        """
        if event_type == 0x4:
            return EventType.Log
        elif event_type == 0x2:
            return EventType.Activity
        elif event_type == 0x3:
            return EventType.Trace
        elif event_type == 0x6:
            return EventType.Signpost
        elif event_type == 0x7:
            return EventType.Loss
        else:
            return EventType.Unknown


def parse_unified_log(data: bytes) -> Tuple[bytes, UnifiedLogData]:
    """Parse the Unified log data read from a tracev3 file.

    Args:
        data: Raw bytes from tracev3 file

    Returns:
        Tuple of (remaining data, UnifiedLogData)
    """
    unified_log_data = UnifiedLogData()
    catalog_data = UnifiedLogCatalogData()

    input_data = data
    chunk_preamble_size = 16

    HEADER_CHUNK = 0x1000
    CATALOG_CHUNK = 0x600b
    CHUNKSET_CHUNK = 0x600d

    while len(input_data) >= chunk_preamble_size:
        try:
            _, preamble = LogPreamble.detect_preamble(input_data)
        except Exception as e:
            logger.warning(f"Failed to detect preamble: {e}")
            break

        chunk_size = preamble.chunk_data_size
        total_size = chunk_size + chunk_preamble_size

        if len(input_data) < total_size:
            logger.warning(f"Not enough data for chunk: need {total_size}, have {len(input_data)}")
            break

        chunk_data = input_data[:total_size]
        input_data = input_data[total_size:]

        if preamble.chunk_tag == HEADER_CHUNK:
            _get_header_data(chunk_data, unified_log_data)
        elif preamble.chunk_tag == CATALOG_CHUNK:
            if catalog_data.catalog.chunk_tag != 0:
                unified_log_data.catalog_data.append(catalog_data)
            catalog_data = UnifiedLogCatalogData()
            _get_catalog_data(chunk_data, catalog_data)
        elif preamble.chunk_tag == CHUNKSET_CHUNK:
            _get_chunkset_data(chunk_data, catalog_data, unified_log_data)
        else:
            logger.error(f"[macos-unifiedlogs] Unknown chunk type: {preamble.chunk_tag}")

        # Handle padding
        padding = padding_size_8(preamble.chunk_data_size)
        if len(input_data) < padding:
            break
        input_data = input_data[padding:]

        if not input_data or len(input_data) < chunk_preamble_size:
            break

    # Make sure to get the last catalog
    if catalog_data.catalog.chunk_tag != 0:
        unified_log_data.catalog_data.append(catalog_data)

    return (input_data, unified_log_data)


def _get_header_data(data: bytes, unified_log_data: UnifiedLogData) -> None:
    """Get the header of the Unified Log data.

    Args:
        data: Raw header chunk data
        unified_log_data: UnifiedLogData to populate
    """
    try:
        _, header_data = HeaderChunk.parse_header(data)
        unified_log_data.header.append(header_data)
    except Exception as e:
        logger.error(f"[macos-unifiedlogs] Failed to parse header data: {e}")


def _get_catalog_data(data: bytes, catalog_data: UnifiedLogCatalogData) -> None:
    """Get the Catalog of the Unified Log data.

    Args:
        data: Raw catalog chunk data
        catalog_data: UnifiedLogCatalogData to populate
    """
    try:
        _, catalog = CatalogChunk.parse_catalog(data)
        catalog_data.catalog = catalog
    except Exception as e:
        logger.error(f"[macos-unifiedlogs] Failed to parse catalog data: {e}")


def _get_chunkset_data(
    data: bytes,
    catalog_data: UnifiedLogCatalogData,
    unified_log_data: UnifiedLogData,
) -> None:
    """Get the Chunkset of the Unified Log data.

    Args:
        data: Raw chunkset chunk data
        catalog_data: UnifiedLogCatalogData to populate
        unified_log_data: UnifiedLogData to populate with oversize entries
    """
    try:
        _, chunkset_data = ChunksetChunk.parse_chunkset(data)
        ChunksetChunk.parse_chunkset_data(chunkset_data.decompressed_data, catalog_data)
        unified_log_data.oversize.extend(catalog_data.oversize)
    except Exception as e:
        logger.error(f"[macos-unifiedlogs] Failed to parse chunkset data: {e}")


def build_log(
    unified_log_data: UnifiedLogData,
    provider: FileProvider,
    timesync_data: Dict[str, TimesyncBoot],
    exclude_missing: bool = False,
) -> Tuple[List[LogData], UnifiedLogData]:
    """Reconstruct Unified Log entries.

    Uses the binary strings data, cached strings data, timesync data, and unified log
    to reconstruct human-readable log entries.

    Args:
        unified_log_data: Parsed unified log data
        provider: File provider for string lookups
        timesync_data: Timesync data for timestamp calculation
        exclude_missing: If True, exclude log entries with missing data

    Returns:
        Tuple of (list of LogData, UnifiedLogData with missing entries)
    """
    log_data_vec: List[LogData] = []
    missing_unified_log_data = UnifiedLogData()

    if not unified_log_data.header:
        return (log_data_vec, missing_unified_log_data)

    boot_uuid = unified_log_data.header[0].boot_uuid
    timezone_path = unified_log_data.header[0].timezone_path
    timezone_name = timezone_path.split('/')[-1] if '/' in timezone_path else "Unknown Timezone Name"

    for catalog_data in unified_log_data.catalog_data:
        # Process firehose entries
        for preamble in catalog_data.firehose:
            for firehose in preamble.public_data:
                # Calculate continuous time
                firehose_log_entry_continuous_time = (
                    firehose.continous_time_delta |
                    (firehose.continous_time_delta_upper << 32)
                )
                continuous_time = preamble.base_continous_time + firehose_log_entry_continuous_time

                # Calculate timestamp
                timestamp = TimesyncBoot.get_timestamp(
                    timesync_data,
                    boot_uuid,
                    continuous_time,
                    preamble.base_continous_time,
                )

                log_data = LogData(
                    thread_id=firehose.thread_id,
                    pid=catalog_data.catalog.get_pid(
                        preamble.first_number_proc_id,
                        preamble.second_number_proc_id,
                    ),
                    time=timestamp,
                    timestamp=unixepoch_to_iso(int(timestamp)),
                    log_type=LogData.get_log_type(
                        firehose.unknown_log_type,
                        firehose.unknown_log_activity_type,
                    ),
                    event_type=LogData.get_event_type(firehose.unknown_log_activity_type),
                    euid=catalog_data.catalog.get_euid(
                        preamble.first_number_proc_id,
                        preamble.second_number_proc_id,
                    ),
                    boot_uuid=boot_uuid,
                    timezone_name=timezone_name,
                    message_entries=firehose.message.item_info[:],
                )

                # Process based on activity type
                if firehose.unknown_log_activity_type == 0x4:  # Non-activity
                    log_data.activity_id = firehose.firehose_non_activity.unknown_activity_id
                    _process_nonactivity(
                        firehose, preamble, catalog_data, unified_log_data,
                        provider, log_data, exclude_missing
                    )
                elif firehose.unknown_log_activity_type == 0x7:  # Loss
                    log_data.event_type = EventType.Loss
                    log_data.log_type = LogType.Loss
                elif firehose.unknown_log_activity_type == 0x2:  # Activity
                    log_data.activity_id = firehose.firehose_activity.unknown_activity_id
                    _process_activity(
                        firehose, preamble, catalog_data,
                        provider, log_data, exclude_missing
                    )
                elif firehose.unknown_log_activity_type == 0x6:  # Signpost
                    log_data.activity_id = firehose.firehose_signpost.unknown_activity_id
                    _process_signpost(
                        firehose, preamble, catalog_data, unified_log_data,
                        provider, log_data, exclude_missing
                    )
                elif firehose.unknown_log_activity_type == 0x3:  # Trace
                    _process_trace(
                        firehose, preamble, catalog_data,
                        provider, log_data, exclude_missing
                    )
                else:
                    logger.error(f"[macos-unifiedlogs] Parsed unknown log firehose data: {firehose}")

                log_data_vec.append(log_data)

        # Process simpledump entries
        for simpledump in catalog_data.simpledump:
            no_firehose_preamble = 1
            timestamp = TimesyncBoot.get_timestamp(
                timesync_data,
                boot_uuid,
                simpledump.continous_time,
                no_firehose_preamble,
            )
            log_data = LogData(
                subsystem=simpledump.subsystem,
                thread_id=simpledump.thread_id,
                pid=simpledump.first_proc_id,
                time=timestamp,
                timestamp=unixepoch_to_iso(int(timestamp)),
                log_type=LogType.Simpledump,
                event_type=EventType.Simpledump,
                message=simpledump.message_string,
                boot_uuid=boot_uuid,
                timezone_name=timezone_name,
                library_uuid=simpledump.sender_uuid,
                process_uuid=simpledump.dsc_uuid,
            )
            log_data_vec.append(log_data)

        # Process statedump entries
        for statedump in catalog_data.statedump:
            no_firehose_preamble = 1
            timestamp = TimesyncBoot.get_timestamp(
                timesync_data,
                boot_uuid,
                statedump.continuous_time,
                no_firehose_preamble,
            )

            # Parse statedump data based on type
            if statedump.unknown_data_type == 0x1:
                data_string = Statedump.parse_statedump_plist(statedump.statedump_data)
            elif statedump.unknown_data_type == 0x2:
                # Protobuf - not implemented, just encode as base64
                data_string = f"Protobuf data: {encode_standard(statedump.statedump_data)}"
            elif statedump.unknown_data_type == 0x3:
                data_string = Statedump.parse_statedump_object(
                    statedump.statedump_data,
                    statedump.title_name,
                )
            else:
                logger.warning(f"Unknown statedump data type: {statedump.unknown_data_type}")
                try:
                    _, string_data = extract_string(statedump.statedump_data)
                    data_string = string_data
                except Exception as e:
                    logger.error(f"[macos-unifiedlogs] Failed to extract string from statedump: {e}")
                    data_string = "Failed to extract string from statedump"

            log_data = LogData(
                pid=statedump.first_proc_id,
                activity_id=statedump.activity_id,
                time=timestamp,
                timestamp=unixepoch_to_iso(int(timestamp)),
                event_type=EventType.Statedump,
                log_type=LogType.Statedump,
                message=f"title: {statedump.title_name}\nObject Type: {statedump.decoder_library}\nObject Type: {statedump.decoder_type}\n{data_string}",
                boot_uuid=boot_uuid,
                timezone_name=timezone_name,
            )
            log_data_vec.append(log_data)

    return (log_data_vec, missing_unified_log_data)


def _process_nonactivity(
    firehose: Firehose,
    preamble: FirehosePreamble,
    catalog_data: UnifiedLogCatalogData,
    unified_log_data: UnifiedLogData,
    provider: FileProvider,
    log_data: LogData,
    exclude_missing: bool,
) -> None:
    """Process non-activity log entry."""
    try:
        _, results = FirehoseNonActivity.get_firehose_nonactivity_strings(
            firehose.firehose_non_activity,
            provider,
            firehose.format_string_location,
            preamble.first_number_proc_id,
            preamble.second_number_proc_id,
            catalog_data.catalog,
        )

        log_data.library = results.library
        log_data.library_uuid = results.library_uuid
        log_data.process = results.process
        log_data.process_uuid = results.process_uuid
        log_data.raw_message = results.format_string

        # Check for oversize data
        if firehose.firehose_non_activity.data_ref_value != 0:
            oversize_strings = Oversize.get_oversize_strings(
                firehose.firehose_non_activity.data_ref_value,
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
                unified_log_data.oversize,
            )
            log_message = format_firehose_log_message(
                results.format_string,
                oversize_strings,
            )
        else:
            log_message = format_firehose_log_message(
                results.format_string,
                firehose.message.item_info,
            )

        if firehose.message.backtrace_strings:
            log_data.message = f"Backtrace:\n{chr(10).join(firehose.message.backtrace_strings)}\n{log_message}"
        else:
            log_data.message = log_message

    except Exception as e:
        logger.warning(f"[macos-unifiedlogs] Failed to get message string data for firehose non-activity log entry: {e}")

    # Get subsystem info
    if firehose.firehose_non_activity.subsystem_value != 0:
        try:
            _, subsystem = catalog_data.catalog.get_subsystem(
                firehose.firehose_non_activity.subsystem_value,
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
            )
            log_data.subsystem = subsystem.subsystem
            log_data.category = subsystem.category
        except Exception as e:
            logger.warning(f"[macos-unifiedlogs] Failed to get subsystem: {e}")


def _process_activity(
    firehose: Firehose,
    preamble: FirehosePreamble,
    catalog_data: UnifiedLogCatalogData,
    provider: FileProvider,
    log_data: LogData,
    exclude_missing: bool,
) -> None:
    """Process activity log entry."""
    try:
        _, results = FirehoseActivity.get_firehose_activity_strings(
            firehose.firehose_activity,
            provider,
            firehose.format_string_location,
            preamble.first_number_proc_id,
            preamble.second_number_proc_id,
            catalog_data.catalog,
        )

        log_data.library = results.library
        log_data.library_uuid = results.library_uuid
        log_data.process = results.process
        log_data.process_uuid = results.process_uuid
        log_data.raw_message = results.format_string

        log_message = format_firehose_log_message(
            results.format_string,
            firehose.message.item_info,
        )

        if firehose.message.backtrace_strings:
            log_data.message = f"Backtrace:\n{chr(10).join(firehose.message.backtrace_strings)}\n{log_message}"
        else:
            log_data.message = log_message

    except Exception as e:
        logger.warning(f"[macos-unifiedlogs] Failed to get message string data for firehose activity log entry: {e}")


def _process_signpost(
    firehose: Firehose,
    preamble: FirehosePreamble,
    catalog_data: UnifiedLogCatalogData,
    unified_log_data: UnifiedLogData,
    provider: FileProvider,
    log_data: LogData,
    exclude_missing: bool,
) -> None:
    """Process signpost log entry."""
    try:
        _, results = FirehoseSignpost.get_firehose_signpost(
            firehose.firehose_signpost,
            provider,
            firehose.format_string_location,
            preamble.first_number_proc_id,
            preamble.second_number_proc_id,
            catalog_data.catalog,
        )

        log_data.library = results.library
        log_data.library_uuid = results.library_uuid
        log_data.process = results.process
        log_data.process_uuid = results.process_uuid
        log_data.raw_message = results.format_string

        # Check for oversize data
        if firehose.firehose_non_activity.data_ref_value != 0:
            oversize_strings = Oversize.get_oversize_strings(
                firehose.firehose_non_activity.data_ref_value,
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
                unified_log_data.oversize,
            )
            log_message = format_firehose_log_message(
                results.format_string,
                oversize_strings,
            )
        else:
            log_message = format_firehose_log_message(
                results.format_string,
                firehose.message.item_info,
            )

        log_message = (
            f"Signpost ID: {firehose.firehose_signpost.signpost_id:X} - "
            f"Signpost Name: {firehose.firehose_signpost.signpost_name:X}\n {log_message}"
        )

        if firehose.message.backtrace_strings:
            log_data.message = f"Backtrace:\n{chr(10).join(firehose.message.backtrace_strings)}\n{log_message}"
        else:
            log_data.message = log_message

    except Exception as e:
        logger.warning(f"[macos-unifiedlogs] Failed to get message string data for firehose signpost log entry: {e}")

    # Get subsystem info
    if firehose.firehose_signpost.subsystem != 0:
        try:
            _, subsystem = catalog_data.catalog.get_subsystem(
                firehose.firehose_signpost.subsystem,
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
            )
            log_data.subsystem = subsystem.subsystem
            log_data.category = subsystem.category
        except Exception as e:
            logger.warning(f"[macos-unifiedlogs] Failed to get subsystem: {e}")


def _process_trace(
    firehose: Firehose,
    preamble: FirehosePreamble,
    catalog_data: UnifiedLogCatalogData,
    provider: FileProvider,
    log_data: LogData,
    exclude_missing: bool,
) -> None:
    """Process trace log entry."""
    try:
        _, results = FirehoseTrace.get_firehose_trace_strings(
            provider,
            firehose.format_string_location,
            preamble.first_number_proc_id,
            preamble.second_number_proc_id,
            catalog_data.catalog,
        )

        log_data.library = results.library
        log_data.library_uuid = results.library_uuid
        log_data.process = results.process
        log_data.process_uuid = results.process_uuid

        log_message = format_firehose_log_message(
            results.format_string,
            firehose.message.item_info,
        )

        if firehose.message.backtrace_strings:
            log_data.message = f"Backtrace:\n{chr(10).join(firehose.message.backtrace_strings)}\n{log_message}"
        else:
            log_data.message = log_message

    except Exception as e:
        logger.warning(f"[macos-unifiedlogs] Failed to get message string data for firehose trace log entry: {e}")
