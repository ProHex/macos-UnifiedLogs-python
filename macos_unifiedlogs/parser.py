# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""High-level API for parsing macOS Unified Logs."""

import logging
from typing import BinaryIO, Dict, List, Optional, Tuple

from .dsc import SharedCacheStrings
from .timesync import TimesyncBoot
from .traits import FileProvider
from .unified_log import LogData, UnifiedLogData, build_log, parse_unified_log
from .uuidtext import UUIDText

logger = logging.getLogger(__name__)


def parse_log(reader: BinaryIO) -> Tuple[bytes, UnifiedLogData]:
    """Parse a single tracev3 file.

    Args:
        reader: Binary reader for the tracev3 file

    Returns:
        Tuple of (remaining data, UnifiedLogData)
    """
    data = reader.read()
    return parse_unified_log(data)


def collect_strings(provider: FileProvider) -> Dict[str, UUIDText]:
    """Load all UUIDText files and return a dictionary keyed by UUID.

    Args:
        provider: File provider to read UUIDText files from

    Returns:
        Dictionary mapping UUID strings to UUIDText data
    """
    strings: Dict[str, UUIDText] = {}

    for source_file in provider.uuidtext_files():
        try:
            with source_file.reader() as reader:
                data = reader.read()
                _, uuidtext = UUIDText.parse_uuidtext(data)

                # Extract UUID from filename
                # UUIDText files are named with the UUID (without the first two chars which are in the directory name)
                path = source_file.source_path()
                # Get the directory name and filename
                parts = path.replace('\\', '/').split('/')
                if len(parts) >= 2:
                    dir_name = parts[-2]  # First two hex chars
                    file_name = parts[-1]  # Remaining hex chars
                    uuid = (dir_name + file_name).upper()
                    strings[uuid] = uuidtext
                    provider.set_uuidtext(uuid, uuidtext)
        except Exception as e:
            logger.warning(f"Failed to parse UUIDText file {source_file.source_path()}: {e}")

    return strings


def collect_shared_strings(provider: FileProvider) -> Dict[str, SharedCacheStrings]:
    """Load all DSC (shared cache strings) files and return a dictionary keyed by UUID.

    Args:
        provider: File provider to read DSC files from

    Returns:
        Dictionary mapping UUID strings to SharedCacheStrings data
    """
    shared_strings: Dict[str, SharedCacheStrings] = {}

    for source_file in provider.dsc_files():
        try:
            with source_file.reader() as reader:
                data = reader.read()
                _, dsc = SharedCacheStrings.parse_dsc(data)

                # Extract UUID from filename or use the UUID in the DSC
                # DSC files may have multiple UUIDs
                for uuid_entry in dsc.uuids:
                    uuid = uuid_entry.uuid.upper()
                    shared_strings[uuid] = dsc
                    provider.set_dsc(uuid, dsc)
        except Exception as e:
            logger.warning(f"Failed to parse DSC file {source_file.source_path()}: {e}")

    return shared_strings


def collect_timesync(provider: FileProvider) -> Dict[str, TimesyncBoot]:
    """Load all timesync files and return a dictionary keyed by boot UUID.

    Args:
        provider: File provider to read timesync files from

    Returns:
        Dictionary mapping boot UUID strings to TimesyncBoot data
    """
    timesync_data: Dict[str, TimesyncBoot] = {}

    for source_file in provider.timesync_files():
        try:
            with source_file.reader() as reader:
                data = reader.read()
                _, timesync_list = TimesyncBoot.parse_timesync_data(data)

                for timesync_boot in timesync_list:
                    timesync_data[timesync_boot.boot_uuid] = timesync_boot
        except Exception as e:
            logger.warning(f"Failed to parse timesync file {source_file.source_path()}: {e}")

    return timesync_data


def parse_all_logs(
    provider: FileProvider,
    exclude_missing: bool = False,
) -> List[LogData]:
    """Parse all log files from a provider.

    This is a convenience function that:
    1. Collects all UUIDText strings
    2. Collects all DSC shared strings
    3. Collects all timesync data
    4. Parses all tracev3 files
    5. Builds and returns all log entries

    Args:
        provider: File provider to read files from
        exclude_missing: If True, exclude log entries with missing data

    Returns:
        List of all LogData entries
    """
    # Collect supporting data
    logger.info("Collecting UUIDText strings...")
    collect_strings(provider)

    logger.info("Collecting DSC shared strings...")
    collect_shared_strings(provider)

    logger.info("Collecting timesync data...")
    timesync_data = collect_timesync(provider)

    # Parse all tracev3 files
    all_logs: List[LogData] = []

    for source_file in provider.tracev3_files():
        logger.info(f"Parsing {source_file.source_path()}...")
        try:
            with source_file.reader() as reader:
                _, unified_log_data = parse_log(reader)
                logs, missing = build_log(
                    unified_log_data,
                    provider,
                    timesync_data,
                    exclude_missing,
                )
                all_logs.extend(logs)
        except Exception as e:
            logger.error(f"Failed to parse {source_file.source_path()}: {e}")

    return all_logs
