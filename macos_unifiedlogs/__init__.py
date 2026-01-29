# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
macOS Unified Log Parser

A Python library for parsing macOS Unified Log files (tracev3 format).

Example usage:

    from macos_unifiedlogs import LogarchiveProvider, collect_timesync, build_log
    from macos_unifiedlogs.unified_log import parse_unified_log

    # Parse from logarchive
    provider = LogarchiveProvider("/path/to/system.logarchive")
    timesync_data = collect_timesync(provider)

    # Iterate through logs
    for source_file in provider.tracev3_files():
        with source_file.reader() as reader:
            data = reader.read()
            _, unified_log_data = parse_unified_log(data)
            logs, missing = build_log(unified_log_data, provider, timesync_data, exclude_missing=True)
            for log in logs:
                print(f"{log.timestamp} [{log.subsystem}] {log.message}")
"""

__version__ = "0.1.0"

# Core data structures
from .unified_log import (
    LogType,
    EventType,
    UnifiedLogData,
    UnifiedLogCatalogData,
    LogData,
    parse_unified_log,
    build_log,
)

# File providers
from .filesystem import (
    LogarchiveProvider,
    LiveSystemProvider,
    FileSourceFile,
)

# Abstract base classes
from .traits import (
    FileProvider,
    SourceFile,
)

# High-level API
from .parser import (
    parse_log,
    collect_strings,
    collect_shared_strings,
    collect_timesync,
    parse_all_logs,
)

# Iterator
from .iterator import UnifiedLogIterator

# Supporting parsers
from .header import HeaderChunk
from .catalog import CatalogChunk
from .chunkset import ChunksetChunk
from .timesync import TimesyncBoot, Timesync
from .uuidtext import UUIDText, UUIDTextEntry
from .dsc import SharedCacheStrings

# Message formatting
from .message import format_firehose_log_message

# Exceptions
from .error import (
    ParserError,
    PathError,
    Tracev3ParseError,
    InvalidSignatureError,
    DecoderError,
    DecompressionError,
)

__all__ = [
    # Version
    '__version__',

    # Core data structures
    'LogType',
    'EventType',
    'UnifiedLogData',
    'UnifiedLogCatalogData',
    'LogData',
    'parse_unified_log',
    'build_log',

    # File providers
    'LogarchiveProvider',
    'LiveSystemProvider',
    'FileSourceFile',

    # Abstract base classes
    'FileProvider',
    'SourceFile',

    # High-level API
    'parse_log',
    'collect_strings',
    'collect_shared_strings',
    'collect_timesync',
    'parse_all_logs',

    # Iterator
    'UnifiedLogIterator',

    # Supporting parsers
    'HeaderChunk',
    'CatalogChunk',
    'ChunksetChunk',
    'TimesyncBoot',
    'Timesync',
    'UUIDText',
    'UUIDTextEntry',
    'SharedCacheStrings',

    # Message formatting
    'format_firehose_log_message',

    # Exceptions
    'ParserError',
    'PathError',
    'Tracev3ParseError',
    'InvalidSignatureError',
    'DecoderError',
    'DecompressionError',
]
