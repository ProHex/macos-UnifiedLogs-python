# macos-unifiedlogs (Python)

A Python library for parsing Apple's Unified Logging system (tracev3 files) from macOS and iOS devices.

This is a Python port of the [macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs) Rust library, maintaining API compatibility while providing a pure Python implementation.

## Features

- Parse tracev3 log files from macOS and iOS devices
- Support for logarchive bundles (`.logarchive` directories)
- Support for live system log access on macOS
- Parse all supporting file formats:
  - UUIDText files (format string lookups)
  - DSC shared cache strings (v1 and v2)
  - Timesync files (timestamp calculation)
- Handle all log entry types:
  - Log (non-activity)
  - Activity
  - Signpost
  - Trace
  - Simpledump
  - Statedump
  - Loss
- ARM (Apple Silicon) and Intel timestamp support
- LZ4 decompression of chunkset data

## Installation

### Requirements

- Python 3.8+
- lz4 library

### Install from source

```bash
cd python
pip install -e .
```

### Dependencies

```bash
pip install lz4
```

## Quick Start

### Parse a logarchive

```python
from macos_unifiedlogs import (
    LogarchiveProvider,
    parse_unified_log,
    build_log,
    TimesyncBoot,
    UUIDText,
)
import os

# Create provider for logarchive
provider = LogarchiveProvider("/path/to/system.logarchive")

# Load timesync data for timestamp calculation
timesync_data = {}
for ts_file in provider.timesync_files():
    with ts_file.reader() as f:
        data = f.read()
    _, boots = TimesyncBoot.parse_timesync_data(data)
    timesync_data.update(boots)

# Load UUIDText files for string lookups
for uuid_file in provider.uuidtext_files():
    with uuid_file.reader() as f:
        data = f.read()
    _, uuidtext = UUIDText.parse_uuidtext(data)
    # Extract UUID from path (e.g., "AB/CD1234..." -> "ABCD1234...")
    path_parts = uuid_file.source_path().split(os.sep)
    uuid = path_parts[-2] + path_parts[-1]
    provider.set_uuidtext(uuid, uuidtext)

# Parse tracev3 files
for tracev3_file in provider.tracev3_files():
    with tracev3_file.reader() as f:
        data = f.read()

    # Parse the unified log data
    _, unified_data = parse_unified_log(data)

    # Build human-readable log entries
    logs, missing = build_log(unified_data, provider, timesync_data)

    for log in logs:
        print(f"{log.timestamp} [{log.log_type.value}] {log.subsystem}")
        print(f"  Process: {log.process} (PID: {log.pid})")
        print(f"  Message: {log.message}")
```

### Parse a single tracev3 file

```python
from macos_unifiedlogs import parse_unified_log

with open("logdata.tracev3", "rb") as f:
    data = f.read()

_, unified_data = parse_unified_log(data)

# Access parsed data
for header in unified_data.header:
    print(f"Boot UUID: {header.boot_uuid}")
    print(f"Timezone: {header.timezone_path}")

for catalog_data in unified_data.catalog_data:
    print(f"Firehose preambles: {len(catalog_data.firehose)}")
    print(f"Simpledump entries: {len(catalog_data.simpledump)}")
```

### Using the Iterator

For memory-efficient processing of large log files:

```python
from macos_unifiedlogs import UnifiedLogIterator, LogarchiveProvider

provider = LogarchiveProvider("/path/to/system.logarchive")

for source_file in provider.tracev3_files():
    with source_file.reader() as reader:
        data = reader.read()
        iterator = UnifiedLogIterator(data)

        for chunk in iterator:
            # Process each chunk individually
            print(f"Header count: {len(chunk.header)}")
            print(f"Catalog count: {len(chunk.catalog_data)}")
```

## API Reference

### File Providers

#### LogarchiveProvider

Provider for `.logarchive` bundles created by `log collect` on macOS or sysdiagnose on iOS.

```python
from macos_unifiedlogs import LogarchiveProvider

provider = LogarchiveProvider("/path/to/archive.logarchive")

# Iterate over tracev3 files
for source_file in provider.tracev3_files():
    path = source_file.source_path()
    with source_file.reader() as f:
        data = f.read()

# Iterate over UUIDText files
for source_file in provider.uuidtext_files():
    ...

# Iterate over DSC files
for source_file in provider.dsc_files():
    ...

# Iterate over timesync files
for source_file in provider.timesync_files():
    ...

# Cache management
provider.set_uuidtext(uuid, uuidtext_obj)
provider.get_uuidtext(uuid)  # Returns cached or None
provider.set_dsc(uuid, dsc_obj)
provider.get_dsc(uuid)
```

Supports both macOS and iOS logarchive structures:
- macOS: `archive/uuidtext/XX/YYYYYYYY...`
- iOS: `archive/XX/YYYYYYYY...` (hex directories at root)

#### LiveSystemProvider

Provider for reading from a live macOS system.

```python
from macos_unifiedlogs import LiveSystemProvider

provider = LiveSystemProvider()

# Reads from:
# - /var/db/diagnostics/ for tracev3 files
# - /var/db/uuidtext/ for UUIDText files
# - /System/Library/Caches/com.apple.dyld/ for DSC files
# - /var/db/diagnostics/timesync/ for timesync files
```

### Core Parsing Functions

#### parse_unified_log

Parse a complete tracev3 file.

```python
from macos_unifiedlogs import parse_unified_log

remaining, unified_data = parse_unified_log(data)

# unified_data.header - List[HeaderChunk]
# unified_data.catalog_data - List[UnifiedLogCatalogData]
# unified_data.oversize - List[Oversize]
```

#### build_log

Reconstruct human-readable log entries from parsed data.

```python
from macos_unifiedlogs import build_log

logs, missing = build_log(
    unified_data,      # Parsed UnifiedLogData
    provider,          # FileProvider with cached strings
    timesync_data,     # Dict[str, TimesyncBoot]
    exclude_missing=False  # If True, exclude entries with missing data
)

for log in logs:
    print(log.timestamp)      # ISO 8601 timestamp string
    print(log.time)           # Unix epoch nanoseconds (float)
    print(log.message)        # Formatted log message
    print(log.subsystem)      # Subsystem name
    print(log.category)       # Category name
    print(log.process)        # Process name
    print(log.pid)            # Process ID
    print(log.thread_id)      # Thread ID
    print(log.log_type)       # LogType enum
    print(log.event_type)     # EventType enum
```

### Data Structures

#### LogData

Reconstructed log entry with all metadata.

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | str | ISO 8601 formatted timestamp |
| `time` | float | Unix epoch in nanoseconds |
| `message` | str | Formatted log message |
| `raw_message` | str | Format string before substitution |
| `subsystem` | str | Logging subsystem |
| `category` | str | Logging category |
| `process` | str | Process name |
| `process_uuid` | str | Process UUID |
| `pid` | int | Process ID |
| `euid` | int | Effective user ID |
| `thread_id` | int | Thread ID |
| `library` | str | Library name |
| `library_uuid` | str | Library UUID |
| `activity_id` | int | Activity ID |
| `log_type` | LogType | Log severity/type |
| `event_type` | EventType | Event classification |
| `boot_uuid` | str | Boot session UUID |
| `timezone_name` | str | Timezone name |
| `message_entries` | List[FirehoseItemInfo] | Raw message components |

#### LogType Enum

```python
from macos_unifiedlogs import LogType

LogType.Debug
LogType.Info
LogType.Default
LogType.Error
LogType.Fault
LogType.Create
LogType.Useraction
LogType.ProcessSignpostEvent
LogType.ProcessSignpostStart
LogType.ProcessSignpostEnd
LogType.SystemSignpostEvent
LogType.SystemSignpostStart
LogType.SystemSignpostEnd
LogType.ThreadSignpostEvent
LogType.ThreadSignpostStart
LogType.ThreadSignpostEnd
LogType.Simpledump
LogType.Statedump
LogType.Loss
```

#### EventType Enum

```python
from macos_unifiedlogs import EventType

EventType.Unknown
EventType.Log
EventType.Activity
EventType.Trace
EventType.Signpost
EventType.Simpledump
EventType.Statedump
EventType.Loss
```

### Supporting File Parsers

#### TimesyncBoot

Parse timesync files for timestamp calculation.

```python
from macos_unifiedlogs import TimesyncBoot

# Parse timesync file
remaining, timesync_dict = TimesyncBoot.parse_timesync_data(data)
# Returns Dict[str, TimesyncBoot] mapping boot_uuid to boot record

# Calculate timestamp for a log entry
timestamp = TimesyncBoot.get_timestamp(
    timesync_data,        # Dict[str, TimesyncBoot]
    boot_uuid,            # Boot UUID from header
    continuous_time,      # Combined continuous time delta
    preamble_base_time,   # Base time from firehose preamble
)
```

#### UUIDText

Parse UUIDText files for format string lookups.

```python
from macos_unifiedlogs import UUIDText

remaining, uuidtext = UUIDText.parse_uuidtext(data)

# uuidtext.signature - File signature (0x66778899)
# uuidtext.number_entries - Number of string entries
# uuidtext.entry_descriptors - List of entry metadata
# uuidtext.footer_data - Raw footer with library paths
```

#### SharedCacheStrings (DSC)

Parse DSC shared cache string files.

```python
from macos_unifiedlogs import SharedCacheStrings

remaining, dsc = SharedCacheStrings.parse_dsc(data)

# dsc.signature - File signature (0x64736368 = "hcsd")
# dsc.major_version - 1 for Big Sur and earlier, 2 for Monterey+
# dsc.minor_version
# dsc.number_ranges - Number of range descriptors
# dsc.number_uuids - Number of UUID descriptors
# dsc.ranges - List[RangeDescriptor]
# dsc.uuids - List[UUIDDescriptor]
# dsc.dsc_uuid - DSC file UUID
```

### Chunk Parsers

#### HeaderChunk

```python
from macos_unifiedlogs import HeaderChunk

remaining, header = HeaderChunk.parse_header(data)

# header.chunk_tag - 0x1000
# header.boot_uuid - Boot session UUID
# header.logfile_path - Path to log file
# header.timezone_path - Timezone path
# header.continous_time - Continuous time value
```

#### CatalogChunk

```python
from macos_unifiedlogs import CatalogChunk

remaining, catalog = CatalogChunk.parse_catalog(data)

# Get process info
pid = catalog.get_pid(first_proc_id, second_proc_id)
euid = catalog.get_euid(first_proc_id, second_proc_id)

# Get subsystem info
remaining, subsystem = catalog.get_subsystem(
    subsystem_value, first_proc_id, second_proc_id
)
```

## File Format Reference

### TraceV3 File Structure

| Chunk Type | Tag | Description |
|------------|-----|-------------|
| Header | 0x1000 | File header with boot UUID and metadata |
| Catalog | 0x600b | Process and subsystem information |
| Chunkset | 0x600d | LZ4-compressed log data |

### Supporting Files

| Format | Signature | Location | Purpose |
|--------|-----------|----------|---------|
| UUIDText | 0x66778899 | `uuidtext/XX/` or `XX/` | Format string lookups |
| DSC | 0x64736368 | `dsc/` | Shared cache strings |
| Timesync | 0xbbb0 (boot) | `timesync/` | Timestamp calculation |

### Firehose Log Types

| Type | Code | Description |
|------|------|-------------|
| Activity | 0x2 | Activity start/end |
| Trace | 0x3 | Trace point |
| Non-Activity | 0x4 | Standard log message |
| Signpost | 0x6 | Performance signpost |
| Loss | 0x7 | Lost log indicator |

## Architecture

```
macos_unifiedlogs/
├── __init__.py              # Public API exports
├── parser.py                # High-level parsing functions
├── unified_log.py           # Core data structures and log assembly
├── iterator.py              # Chunk-by-chunk iteration
├── header.py                # Header chunk (0x1000)
├── catalog.py               # Catalog chunk (0x600b)
├── chunkset.py              # Chunkset chunk (0x600d) with LZ4
├── preamble.py              # Chunk preamble detection
├── timesync.py              # Timesync file parsing
├── uuidtext.py              # UUIDText file parsing
├── dsc.py                   # DSC shared cache parsing
├── message.py               # Printf-style message formatting
├── filesystem.py            # File providers
├── traits.py                # Abstract base classes
├── util.py                  # Helper functions
├── error.py                 # Custom exceptions
├── chunks/
│   ├── firehose/
│   │   ├── firehose_log.py  # Firehose preamble and entries
│   │   ├── activity.py      # Activity type (0x2)
│   │   ├── nonactivity.py   # Non-activity type (0x4)
│   │   ├── signpost.py      # Signpost type (0x6)
│   │   ├── trace.py         # Trace type (0x3)
│   │   ├── loss.py          # Loss type (0x7)
│   │   └── flags.py         # Flag constants
│   ├── oversize.py          # Oversize string entries
│   ├── simpledump.py        # Simpledump entries
│   └── statedump.py         # Statedump entries
└── decoders/
    ├── decoder.py           # Main dispatcher
    ├── bool_decoder.py      # Boolean formatting
    ├── darwin.py            # Darwin-specific (errno, permissions)
    ├── dns.py               # DNS record decoding
    ├── location.py          # Location/GPS data
    ├── network.py           # Network addresses
    ├── opendirectory.py     # Open Directory objects
    ├── time_decoder.py      # Time value formatting
    └── uuid_decoder.py      # UUID formatting
```

## Platform Support

### Tested Platforms

- macOS logarchives (Big Sur, Monterey, and later)
- iOS logarchives (sysdiagnose exports)

### Architecture Support

- Intel (x86_64): Timebase 1/1
- Apple Silicon (ARM): Timebase 125/3

The library automatically detects and applies the correct timebase adjustment for timestamp calculation.

## Exceptions

```python
from macos_unifiedlogs import (
    ParserError,           # Base parsing exception
    PathError,             # File path issues
    Tracev3ParseError,     # TraceV3 parsing failures
    InvalidSignatureError, # Invalid file signature
    DecoderError,          # Object decoding failures
    DecompressionError,    # LZ4 decompression failures
)
```

## Limitations

- DSC string lookups require loading potentially large files (100MB+)
- Some newer log format extensions may not be fully supported
- Protobuf statedump data is returned as base64-encoded bytes

## Testing

Run the test suite:

```bash
cd python
pip install pytest
python -m pytest tests/ -v
```

## API Compatibility

This Python library maintains API compatibility with the Rust library:

| Rust | Python |
|------|--------|
| `LogarchiveProvider::new(path)` | `LogarchiveProvider(path)` |
| `parse_log(reader)` | `parse_unified_log(data)` |
| `build_log(&data, &provider, &timesync, exclude)` | `build_log(data, provider, timesync, exclude)` |

## License

Apache License 2.0

## Credits

This Python implementation is based on the [macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs) Rust library by Mandiant.

## See Also

- [Apple Unified Logging Documentation](https://developer.apple.com/documentation/os/logging)
- [Original Rust Implementation](https://github.com/mandiant/macos-UnifiedLogs)
