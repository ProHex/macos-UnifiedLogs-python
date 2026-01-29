# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""File system providers for accessing Unified Log files."""

import logging
import os
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Dict, Iterator, List, Optional

from .dsc import SharedCacheStrings
from .traits import FileProvider, SourceFile
from .uuidtext import UUIDText

logger = logging.getLogger(__name__)


class FileSourceFile(SourceFile):
    """SourceFile implementation for regular filesystem files."""

    def __init__(self, path: str):
        """Initialize with a file path.

        Args:
            path: Path to the file
        """
        self._path = path

    def reader(self) -> BinaryIO:
        """Get a binary reader for this file.

        Returns:
            BinaryIO reader for the file
        """
        return open(self._path, 'rb')

    def source_path(self) -> str:
        """Get the source path of this file.

        Returns:
            File path string
        """
        return self._path


class LogarchiveProvider(FileProvider):
    """File provider for .logarchive bundles.

    Logarchive bundles are created by the `log collect` command on macOS.
    They contain all the necessary files to parse Unified Logs:
    - tracev3 files
    - UUIDText files
    - DSC files
    - Timesync files
    """

    def __init__(self, archive_path: str):
        """Initialize with a logarchive path.

        Args:
            archive_path: Path to the .logarchive directory
        """
        self._archive_path = Path(archive_path)
        self._uuidtext_cache: Dict[str, UUIDText] = {}
        self._dsc_cache: Dict[str, SharedCacheStrings] = {}

    def tracev3_files(self) -> Iterator[SourceFile]:
        """Get all tracev3 files in the archive.

        Yields:
            SourceFile for each tracev3 file
        """
        # Look in the Persist, HighVolume, Special, and Signpost directories
        persist_dir = self._archive_path / "Persist"
        highvolume_dir = self._archive_path / "HighVolume"
        special_dir = self._archive_path / "Special"
        signpost_dir = self._archive_path / "Signpost"

        tracev3_files = []

        for search_dir in [persist_dir, highvolume_dir, special_dir, signpost_dir]:
            if search_dir.exists():
                for tracev3_file in search_dir.glob("*.tracev3"):
                    if not tracev3_file.name.startswith('._'):
                        tracev3_files.append(str(tracev3_file))

        # Also check for tracev3 files at archive root (iOS logdata.LiveData.tracev3)
        for tracev3_file in self._archive_path.glob("*.tracev3"):
            if not tracev3_file.name.startswith('._'):
                tracev3_files.append(str(tracev3_file))

        # Sort by filename to ensure consistent ordering
        tracev3_files.sort()

        for tracev3_file in tracev3_files:
            yield FileSourceFile(tracev3_file)

    def uuidtext_files(self) -> Iterator[SourceFile]:
        """Get all UUIDText files in the archive.

        Supports both macOS and iOS logarchive structures:
        - macOS: archive/uuidtext/XX/YYYYYYYY...
        - iOS: archive/XX/YYYYYYYY... (hex directories at root)

        Yields:
            SourceFile for each UUIDText file
        """
        # Try macOS style first: uuidtext subdirectory
        uuidtext_dir = self._archive_path / "uuidtext"
        if uuidtext_dir.exists():
            for subdir in uuidtext_dir.iterdir():
                if subdir.is_dir():
                    for uuidtext_file in subdir.iterdir():
                        if uuidtext_file.is_file() and not uuidtext_file.name.startswith('._'):
                            yield FileSourceFile(str(uuidtext_file))
            return

        # iOS style: hex directories (00-FF) directly at archive root
        hex_chars = set('0123456789ABCDEFabcdef')
        for subdir in self._archive_path.iterdir():
            # Check if directory name is a 2-char hex value
            if (subdir.is_dir() and
                len(subdir.name) == 2 and
                all(c in hex_chars for c in subdir.name)):
                for uuidtext_file in subdir.iterdir():
                    if uuidtext_file.is_file() and not uuidtext_file.name.startswith('._'):
                        yield FileSourceFile(str(uuidtext_file))

    def dsc_files(self) -> Iterator[SourceFile]:
        """Get all DSC (shared cache) files in the archive.

        Yields:
            SourceFile for each DSC file
        """
        dsc_dir = self._archive_path / "dsc"
        if not dsc_dir.exists():
            return

        for dsc_file in dsc_dir.iterdir():
            if dsc_file.is_file() and not dsc_file.name.startswith('._'):
                yield FileSourceFile(str(dsc_file))

    def timesync_files(self) -> Iterator[SourceFile]:
        """Get all timesync files in the archive.

        Yields:
            SourceFile for each timesync file
        """
        timesync_dir = self._archive_path / "timesync"
        if not timesync_dir.exists():
            return

        for timesync_file in timesync_dir.glob("*.timesync"):
            if not timesync_file.name.startswith('._'):
                yield FileSourceFile(str(timesync_file))

    def get_uuidtext(self, uuid: str) -> Optional[UUIDText]:
        """Get cached UUIDText data for a UUID."""
        return self._uuidtext_cache.get(uuid)

    def set_uuidtext(self, uuid: str, uuidtext: UUIDText) -> None:
        """Cache UUIDText data for a UUID."""
        self._uuidtext_cache[uuid] = uuidtext

    def get_dsc(self, uuid: str) -> Optional[SharedCacheStrings]:
        """Get cached DSC data for a UUID."""
        return self._dsc_cache.get(uuid)

    def set_dsc(self, uuid: str, dsc: SharedCacheStrings) -> None:
        """Cache DSC data for a UUID."""
        self._dsc_cache[uuid] = dsc

    def read_uuidtext(self, uuid: str) -> UUIDText:
        """Reads a provided UUID file at runtime.

        Supports both macOS and iOS logarchive structures:
        - macOS: archive/uuidtext/XX/YYYYYYYY...
        - iOS: archive/XX/YYYYYYYY...
        """
        cached = self._uuidtext_cache.get(uuid)
        if cached is not None:
            return cached

        prefix = uuid[:2]
        suffix = uuid[2:]

        # Try macOS style first
        uuidtext_path = self._archive_path / "uuidtext" / prefix / suffix
        if not uuidtext_path.exists():
            # Try iOS style (hex directories at root)
            uuidtext_path = self._archive_path / prefix / suffix

        if uuidtext_path.exists():
            with open(uuidtext_path, 'rb') as f:
                data = f.read()
                _, uuidtext = UUIDText.parse_uuidtext(data)
                self._uuidtext_cache[uuid] = uuidtext
                return uuidtext

        raise FileNotFoundError(f"UUIDText file not found for UUID: {uuid}")

    def cached_uuidtext(self, uuid: str) -> Optional[UUIDText]:
        """Check our cached UUIDText data for strings."""
        return self._uuidtext_cache.get(uuid)

    def update_uuid(self, uuid: str, uuid2: str) -> None:
        """Update our cached UUIDText data."""
        if uuid in self._uuidtext_cache:
            self._uuidtext_cache[uuid2] = self._uuidtext_cache[uuid]

    def read_dsc_uuid(self, uuid: str) -> SharedCacheStrings:
        """Reads a provided DSC UUID file at runtime."""
        cached = self._dsc_cache.get(uuid)
        if cached is not None:
            return cached
        raise FileNotFoundError(f"DSC file not found for UUID: {uuid}")

    def cached_dsc(self, uuid: str) -> Optional[SharedCacheStrings]:
        """Check our cached SharedCacheStrings for strings."""
        return self._dsc_cache.get(uuid)

    def update_dsc(self, uuid: str, uuid2: str) -> None:
        """Update our cached SharedCacheStrings data."""
        if uuid in self._dsc_cache:
            self._dsc_cache[uuid2] = self._dsc_cache[uuid]


class LiveSystemProvider(FileProvider):
    """File provider for reading from a live macOS system.

    This reads from the standard system locations:
    - /var/db/diagnostics/ for tracev3 files
    - /var/db/uuidtext/ for UUIDText files
    - /System/Library/Caches/com.apple.dyld/ for DSC files
    """

    def __init__(self):
        """Initialize the live system provider."""
        self._uuidtext_cache: Dict[str, UUIDText] = {}
        self._dsc_cache: Dict[str, SharedCacheStrings] = {}

    def tracev3_files(self) -> Iterator[SourceFile]:
        """Get all tracev3 files from the live system."""
        base_paths = [
            "/var/db/diagnostics/Persist",
            "/var/db/diagnostics/HighVolume",
            "/var/db/diagnostics/Special",
            "/var/db/diagnostics/Signpost",
        ]

        tracev3_files = []

        for base_path in base_paths:
            path = Path(base_path)
            if path.exists():
                for tracev3_file in path.glob("*.tracev3"):
                    tracev3_files.append(str(tracev3_file))

        tracev3_files.sort()

        for tracev3_file in tracev3_files:
            yield FileSourceFile(tracev3_file)

    def uuidtext_files(self) -> Iterator[SourceFile]:
        """Get all UUIDText files from the live system."""
        uuidtext_dir = Path("/var/db/uuidtext")
        if not uuidtext_dir.exists():
            return

        for subdir in uuidtext_dir.iterdir():
            if subdir.is_dir():
                for uuidtext_file in subdir.iterdir():
                    if uuidtext_file.is_file():
                        yield FileSourceFile(str(uuidtext_file))

    def dsc_files(self) -> Iterator[SourceFile]:
        """Get all DSC files from the live system."""
        dsc_dir = Path("/System/Library/Caches/com.apple.dyld")
        if not dsc_dir.exists():
            return

        for dsc_file in dsc_dir.iterdir():
            if dsc_file.is_file() and dsc_file.name.startswith("dyld_shared_cache"):
                yield FileSourceFile(str(dsc_file))

    def timesync_files(self) -> Iterator[SourceFile]:
        """Get all timesync files from the live system."""
        timesync_dir = Path("/var/db/diagnostics/timesync")
        if not timesync_dir.exists():
            return

        for timesync_file in timesync_dir.glob("*.timesync"):
            yield FileSourceFile(str(timesync_file))

    def get_uuidtext(self, uuid: str) -> Optional[UUIDText]:
        """Get cached UUIDText data for a UUID."""
        return self._uuidtext_cache.get(uuid)

    def set_uuidtext(self, uuid: str, uuidtext: UUIDText) -> None:
        """Cache UUIDText data for a UUID."""
        self._uuidtext_cache[uuid] = uuidtext

    def get_dsc(self, uuid: str) -> Optional[SharedCacheStrings]:
        """Get cached DSC data for a UUID."""
        return self._dsc_cache.get(uuid)

    def set_dsc(self, uuid: str, dsc: SharedCacheStrings) -> None:
        """Cache DSC data for a UUID."""
        self._dsc_cache[uuid] = dsc

    def read_uuidtext(self, uuid: str) -> UUIDText:
        """Reads a provided UUID file at runtime."""
        cached = self._uuidtext_cache.get(uuid)
        if cached is not None:
            return cached

        prefix = uuid[:2]
        suffix = uuid[2:]
        uuidtext_path = Path("/var/db/uuidtext") / prefix / suffix

        if uuidtext_path.exists():
            with open(uuidtext_path, 'rb') as f:
                data = f.read()
                _, uuidtext = UUIDText.parse_uuidtext(data)
                self._uuidtext_cache[uuid] = uuidtext
                return uuidtext

        raise FileNotFoundError(f"UUIDText file not found for UUID: {uuid}")

    def cached_uuidtext(self, uuid: str) -> Optional[UUIDText]:
        """Check our cached UUIDText data for strings."""
        return self._uuidtext_cache.get(uuid)

    def update_uuid(self, uuid: str, uuid2: str) -> None:
        """Update our cached UUIDText data."""
        if uuid in self._uuidtext_cache:
            self._uuidtext_cache[uuid2] = self._uuidtext_cache[uuid]

    def read_dsc_uuid(self, uuid: str) -> SharedCacheStrings:
        """Reads a provided DSC UUID file at runtime."""
        cached = self._dsc_cache.get(uuid)
        if cached is not None:
            return cached
        raise FileNotFoundError(f"DSC file not found for UUID: {uuid}")

    def cached_dsc(self, uuid: str) -> Optional[SharedCacheStrings]:
        """Check our cached SharedCacheStrings for strings."""
        return self._dsc_cache.get(uuid)

    def update_dsc(self, uuid: str, uuid2: str) -> None:
        """Update our cached SharedCacheStrings data."""
        if uuid in self._dsc_cache:
            self._dsc_cache[uuid2] = self._dsc_cache[uuid]
