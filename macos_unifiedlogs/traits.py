# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Abstract base classes for file providers."""

from abc import ABC, abstractmethod
from typing import BinaryIO, Iterator, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .uuidtext import UUIDText
    from .dsc import SharedCacheStrings


class SourceFile(ABC):
    """Defines an interface for providing a single unified log file.

    Parsing unified logs requires the name of the original file in order to
    reconstruct format strings.
    """

    @abstractmethod
    def reader(self) -> BinaryIO:
        """A reader for the given source file."""
        pass

    @abstractmethod
    def source_path(self) -> str:
        """The source path of the file on the machine from which it was collected.

        This is distinct from any secondary storage location where, for instance,
        a file backing the reader might exist.
        """
        pass


class FileProvider(ABC):
    """Implementing this class allows library consumers to provide the files required
    by the parser in arbitrary formats.

    For help mapping files to the correct filetype, see the LogFileType enum.
    """

    @abstractmethod
    def tracev3_files(self) -> Iterator[SourceFile]:
        """Provides an iterator of .tracev3 files from the
        /private/var/db/diagnostics/(HighVolume|Signpost|Trace|Special)/, plus the
        livedata.LogData.tracev3 file if it was collected via `log collect`.
        """
        pass

    @abstractmethod
    def uuidtext_files(self) -> Iterator[SourceFile]:
        """Provides an iterator of UUIDText string files from the /var/db/uuidtext/XX/
        directories, where XX is any two uppercase hex characters.

        The filename should be a 30-character name containing only hex digits.
        It is important that this is accurate, or else strings will not be able
        to be referenced from the source file.
        """
        pass

    @abstractmethod
    def read_uuidtext(self, uuid: str) -> 'UUIDText':
        """Reads a provided UUID file at runtime.

        The UUID is obtained by parsing the tracev3 files. Reads will fail if
        the UUID does not exist. This avoids having to read all UUIDText files
        into memory.
        """
        pass

    @abstractmethod
    def cached_uuidtext(self, uuid: str) -> Optional['UUIDText']:
        """Check our cached UUIDText data for strings."""
        pass

    @abstractmethod
    def update_uuid(self, uuid: str, uuid2: str) -> None:
        """Update our cached UUIDText data."""
        pass

    @abstractmethod
    def dsc_files(self) -> Iterator[SourceFile]:
        """Provides an iterator of shared string files from the /var/db/uuidtext/dsc
        subdirectory.

        The filename should be a 30-character name containing only hex digits.
        It is important that this is accurate, or else strings will not be able
        to be referenced from the source file.
        """
        pass

    @abstractmethod
    def read_dsc_uuid(self, uuid: str) -> 'SharedCacheStrings':
        """Reads a provided DSC UUID file at runtime.

        The UUID is obtained by parsing the tracev3 files. Reads will fail if
        the UUID does not exist. This avoids having to read all SharedCacheStrings
        files into memory.
        """
        pass

    @abstractmethod
    def cached_dsc(self, uuid: str) -> Optional['SharedCacheStrings']:
        """Check our cached SharedCacheStrings for strings."""
        pass

    @abstractmethod
    def update_dsc(self, uuid: str, uuid2: str) -> None:
        """Update our cached SharedCacheStrings data."""
        pass

    @abstractmethod
    def timesync_files(self) -> Iterator[SourceFile]:
        """Provides an iterator of .timesync files from the
        /var/db/diagnostics/timesync subdirectory.
        """
        pass
