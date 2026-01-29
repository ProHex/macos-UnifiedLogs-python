# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Custom exceptions for the macos-unifiedlogs library."""


class ParserError(Exception):
    """Base exception for parser errors."""
    pass


class PathError(ParserError):
    """Failed to open file path."""
    def __init__(self, message: str = "Failed to open file path"):
        super().__init__(message)


class DirError(ParserError):
    """Failed to open directory path."""
    def __init__(self, message: str = "Failed to open directory path"):
        super().__init__(message)


class Tracev3ParseError(ParserError):
    """Failed to parse tracev3 file."""
    def __init__(self, message: str = "Failed to parse tracev3 file"):
        super().__init__(message)


class ReadError(ParserError):
    """Failed to read file."""
    def __init__(self, message: str = "Failed to read file"):
        super().__init__(message)


class TimesyncError(ParserError):
    """Failed to parse timesync file."""
    def __init__(self, message: str = "Failed to parse timesync file"):
        super().__init__(message)


class DscError(ParserError):
    """Failed to parse dsc file."""
    def __init__(self, message: str = "Failed to parse dsc file"):
        super().__init__(message)


class UUIDTextError(ParserError):
    """Failed to parse UUIDtext file."""
    def __init__(self, message: str = "Failed to parse UUIDtext file"):
        super().__init__(message)


class InvalidSignatureError(ParserError):
    """Wrong file signature."""
    def __init__(self, expected: int, got: int, file_type: str = "file"):
        self.expected = expected
        self.got = got
        super().__init__(f"Incorrect {file_type} signature. Expected {expected:#x}. Got: {got:#x}")


class DecoderError(ParserError):
    """Object decoding failed."""
    def __init__(self, message: str = "Failed to decode object"):
        super().__init__(message)


class DecompressionError(ParserError):
    """Failed to decompress data."""
    def __init__(self, message: str = "Failed to decompress data"):
        super().__init__(message)
