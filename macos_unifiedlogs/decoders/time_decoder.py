# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Time value decoder for Unified Log format strings."""

from datetime import datetime, timezone

from ..error import DecoderError


def parse_time(input_str: str) -> str:
    """Parse time data object.

    Args:
        input_str: Unix timestamp as string

    Returns:
        ISO 8601 formatted timestamp string

    Raises:
        DecoderError: If timestamp cannot be parsed
    """
    try:
        timestamp = int(input_str)
    except ValueError as e:
        raise DecoderError(f"Failed to parse timestamp: {input_str}") from e

    try:
        # Format to UTC, the log command will format to whatever the local time is for the system
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (OSError, OverflowError, ValueError) as e:
        raise DecoderError(f"Could not parse time: {input_str}") from e
