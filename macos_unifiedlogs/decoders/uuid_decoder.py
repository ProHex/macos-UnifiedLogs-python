# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""UUID decoder for Unified Log format strings."""

import base64

from ..error import DecoderError


def parse_uuid(input_str: str) -> str:
    """Get UUID string from log object.

    Args:
        input_str: Base64 encoded UUID data

    Returns:
        UUID as uppercase hex string

    Raises:
        DecoderError: If UUID cannot be decoded
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode uuid data: {input_str}") from e

    # Format as uppercase hex string without separators
    uuid_string = decoded_data.hex().upper()
    return uuid_string
