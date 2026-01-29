# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Boolean value decoders for Unified Log format strings."""


def uppercase_bool(bool_data: str) -> str:
    """Return BOOL value to string (YES/NO).

    Args:
        bool_data: String representation of boolean ("0" or other)

    Returns:
        "NO" if bool_data is "0", otherwise "YES"
    """
    if bool_data == "0":
        return "NO"
    return "YES"


def lowercase_bool(bool_data: str) -> str:
    """Return bool value to string (true/false).

    Args:
        bool_data: String representation of boolean ("0" or other)

    Returns:
        "false" if bool_data is "0", otherwise "true"
    """
    if bool_data == "0":
        return "false"
    return "true"


def lowercase_int_bool(bool_data: int) -> str:
    """Return int value to bool string (true/false).

    Args:
        bool_data: Integer boolean value

    Returns:
        "false" if bool_data is 0, otherwise "true"
    """
    if bool_data == 0:
        return "false"
    return "true"
