# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Format Unified Log message entries based on parsed log items using printf-style formatting."""

import logging
import re
import struct
from dataclasses import dataclass
from typing import List, Optional, Pattern, Tuple

from .chunks.firehose.firehose_log import FirehoseItemInfo

logger = logging.getLogger(__name__)

# Printf format type constants
FLOAT_TYPES = ["f", "F", "e", "E", "g", "G"]
INT_TYPES = ["d", "D", "i", "u"]
HEX_TYPES = ["x", "X", "a", "A", "p"]
OCTAL_TYPES = ["o", "O"]
ERROR_TYPES = ["m"]
STRING_TYPES = ["c", "s", "@", "S", "C", "P"]

# Compiled regex for printf-style formatters
# This pattern matches C printf format specifiers including Apple extensions
MESSAGE_RE = re.compile(
    r"(%(?:(?:\{[^}]+}?)(?:[-+0#]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l|ll|w|I|z|t|q|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%}]|(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l||q|t|ll|w|I|z|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%]))"
)


@dataclass
class FormatAndMessage:
    """Holds a printf formatter and its corresponding message value."""
    formatter: str = ""
    message: str = ""


def format_firehose_log_message(
    format_string: str,
    item_message: List[FirehoseItemInfo],
    message_re: Optional[Pattern] = None,
) -> str:
    """Format the Unified Log message entry based on the parsed log items.

    Formatting follows the C lang printf formatting process.

    Args:
        format_string: The format string containing printf-style specifiers
        item_message: List of FirehoseItemInfo containing message values
        message_re: Optional compiled regex pattern (uses default if None)

    Returns:
        Formatted log message string
    """
    # Import here to avoid circular imports
    from .decoders.decoder import check_objects

    if message_re is None:
        message_re = MESSAGE_RE

    log_message = format_string
    format_and_message_vec: List[FormatAndMessage] = []
    logger.info(f"Unified log base message: {log_message!r}")
    logger.info(f"Unified log entry strings: {item_message!r}")

    # Some log entries may be completely empty (no format string or message data)
    if not log_message and not item_message:
        return ""
    if not log_message:
        return item_message[0].message_strings

    results = message_re.finditer(log_message)

    item_index = 0
    for match in results:
        formatter_str = match.group(0)

        # Skip literal "% " values
        if formatter_str.startswith("% "):
            continue

        format_and_message = FormatAndMessage()

        # %% is literal %
        if formatter_str == "%%":
            format_and_message.formatter = formatter_str
            format_and_message.message = "%"
            format_and_message_vec.append(format_and_message)
            continue

        # Sometimes the log message does not have all of the message strings
        # Apple labels them: "<decode: missing data>"
        if item_index >= len(item_message):
            format_and_message.formatter = formatter_str
            format_and_message.message = "<Missing message data>"
            format_and_message_vec.append(format_and_message)
            continue

        formatted_log_message = item_message[item_index].message_strings

        # If the formatter does not have a type then the entry is the literal format
        # Ex: RDAlarmNotificationConsumer {identifier: %{public}%@ currentSet: %@, count: %{public}%d}
        #  -> RDAlarmNotificationConsumer {identifier: {public}<private> allowedSet: <private>, count {public}0}
        if formatter_str.startswith("%{") and formatter_str.endswith("}"):
            format_and_message.formatter = formatter_str
            format_and_message.message = formatter_str[1:]  # Remove leading %
            format_and_message_vec.append(format_and_message)
            continue

        PRECISION_ITEMS = [0x10, 0x12]  # dynamic precision item types
        # If the item message was a precision type increment to actual value
        if item_message[item_index].item_type in PRECISION_ITEMS:
            item_index += 1

        # Also seen number type value 0 also used for dynamic width/precision value
        DYNAMIC_PRECISION_VALUE = 0x0
        if (item_message[item_index].item_type == DYNAMIC_PRECISION_VALUE
                and item_message[item_index].item_size == 0
                and "%*" in formatter_str):
            item_index += 1

        if item_index >= len(item_message):
            format_and_message.formatter = formatter_str
            format_and_message.message = "<Missing message data>"
            format_and_message_vec.append(format_and_message)
            continue

        private_strings = [0x1, 0x21, 0x31, 0x41]
        private_number = 0x1
        private_message = 0x8000

        if formatter_str.startswith("%{"):
            # If item type is [0x1, 0x21, 0x31, 0x41] and the value is zero. It appears to be a private string
            if ((item_message[item_index].item_type in private_strings
                    and not item_message[item_index].message_strings
                    and item_message[item_index].item_size == 0)
                    or (item_message[item_index].item_type == private_number
                        and item_message[item_index].item_size == private_message)):
                formatted_log_message = "<private>"
            else:
                try:
                    formatted_log_message = parse_type_formatter(
                        formatter_str,
                        item_message,
                        item_message[item_index].item_type,
                        item_index,
                    )
                except Exception as err:
                    logger.warning(f"Failed to format message type ex: public/private: {err!r}")
        else:
            # If item type is [0x1, 0x21, 0x31, 0x41] and the size is zero (or 0x8000 for 0x1). It appears to be a literal <private> string
            if ((item_message[item_index].item_type in private_strings
                    and not item_message[item_index].message_strings
                    and item_message[item_index].item_size == 0)
                    or (item_message[item_index].item_type == private_number
                        and item_message[item_index].item_size == private_message)):
                formatted_log_message = "<private>"
            else:
                try:
                    formatted_log_message = parse_formatter(
                        formatter_str,
                        item_message,
                        item_message[item_index].item_type,
                        item_index,
                    )
                except Exception as err:
                    logger.warning(f"[macos-unifiedlogs] Failed to format message: {err!r}")

        item_index += 1
        format_and_message.formatter = formatter_str
        format_and_message.message = formatted_log_message
        format_and_message_vec.append(format_and_message)

    # Build final message by replacing formatters with values
    log_message_vec: List[str] = []
    for values in format_and_message_vec:
        # Split the values by printf formatter
        # We have to do this instead of using replace because our replacement string may also contain a printf formatter
        parts = log_message.split(values.formatter, 1)
        if len(parts) == 2:
            log_message_vec.append(parts[0])
            log_message_vec.append(values.message)
            log_message = parts[1]
        else:
            logger.error(
                f"Failed to split log message ({log_message}) by printf formatter: {values.formatter}"
            )

    log_message_vec.append(log_message)
    return "".join(log_message_vec)


def parse_formatter(
    formatter: str,
    message_value: List[FirehoseItemInfo],
    item_type: int,
    item_index: int,
) -> str:
    """Parse format specification and format the message value.

    Format strings are based on C printf formats.

    Args:
        formatter: Printf format specification string
        message_value: List of FirehoseItemInfo
        item_type: Type of the item
        item_index: Index into message_value

    Returns:
        Formatted message string
    """
    index = item_index

    PRECISION_ITEMS = [0x10, 0x12]
    precision_value = 0
    if item_type in PRECISION_ITEMS:
        precision_value = message_value[index].item_size
        index += 1

        if index >= len(message_value):
            logger.error(
                f"[macos-unifiedlogs] Index now greater than messages array. This should not have happened. "
                f"Index: {index}. Message Array len: {len(message_value)}"
            )
            return "Failed to format string due index length"

    message = message_value[index].message_strings

    number_item_types = [0x0, 0x1, 0x2]

    # If the message formatter expects a string/character and the message string is a number type
    # Try to convert to a character/string
    if formatter.lower().endswith('c') and message_value[index].item_type in number_item_types:
        try:
            char_value = int(message)
            message = chr(char_value & 0xFF)
        except (ValueError, OverflowError) as err:
            logger.error(f"[macos-unifiedlogs] Failed to parse number item to char string: {err!r}")
            return "Failed to parse number item to char string"

    # Parse format flags
    left_justify = False
    hashtag = False
    pad_zero = False
    plus_minus = False
    width_index = 1

    for i, char in enumerate(formatter):
        if i == 0:
            continue

        if char == '-':
            left_justify = True
        elif char == '+':
            plus_minus = True
        elif char == '#':
            hashtag = True
        elif char == '0':
            pad_zero = True
        else:
            width_index = i
            break

    formatter_message = formatter[width_index:]

    # Extract width
    width_match = re.match(r'^(\d*)', formatter_message)
    width = width_match.group(1) if width_match else ""
    formatter_message = formatter_message[len(width):]

    if formatter_message.startswith('*'):
        # Dynamic width/precision
        DYNAMIC_PRECISION_VALUE = 0x0
        if item_type == DYNAMIC_PRECISION_VALUE and message_value[index].item_size == 0:
            precision_value = message_value[index].item_size
            index += 1
            if index >= len(message_value):
                logger.error(
                    f"[macos-unifiedlogs] Index now greater than messages array. "
                    f"Index: {index}. Message Array len: {len(message_value)}"
                )
                return "Failed to format precision/dynamic string due index length"
            message = message_value[index].message_strings

        width = str(precision_value)
        formatter_message = formatter_message[1:]  # Skip '*'

    # Parse precision
    if formatter_message.startswith('.'):
        formatter_message = formatter_message[1:]  # Skip '.'
        precision_match = re.match(r'^([^hljzZtqLdDiuUoOcCxXfFeEgGaASspPn%@]*)', formatter_message)
        precision_data = precision_match.group(1) if precision_match else ""
        formatter_message = formatter_message[len(precision_data):]

        if precision_data != "*":
            try:
                precision_value = int(precision_data) if precision_data else 0
            except ValueError as err:
                logger.error(f"[macos-unifiedlogs] Failed to parse format precision value: {err!r}")
        elif precision_value != 0:
            # For dynamic length use the length of the message string
            precision_value = len(message_value)

    # Get length and type data
    length_values = ["h", "hh", "l", "ll", "w", "I", "z", "t", "q"]
    type_chars = "cmCdiouxXeEfgGaAnpsSZP@"

    # Check for length specifier
    length_match = re.match(r'^(hh|ll|[hlwIztq])?', formatter_message)
    length_data = length_match.group(1) if length_match and length_match.group(1) else ""
    if length_data:
        formatter_message = formatter_message[len(length_data):]

    # Get type specifier
    type_data = ""
    if formatter_message:
        type_match = re.match(r'^([cmCdiouxXeEfgGaAnpsSZP@])', formatter_message)
        if type_match:
            type_data = type_match.group(1)

    # Error types map error code to error message string
    if type_data in ERROR_TYPES:
        return f"Error code: {message}"

    width_value = 0
    if width:
        try:
            width_value = int(width)
        except ValueError as err:
            logger.error(f"[macos-unifiedlogs] Failed to parse format width value: {err!r}")

    if width_value > 0:
        if pad_zero:
            if left_justify:
                message = format_alignment_left(
                    message, width_value, precision_value, type_data, plus_minus, hashtag
                )
            else:
                message = format_alignment_right(
                    message, width_value, precision_value, type_data, plus_minus, hashtag
                )
        else:
            if left_justify:
                message = format_alignment_left_space(
                    message, width_value, precision_value, type_data, plus_minus, hashtag
                )
            else:
                message = format_alignment_right_space(
                    message, width_value, precision_value, type_data, plus_minus, hashtag
                )
    elif left_justify:
        message = format_left(message, precision_value, type_data, plus_minus, hashtag)
    else:
        message = format_right(message, precision_value, type_data, plus_minus, hashtag)

    return message


def parse_type_formatter(
    formatter: str,
    message_value: List[FirehoseItemInfo],
    item_type: int,
    item_index: int,
) -> str:
    """Parse formatters containing types like %{errno}d, %{public}s, %{private}s.

    Args:
        formatter: Printf format specification with type info
        message_value: List of FirehoseItemInfo
        item_type: Type of the item
        item_index: Index into message_value

    Returns:
        Formatted message string
    """
    # Import here to avoid circular imports
    from .decoders.decoder import check_objects

    # Extract format type (everything before the closing brace)
    brace_idx = formatter.find("}")
    if brace_idx == -1:
        return message_value[item_index].message_strings

    format_type = formatter[:brace_idx]
    remaining_format = formatter[brace_idx:]

    # Check for Apple custom objects
    apple_object = check_objects(format_type, message_value, item_type, item_index)

    # If we successfully decoded an apple object, then there is nothing to format
    if apple_object:
        return apple_object

    # Parse remaining format
    message = parse_formatter(remaining_format, message_value, item_type, item_index)

    if "signpost" in format_type:
        signpost_message = parse_signpost_format(format_type)
        message = f"{message} ({signpost_message})"

    return message


def parse_signpost_format(signpost_format: str) -> str:
    """Parse additional signpost metadata.

    Ex: %{public,signpost.description:attribute}@
        %{public,signpost.telemetry:number1,name=SOSSignpostNameSOSCCCopyApplicantPeerInfo}d

    Args:
        signpost_format: Signpost format string

    Returns:
        Parsed signpost message
    """
    # Remove leading %{
    signpost_value = signpost_format
    if signpost_value.startswith("%{"):
        signpost_value = signpost_value[2:]

    if signpost_format.startswith("%{sign"):
        signpost_vec = signpost_value.split(',')
        return signpost_vec[0] if signpost_vec else ""
    else:
        signpost_vec = signpost_value.split(',')
        if len(signpost_vec) > 1:
            return signpost_vec[1].strip()
        return ""


def parse_float(message: str) -> float:
    """Parse the float string log message to float value.

    Args:
        message: String representation of float bits

    Returns:
        Float value
    """
    try:
        bytes_val = int(message)
        # Convert i64 bits to f64
        return struct.unpack('d', struct.pack('Q', bytes_val & 0xFFFFFFFFFFFFFFFF))[0]
    except (ValueError, struct.error) as err:
        logger.warning(
            f"[macos-unifiedlogs] Failed to parse float log message value: {message}, err: {err!r}. "
            "Log message possibly incorrectly formatted ex: printf(%u, \"message\") instead of printf(%u, 10). "
            "Apple may record message as '<decode: mismatch for [%u] got [STRING sz:10]>'"
        )
    return 0.0


def parse_int(message: str) -> int:
    """Parse the int string log message to int value.

    Args:
        message: String representation of integer

    Returns:
        Integer value
    """
    try:
        return int(message)
    except ValueError as err:
        logger.warning(
            f"[macos-unifiedlogs] Failed to parse int log message value: {message}, err: {err!r}. "
            "Log message possibly incorrectly formatted ex: printf(%u, \"message\") instead of printf(%u, 10). "
            "Apple may record message as '<decode: mismatch for [%u] got [STRING sz:10]>'"
        )
    return 0


def format_alignment_left(
    format_message: str,
    format_width: int,
    format_precision: int,
    type_data: str,
    plus_minus: bool,
    hashtag: bool,
) -> str:
    """Align the message to the left and pad using zeros instead of spaces."""
    message = format_message
    precision_value = format_precision
    plus_option = "+" if plus_minus else ""
    adjust_width = 1 if plus_minus else 0

    if type_data in FLOAT_TYPES:
        float_message = parse_float(message)
        if precision_value == 0:
            float_parts = str(float_message).split('.')
            if len(float_parts) == 2:
                precision_value = len(float_parts[1])
        message = f"{plus_option}{float_message:<0{format_width - adjust_width}.{precision_value}f}"
    elif type_data in INT_TYPES:
        int_message = parse_int(message)
        message = f"{plus_option}{int_message:<0{format_width - adjust_width}d}"
    elif type_data in STRING_TYPES:
        if precision_value == 0:
            precision_value = len(message)
        message = f"{plus_option}{message[:precision_value]:<0{format_width - adjust_width}}"
    elif type_data in HEX_TYPES:
        hex_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{hex_message:<#0{format_width - adjust_width}X}"
        else:
            message = f"{plus_option}{hex_message:<0{format_width - adjust_width}X}"
    elif type_data in OCTAL_TYPES:
        octal_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{octal_message:<#0{format_width - adjust_width}o}"
        else:
            message = f"{plus_option}{octal_message:<0{format_width - adjust_width}o}"

    return message


def format_alignment_right(
    format_message: str,
    format_width: int,
    format_precision: int,
    type_data: str,
    plus_minus: bool,
    hashtag: bool,
) -> str:
    """Align the message to the right and pad using zeros instead of spaces."""
    message = format_message
    precision_value = format_precision
    plus_option = "+" if plus_minus else ""
    adjust_width = 1 if plus_minus else 0

    if type_data in FLOAT_TYPES:
        float_message = parse_float(message)
        if precision_value == 0:
            float_parts = str(float_message).split('.')
            if len(float_parts) == 2:
                precision_value = len(float_parts[1])
        message = f"{plus_option}{float_message:>0{format_width - adjust_width}.{precision_value}f}"
    elif type_data in INT_TYPES:
        int_message = parse_int(message)
        message = f"{plus_option}{int_message:>0{format_width - adjust_width}d}"
    elif type_data in STRING_TYPES:
        if precision_value == 0:
            precision_value = len(message)
        message = f"{plus_option}{message[:precision_value]:>0{format_width - adjust_width}}"
    elif type_data in HEX_TYPES:
        hex_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{hex_message:>#0{format_width - adjust_width}X}"
        else:
            message = f"{plus_option}{hex_message:>0{format_width - adjust_width}X}"
    elif type_data in OCTAL_TYPES:
        octal_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{octal_message:>#0{format_width - adjust_width}o}"
        else:
            message = f"{plus_option}{octal_message:>0{format_width - adjust_width}o}"

    return message


def format_alignment_left_space(
    format_message: str,
    format_width: int,
    format_precision: int,
    type_data: str,
    plus_minus: bool,
    hashtag: bool,
) -> str:
    """Align the message to the left and pad using spaces."""
    message = format_message
    precision_value = format_precision
    plus_option = "+" if plus_minus else ""
    adjust_width = 1 if plus_minus else 0

    if type_data in FLOAT_TYPES:
        float_message = parse_float(message)
        if precision_value == 0:
            float_parts = str(float_message).split('.')
            if len(float_parts) == 2:
                precision_value = len(float_parts[1])
        message = f"{plus_option}{float_message:<{format_width - adjust_width}.{precision_value}f}"
    elif type_data in INT_TYPES:
        int_message = parse_int(message)
        message = f"{plus_option}{int_message:<{format_width - adjust_width}d}"
    elif type_data in STRING_TYPES:
        if precision_value == 0:
            precision_value = len(message)
        message = f"{plus_option}{message[:precision_value]:<{format_width - adjust_width}}"
    elif type_data in HEX_TYPES:
        hex_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{hex_message:<#{format_width - adjust_width}X}"
        else:
            message = f"{plus_option}{hex_message:<{format_width - adjust_width}X}"
    elif type_data in OCTAL_TYPES:
        octal_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{octal_message:<#{format_width - adjust_width}o}"
        else:
            message = f"{plus_option}{octal_message:<{format_width - adjust_width}o}"

    return message


def format_alignment_right_space(
    format_message: str,
    format_width: int,
    format_precision: int,
    type_data: str,
    plus_minus: bool,
    hashtag: bool,
) -> str:
    """Align the message to the right and pad using spaces."""
    message = format_message
    precision_value = format_precision
    plus_option = "+" if plus_minus else ""
    adjust_width = 1 if plus_minus else 0

    if type_data in FLOAT_TYPES:
        float_message = parse_float(message)
        if precision_value == 0:
            float_parts = str(float_message).split('.')
            if len(float_parts) == 2:
                precision_value = len(float_parts[1])
        message = f"{plus_option}{float_message:>{format_width - adjust_width}.{precision_value}f}"
    elif type_data in INT_TYPES:
        int_message = parse_int(message)
        message = f"{plus_option}{int_message:>{format_width - adjust_width}d}"
    elif type_data in STRING_TYPES:
        if precision_value == 0:
            precision_value = len(message)
        message = f"{plus_option}{message[:precision_value]:>{format_width - adjust_width}}"
    elif type_data in HEX_TYPES:
        hex_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{hex_message:>#{format_width - adjust_width}X}"
        else:
            message = f"{plus_option}{hex_message:>{format_width - adjust_width}X}"
    elif type_data in OCTAL_TYPES:
        octal_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{octal_message:>#{format_width - adjust_width}o}"
        else:
            message = f"{plus_option}{octal_message:>{format_width - adjust_width}o}"

    return message


def format_left(
    format_message: str,
    format_precision: int,
    type_data: str,
    plus_minus: bool,
    hashtag: bool,
) -> str:
    """Align the message to the left."""
    message = format_message
    precision_value = format_precision
    plus_option = "+" if plus_minus else ""

    if type_data in FLOAT_TYPES:
        float_message = parse_float(message)
        if precision_value == 0:
            float_parts = str(float_message).split('.')
            if len(float_parts) == 2:
                precision_value = len(float_parts[1])
        message = f"{plus_option}{float_message:<.{precision_value}f}"
    elif type_data in INT_TYPES:
        int_message = parse_int(message)
        message = f"{plus_option}{int_message:<d}"
    elif type_data in STRING_TYPES:
        if precision_value == 0:
            precision_value = len(message)
        message = f"{plus_option}{message[:precision_value]:<}"
    elif type_data in HEX_TYPES:
        hex_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{hex_message:<#X}"
        else:
            message = f"{plus_option}{hex_message:<X}"
    elif type_data in OCTAL_TYPES:
        octal_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{octal_message:<#o}"
        else:
            message = f"{plus_option}{octal_message:<o}"

    return message


def format_right(
    format_message: str,
    format_precision: int,
    type_data: str,
    plus_minus: bool,
    hashtag: bool,
) -> str:
    """Align the message to the right (default)."""
    message = format_message
    precision_value = format_precision
    plus_option = "+" if plus_minus else ""

    if type_data in FLOAT_TYPES:
        float_message = parse_float(message)
        if precision_value == 0:
            float_parts = str(float_message).split('.')
            if len(float_parts) == 2:
                precision_value = len(float_parts[1])
        message = f"{plus_option}{float_message:>.{precision_value}f}"
    elif type_data in INT_TYPES:
        int_message = parse_int(message)
        message = f"{plus_option}{int_message:>d}"
    elif type_data in STRING_TYPES:
        if precision_value == 0:
            precision_value = len(message)
        message = f"{plus_option}{message[:precision_value]:>}"
    elif type_data in HEX_TYPES:
        hex_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{hex_message:>#X}"
        else:
            message = f"{plus_option}{hex_message:>X}"
    elif type_data in OCTAL_TYPES:
        octal_message = parse_int(message)
        if hashtag:
            message = f"{plus_option}{octal_message:>#o}"
        else:
            message = f"{plus_option}{octal_message:>o}"

    return message
