import argparse
import os

from src.constants import CONSTANTS


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "This script analyzes the log_transmitted_if_crashed log files "
            "and searches for bits that are identical in all transmitted values that led to a crash."
        )
    )

    parser.add_argument(
        "-b",
        "--board",
        default=CONSTANTS.BOARD,
        choices=CONSTANTS.AVAILABLE_BOARDS,
        help=("Specify the development board to be analyzed."),
    )
    parser.add_argument(
        "-f",
        "--log_file",
        default=None,
        help=(
            "Specify a log_transmitted_if_crashed log file that should be analyzed. "
            "If no log file is provided the newest log_transmitted_if_crashed log file in the RESULTS_DIR is analyzed."
        ),
    )
    parser.add_argument(
        "-m",
        "--fuzzing_mask",
        default=None,
        type=lambda x: int(x, 16),
        help=(
            "If a fuzzing mask is provided (as hex value) all bits that are not set in the fuzzing mask "
            "are marked with a question mark in the identical_bits string."
        ),
    )
    parser.add_argument(
        "-if",
        "--transmitted_if",
        default="both",
        choices=["crashed", "not_crashed", "both"],
        help=(
            "This parameter can be used to only search for the newest log_transmitted_if_crashed "
            "or log_transmitted_if_not_crashed file. "
            "If a log file is specified this parameter is ignored."
        ),
    )

    return parser.parse_args()


def find_newest_log_file(starts_with) -> str:
    """Find the newest log_transmitted_if_crashed log file in the RESULTS_DIR."""

    log_files = []
    # Iterate over the RESULTS_DIR and all its subdirectories
    for root, dirs, files in os.walk(CONSTANTS.RESULTS_DIR):
        # Append all log_transmitted_if_crashed log files in the current directory to the log_files list.
        [
            log_files.append(os.path.join(root, f))
            for f in files
            if f.startswith(starts_with)
        ]

    # Get the newest log_transmitted_if_crashed log file.
    if log_files:
        return max(log_files, key=os.path.getctime)
    else:
        return ""


def separate_bytes_in_bitstring(bitstring: str) -> str:
    """Separates the bytes in a bit string by inserting a space character between each 8-bit group."""

    return " ".join(bitstring[i : i + 8] for i in range(0, len(bitstring), 8))


args = parse_args()

CONSTANTS.update_board(args.board)

if args.log_file:
    log_file = args.log_file
else:
    # Use the newest log_transmitted_if_crashed log file in the RESULTS_DIR if no log file was specified.
    starts_with = "log_transmitted_if_"
    if args.transmitted_if == "crashed":
        starts_with += "crashed"
    elif args.transmitted_if == "not_crashed":
        starts_with += "not_crashed"

    log_file = find_newest_log_file(starts_with)

with open(log_file) as f:
    # The lines in the log_transmitted_if_crashed log file contain values separated by \t\t.
    # We only need the first column which contains the transmitted value as hex string.
    transmitted_values = [line.split("\t", 1)[0] for line in f if line.strip()]

# Calculate the length in bits of the transmitted values.
# They should all have the same length.
transmitted_values_length = len(transmitted_values[0].replace(" ", "")) * 4

# Remove spaces from the hex values convert them to integers.
transmitted_values = [int(value.replace(" ", ""), 16) for value in transmitted_values]
# Compute the bitwise inversion of all transmitted values.
transmitted_values_inverted = [~value for value in transmitted_values]

# Compute the result of a bitwise AND of all integers each list.
# idendical_ones only has bits set at positions where all values in the transmitted_values list have a bit set.
# identical_zeros only has bits set at positions where all values in the transmitted_values_inverted list have a bit set.
identical_ones = transmitted_values[0]
identical_zeros = transmitted_values_inverted[0]
for i in range(1, len(transmitted_values)):
    identical_ones &= transmitted_values[i]
    identical_zeros &= transmitted_values_inverted[i]

if args.fuzzing_mask:
    fuzzing_mask = args.fuzzing_mask
else:
    # Generate a fuzzing mask where all bits are set if no fuzzing mask was specified.
    fuzzing_mask = 2**transmitted_values_length - 1

# Bits in the identical_bits string are only 1 or 0 if all transmitted values have the same bit value at this position.
# All other bits in the identical_bits string are marked with a question mark.
# Only bits that are set in the fuzzing mask can be set in the identical_bits string.
identical_bits = ""
for i in reversed(range(transmitted_values_length)):
    if identical_ones >> i & 0x1 and fuzzing_mask >> i & 0x1:
        identical_bits += "1"
    elif identical_zeros >> i & 0x1 and fuzzing_mask >> i & 0x1:
        identical_bits += "0"
    else:
        identical_bits += "?"

print(log_file)
print()
# Print all transmitted values, the fuzzing mask and the identical_bits string.
[
    print(separate_bytes_in_bitstring(f"{value:0{transmitted_values_length}b}"))
    for value in transmitted_values
]
print()
print(
    separate_bytes_in_bitstring(f"{fuzzing_mask:0{transmitted_values_length}b}")
    + " (fuzzing mask)"
)
print()
print(separate_bytes_in_bitstring(identical_bits) + " (identical bits)")
