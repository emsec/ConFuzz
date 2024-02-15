import os
import sys

from boofuzz.helpers import mkdir_safe
from boofuzz.primitives import Static
from src.constants import CONSTANTS
from src.primitives import *

if len(sys.argv) > 2:
    CONSTANTS.update_board(sys.argv[1])
    bitstream_name = sys.argv[2]
else:
    raise ValueError("please pass a board and a bitstream name as arguments")

### BITSTREAM DEFINITION START ###

bitstream = [
    SyncWord(),
    EncryptedSeries7Block(
        name="encrypted_block",
        children=(
            Type1WritePacket(name="write_to_idcode", register_address=12),
            Static(
                name="idcode_value",
                default_value=CONSTANTS.BOARD_CONSTANTS.DEVICE_IDCODE,
            ),
            Type1WritePacket(name="write_to_far", register_address=1),
            Static(name="far_value", default_value=b"\x00\x00\x00\x00"),
            Type1WritePacket(name="write_to_cmd", register_address=4),
            Static(name="wcfg_code", default_value=b"\x00\x00\x00\x01"),
            Type1WritePacket(name="write_to_fdri", register_address=2, word_count=0),
            Type2WritePacket(
                name="write_to_fdri_type_2",
                word_count=3 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            Static(
                name="fdri_value_1",
                default_value=b"\xF0\x0D\xF0\x0D"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            Static(
                name="fdri_value_2",
                default_value=b"\xBE\xEF\xBE\xEF"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            Static(
                name="fdri_value_3",
                default_value=b"\xDE\xAD\xC0\xDE"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
        ),
        pad_child_data=True,
        key_file_name="test_key.nky",
    ),
]

### BITSTREAM DEFINITION END ###

bitstream_bytes = b"".join(primitive.render() for primitive in bitstream)

mkdir_safe(CONSTANTS.BITSTREAMS_DIR)

with open(os.path.join(CONSTANTS.BITSTREAMS_DIR, bitstream_name), "wb") as f:
    f.write(bitstream_bytes)
