from boofuzz.blocks import Request
from boofuzz.primitives import Mirror, Static
from boofuzz.sessions import Session
from src.callbacks import write_two_frames
from src.constants import CONSTANTS
from src.primitives import (
    NOP,
    BitstreamWord,
    Type1ReadPacket,
    Type1WritePacket,
    Type2ReadPacket,
    Type2WritePacket,
)

"""Fuzzes the frame address register.

https://docs.xilinx.com/r/en-US/ug470_7Series_Config
Table 5-24, page 102
"""


def fuzz_far_register_reserved(self, session_kwargs: dict = {}):
    """Fuzz the reserved bits 26 to 31 of the FAR register.

    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    Table 6-5, page 125, readback command sequence from step 7

    Strategy:
    1.) Write two frames to the frame address zero.
    2.) Try to read the written frames from frame address zero while fuzzing bits 26 to 31.
    3.) Mark the test case as crash if the fuzz response did not return the written frames.
    """

    session = Session(
        post_start_target_callbacks=[write_two_frames],
        receive_data_after_fuzz=True,
        **session_kwargs,
    )

    words_to_read = (
        3 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
        + CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS
    )

    custom_register_settings = {
        "fuzz_response": {
            "probe": "yes",
            "length": words_to_read * 32,
            "display_data_as_frames": "yes",
            "crash_if_not_equal_to": "BE EF BE EF"
            * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
            + "F0 0D F0 0D" * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
            + "00 00 00 00"
            * (
                CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
                + CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS
            ),
        },
        "register1": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 03",
        },
        # The FDRO register can be ignored to improve the performance because the fuzz_response contains the same data.
        "register3": {"probe": "no"},
        "register4": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "far_request.rcfg_code",
        },
        "register21": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 00",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            response_length=words_to_read * 32,
            custom_register_settings=custom_register_settings,
        )
    )

    far_request = Request(
        name="far_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_cmd", register_address=4),
            Static(name="rcfg_code", default_value=b"\x00\x00\x00\x04"),
            Type1WritePacket(name="write_to_far", register_address=1),
            BitstreamWord(
                name="fuzzed_far_value",
                static_bits=0x00000000,
                fuzzing_mask=0xFC000000,
            ),
            Type1ReadPacket(name="read_from_fdro", register_address=3, word_count=0),
            Type2ReadPacket(name="read_from_fdro_type_2", word_count=words_to_read),
            NOP(2),
        ),
    )

    session.connect(far_request)

    session.fuzz(self._test_case_name)


def fuzz_far_register_block_type(self, session_kwargs: dict = {}):
    """Fuzz the block type of the FAR register.

    Strategy:
    1.) Try to write to a specific frame address while mutating the block type.
    2.) Try to read from the same frame address.
    3.) Store the results for manual analysis.
    """

    session = Session(receive_data_after_fuzz=True, **session_kwargs)

    words_to_read = (
        5 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
        + CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS
    )

    custom_register_settings = {
        "fuzz_response": {
            "probe": "yes",
            "length": words_to_read * 32,
            "display_data_as_frames": "yes",
        },
        "register4": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "far_request.rcfg_code",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            response_length=words_to_read * 32,
            custom_register_settings=custom_register_settings,
        )
    )

    far_request = Request(
        name="far_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_idcode", register_address=12),
            Static(
                name="idcode_value",
                default_value=CONSTANTS.BOARD_CONSTANTS.DEVICE_IDCODE,
            ),
            Type1WritePacket(name="write_to_far", register_address=1),
            BitstreamWord(
                name="fuzzed_far_value",
                static_bits=0x00000000,
                fuzzing_mask=0x03800000,
            ),
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
            Type1WritePacket(name="write_to_cmd_2", register_address=4),
            Static(name="rcfg_code", default_value=b"\x00\x00\x00\x04"),
            Type1WritePacket(name="write_to_far_2", register_address=1),
            Mirror(name="mirrored_far_value", primitive_name="fuzzed_far_value"),
            Type1ReadPacket(name="read_from_fdro", register_address=3, word_count=0),
            Type2ReadPacket(name="read_from_fdro_type_2", word_count=words_to_read),
            NOP(2),
        ),
    )

    session.connect(far_request)

    session.fuzz(self._test_case_name)
