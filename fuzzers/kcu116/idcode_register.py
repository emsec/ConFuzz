from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.constants import CONSTANTS
from src.primitives import NOP, BitstreamWord, Type1WritePacket, Type2WritePacket

"""Fuzzes the IDCODE register.

https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
page 171
"""


def fuzz_idcode_register_irrelevant_bits(self, session_kwargs: dict = {}):
    """Fuzz the irrelevant bits of the IDCODE register.

    According to the documentation the four most significant bits in the IDCODE register
    represent the revision field which can vary.
    The twelve least significant bits are always identical.
    https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    page 19

    Hence, it can be assumed that the four most significant and the twelve least significant bits
    of the IDCODE register are not relevant when writing to the FDRI register.
    This will be verified with this fuzzer.

    Strategy:
    1.) Try to write three frames (incl. dummy frame) to the FDRI register while fuzzing
        the four most significant and the twelve least significant bits of the IDCODE register.
    2.) Try to read back the written frames and
        crash if the written frames could not be read back from the FDRO register.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register1": {
            "crash_if_differs_from_default": "no",
            # Two frame have been written, therefore the FAR register should contain 00 00 00 02.
            "crash_if_not_equal_to": "00 00 00 02",
        },
        "register3": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "BE EF BE EF" * 45
            # Account for ECC bits inside the frame.
            + "00 0F BE EF B0 00 BE EF" + "BE EF BE EF" * 46 + "F0 0D F0 0D" * 45
            # Account for ECC bits inside the frame.
            + "00 0D F0 0D F0 00 F0 0D"
            + "F0 0D F0 0D" * 46
            + "00 00 00 00"
            * (
                CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
                + CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS
            ),
        },
        "register4": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "idcode_request.wcfg_code",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    idcode_request = Request(
        name="idcode_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_idcode", register_address=12),
            BitstreamWord(
                name="fuzzed_idcode_value",
                static_bits=0x04A62000,
                fuzzing_mask=0xF0000FFF,
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
                name="fdri_frame_1",
                default_value=b"\xF0\x0D\xF0\x0D"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            Static(
                name="fdri_frame_2",
                default_value=b"\xBE\xEF\xBE\xEF"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            Static(
                name="fdri_frame_dummy",
                default_value=b"\xDE\xAD\xC0\xDE"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            NOP(2),
        ),
    )

    session.connect(idcode_request)

    session.fuzz(self._test_case_name)


def fuzz_idcode_register_relevant_bits(self, session_kwargs: dict = {}):
    """Fuzz the relevant bits of the IDCODE register.

    It can be assumed that the remaining bits of the IDCODE register
    can not be changed when writing to FDRI register.
    This will be verified with this fuzzer.

    Strategy:
    1.) Try to write three frames (incl. dummy frame) to the FDRI register while fuzzing
        the relevant bits that have not been fuzzed by the fuzzer above.
    2.) Try to read back the written frames and crash if the status register
        and BOOTSTS register do not contain ID_ERRORs.
        This leads to one expected crash: the test case with the correct IDCODE for the device.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register1": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 00",
        },
        "register4": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "idcode_request.wcfg_code",
        },
        "register7": {
            "crash_if_differs_from_default": "no",
            # Default value but BIT15_ID_ERROR is set.
            "crash_if_not_equal_to": "12 80 9D 0C",
        },
        "register22": {
            "crash_if_differs_from_default": "no",
            # We expect ID_ERROR_0 and VALID_0 to be set.
            "crash_if_not_equal_to": "00 00 00 11",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
            sync_after_fuzz=True,
        )
    )

    idcode_request = Request(
        name="idcode_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_idcode", register_address=12),
            BitstreamWord(
                name="fuzzed_idcode_value",
                static_bits=0x00000093,
                fuzzing_mask=0x0FFFF000,
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
                name="fdri_frame_1",
                default_value=b"\xF0\x0D\xF0\x0D"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            Static(
                name="fdri_frame_2",
                default_value=b"\xBE\xEF\xBE\xEF"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            Static(
                name="fdri_frame_dummy",
                default_value=b"\xDE\xAD\xC0\xDE"
                * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
            ),
            NOP(2),
        ),
    )

    session.connect(idcode_request)

    session.fuzz(self._test_case_name)
