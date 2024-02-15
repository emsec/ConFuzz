from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from fuzzers.default_register_fuzzer import _default_register_fuzzer
from src.constants import CONSTANTS
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes unknown registers with undocumented register addresses.

According to the documentation there are 20 documented configuration registers.
Since register addresses are five bit wide there could be twelve more registers.

https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
Table 9-19, page 162
"""


def fuzz_unknown_register_15(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 15."""

    _default_register_fuzzer(self, 15, session_kwargs)


def fuzz_unknown_register_18(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 18."""

    _default_register_fuzzer(self, 18, session_kwargs)


def fuzz_unknown_register_19(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 19."""

    custom_register_settings = {
        "register1": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "04 04 00 00",
        }
    }

    _default_register_fuzzer(self, 19, session_kwargs, custom_register_settings)


def fuzz_unknown_register_20(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 20."""

    custom_register_settings = {
        "register20": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "default_request.fuzzed_register_20_value",
        }
    }

    _default_register_fuzzer(self, 20, session_kwargs, custom_register_settings)


def fuzz_unknown_register_21(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 21."""

    _default_register_fuzzer(self, 21, session_kwargs)


def fuzz_unknown_register_23(self, session_kwargs: dict = {}):
    """Use a modified default register fuzzer to fuzz the unknown register 23.

    Bits 5 to 10, 16, 17, 20, 23, and 24 influence other registers, their behavior needs to be analyzed manually.
    Bits 5 to 10 are fuzzed with the second fuzzing mask, bits 16, 17, 20, 23, and 24 with first fuzzing mask.
    For these test cases crashes are expected.
    With the other two fuzzing masks the remaining bits are fuzzed.

    Strategy:
    1.) Modify the fuzzing masks from the default register fuzzer to fuzz bits 5 to 10, 16, 17, 20, 23, and 24 separately.
    2.) Mark test case as crash if the register value is not equal to the fuzzed_unknown_register_23_value.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register23": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "unknown_register_23_request.fuzzed_unknown_register_23_value",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    unknown_register_23_request = Request(
        name="unknown_register_23_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_unknown_register_23", register_address=23),
            BitstreamWord(
                name="fuzzed_unknown_register_23_value",
                static_bits=0x00000000,
                fuzzing_mask=[0x01930000, 0x000007E0, 0xFE6CC000, 0x0000F81F],
            ),
            NOP(2),
        ),
    )

    session.connect(unknown_register_23_request)

    session.fuzz(self._test_case_name)


def fuzz_unknown_register_25(self, session_kwargs: dict = {}):
    """Use a modified default register fuzzer to fuzz the unknown register 25.

    Ignore all values where one of the first four bits is set because they can not be read back.

    Strategy:
    1.) Modify the fuzzing masks from the default register fuzzer to exclude the first four bits.
    2.) Mark test case as crash if the register value is not equal to the fuzzed_unknown_register_25_value.
        Exclude the varying FDRO outputs because manually it is not clear which bits lead to which output.
        At this point, further analysis is necessary.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register3": {
            "crash_if_differs_from_default": "no",
        },
        "register25": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "unknown_register_25_request.fuzzed_unknown_register_25_value",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    unknown_register_25_request = Request(
        name="unknown_register_25_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(
                name=f"write_to_unknown_register_25",
                register_address=25,
            ),
            BitstreamWord(
                name=f"fuzzed_unknown_register_25_value",
                static_bits=0x00000000,
                fuzzing_mask=[
                    0x0FFFC000,
                    0x0003FFFF,
                ],
            ),
            NOP(2),
        ),
    )

    session.connect(unknown_register_25_request)

    session.fuzz(self._test_case_name)


def fuzz_unknown_register_25_first_four_bits(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to verify that the first four bits of the unknown register 26 can never be read back.

    Exclude the FDRO register becuase its output varies depending on the current fuzz value.
    """

    custom_register_settings = {
        "register3": {
            "crash_if_differs_from_default": "no",
        },
        "register25": {
            "crash_if_differs_from_default": "no",
            "crash_if_some_bits_in_mask_set": "F0 00 00 00",
        },
    }

    _default_register_fuzzer(self, 25, session_kwargs, custom_register_settings)


def fuzz_unknown_register_26(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 26.

    After writing to this register BIT15_IDCODE_ERROR in the status register is set.
    Additionally the ID_ERROR_0 and VALID_0 bits in the BOOTSTS register are set.
    """

    custom_register_settings = {
        "register7": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": " 12 80 9D 0C",
        },
        "register22": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 11",
        },
    }

    _default_register_fuzzer(
        self, 26, session_kwargs, custom_register_settings, sync_after_fuzz=True
    )


def fuzz_unknown_register_26_with_idcode(self, session_kwargs: dict = {}):
    """Use a modified default register fuzzer to fuzz the unknown register 26.

    This fuzzer verifies that writing the device IDCODE to the IDCODE register before
    writing to the unknown register 26 prevents the errors of the unmodified default register fuzzer.
    """

    session = Session(**session_kwargs)

    session.add_target(self._get_target(session._fuzz_data_logger))

    unknown_register_26_request = Request(
        name="unknown_register_26_request",
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
            Type1WritePacket(
                name=f"write_to_unknown_register_26",
                register_address=26,
            ),
            BitstreamWord(
                name=f"fuzzed_unknown_register_26_value",
                static_bits=0x00000000,
                fuzzing_mask=[
                    0xFFFFC000,
                    0x0003FFFF,
                ],
            ),
            NOP(2),
        ),
    )

    session.connect(unknown_register_26_request)

    session.fuzz(self._test_case_name)


def fuzz_unknown_register_27(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 27."""

    _default_register_fuzzer(self, 27, session_kwargs)


def fuzz_unknown_register_28(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 28."""

    _default_register_fuzzer(self, 28, session_kwargs)


def fuzz_unknown_register_29(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 29."""

    _default_register_fuzzer(self, 29, session_kwargs)


def fuzz_unknown_register_30(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 30."""

    _default_register_fuzzer(self, 30, session_kwargs)
