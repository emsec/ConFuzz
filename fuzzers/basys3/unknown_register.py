from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from fuzzers.default_register_fuzzer import _default_register_fuzzer
from src.callbacks import write_two_frames
from src.constants import CONSTANTS
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes unknown registers with undocumented register addresses.

According to the documentation there are 20 documented configuration registers.
Since register addresses are five bit wide there could be twelve more registers.

https://docs.xilinx.com/r/en-US/ug470_7Series_Config
Table 5-23, page 101
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
        "register19": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "default_request.fuzzed_register_19_value",
        }
    }

    _default_register_fuzzer(self, 19, session_kwargs, custom_register_settings)


def fuzz_unknown_register_20(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 20."""

    _default_register_fuzzer(self, 20, session_kwargs)


def fuzz_unknown_register_21(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the unknown register 21."""

    _default_register_fuzzer(self, 21, session_kwargs)


def fuzz_unknown_register_23(self, session_kwargs: dict = {}):
    """Use a modified default register fuzzer to fuzz the unknown register 23.

    Bits 5, 19, 20, 23, and 24 influence other registers, their behavior needs to be analyzed manually.
    Bits 5, 19, 20, and 24 are fuzzed with the first fuzzing mask.
    For these test cases crashes are expected.
    Bit 23 is excluded from the fuzzing process because setting this bit can completely crash the device.
    With the other two fuzzing masks the remaining bits are fuzzed.

    Strategy:
    1.) Modify the fuzzing masks from the default register fuzzer to fuzz bits 5, 19, 20, 23, and 24 separately.
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
                fuzzing_mask=[0x01180020, 0xFE67C000, 0x0003FFDF],
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
    """Use a modified default register fuzzer to fuzz the unknown register 26.

    Ignore all values where one of the first five bits is set because they can not be read back.

    Strategy:
    1.) Modify the fuzzing masks from the default register fuzzer to exclude the first five bits.
    2.) Mark test case as crash if the register value is not equal to the fuzzed_unknown_register_26_value
        or the CRC register is not zero.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register0": {
            "crash_if_equal_to": "",
            "crash_if_not_equal_to": "00 00 00 00",
        },
        "register26": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "unknown_register_26_request.fuzzed_unknown_register_26_value",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    unknown_register_26_request = Request(
        name="unknown_register_26_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(
                name=f"write_to_unknown_register_26",
                register_address=26,
            ),
            BitstreamWord(
                name=f"fuzzed_unknown_register_26_value",
                static_bits=0x00000000,
                fuzzing_mask=[
                    0x07FFC000,
                    0x0003FFFF,
                ],
            ),
            NOP(2),
        ),
    )

    session.connect(unknown_register_26_request)

    session.fuzz(self._test_case_name)


def fuzz_unknown_register_26_first_five_bits(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to verify that the first five bits of the unknown register 26 can never be read back."""

    custom_register_settings = {
        "register0": {
            "crash_if_equal_to": "",
            "crash_if_not_equal_to": "00 00 00 00",
        },
        "register26": {
            "crash_if_differs_from_default": "no",
            "crash_if_some_bits_in_mask_set": "F8 00 00 00",
        },
    }

    _default_register_fuzzer(self, 26, session_kwargs, custom_register_settings)


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
