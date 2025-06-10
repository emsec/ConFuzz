from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from fuzzers.default_register_fuzzer import _default_register_fuzzer
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes the control register 0 and the control register 1.

https://docs.xilinx.com/r/en-US/ug470_7Series_Config
Table 5-26, page 104
Table 5-40, page 113
"""


def fuzz_ctl0_register_reserved(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the CTL0 register except bit 14.

    Bit 14 is ignored in this fuzzer because if bit 14 is set the status register always returns zero.

    Strategy:
    1.) The write to the MASK register includes all reserved bits and the ConfigFallback bit.
    2.) Fuzz all reserved bits except bit 14 of the CTL0 register
        while keeping the ConfigFallback bit and the bits from the default value set.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register5": {
            "crash_if_not_equal_to": "",
            "crash_if_not_equal_to_transmitted": "ctl0_request.fuzzed_ctl0_value",
        }
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    ctl0_request = Request(
        name="ctl0_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x3f\xff\xee\x06"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            BitstreamWord(
                name="fuzzed_ctl0_value",
                static_bits=0x00000501,
                fuzzing_mask=0x3FFFAA06,
            ),
            NOP(2),
        ),
    )

    session.connect(ctl0_request)

    session.fuzz(self._test_case_name)


def fuzz_ctl0_register_reserved_bits_11_14_29(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the CTL0 register except bits 11, 14, and 29 after setting bits 11, 14, and 29.

    This fuzzer verifies that bits 11, 14, and 29 can not be set to zero after they have been set.
    Additionally, this fuzzer verifies that the status register is always zero if bit 14 is set.

    Strategy:
    1.) Set the ConfigFallback bit, and bits 11, 14, and 29.
    2.) Fuzz all reserved bits except bits 11, 14, and 29 of the CTL0 register
        while keeping the ConfigFallback bit, bit 14, and the bits from the default value set.
    3.) Mark the test case as crash if bits 11, 14, or 29 are not set or the status register is not zero.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register5": {
            "crash_if_not_equal_to": "",
            "crash_if_some_bits_in_mask_not_set": "20 00 48 00",
        },
        "register7": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 00",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    ctl0_request = Request(
        name="ctl0_request",
        children=(
            Type1WritePacket(
                name="write_to_mask_set_bits_10_11_14_29", register_address=6
            ),
            Static(
                name="mask_value_set_bits_10_11_14_29",
                default_value=b"\x20\x00\x4c\x00",
            ),
            Type1WritePacket(
                name="write_to_ctl0_set_bits_10_11_14_29", register_address=5
            ),
            Static(
                name="ctl0_value_set_bits_10_11_14_29",
                default_value=b"\x20\x00\x4c\x00",
            ),
            NOP(2),
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x3f\xff\xee\x06"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            BitstreamWord(
                name="fuzzed_ctl0_value",
                static_bits=0x00000501,
                fuzzing_mask=0x1FFFA206,
            ),
            NOP(2),
        ),
    )

    session.connect(ctl0_request)

    session.fuzz(self._test_case_name)


def fuzz_ctl1_register_reserved(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the CTL1 register."""

    _default_register_fuzzer(self, 24, session_kwargs)
