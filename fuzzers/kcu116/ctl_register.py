from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from fuzzers.default_register_fuzzer import _default_register_fuzzer
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes the control register 0 and the control register 1.

https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
Table 9-23, page 165
Table 9-37, page 176
"""


def fuzz_ctl0_register_reserved(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the CTL0 register except bits 1, 7, 14, 15, 16, 17, and 18.

    Modifying any of the other bits reserved bits changes the behavior of the target device.
    This has been tested with the fuzzers below or manually (bits 15 to 18).

    Strategy:
    1.) The write to the MASK register includes all reserved bits and the ConfigFallback bit.
    2.) Fuzz all reserved bits except bits 1, 7, 14, 15, 16, 17, and 18 of the CTL0 register
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
            Static(name="mask_value", default_value=b"\x3F\xFF\xEE\x86"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            BitstreamWord(
                name="fuzzed_ctl0_value",
                static_bits=0x00000501,
                fuzzing_mask=0x3FF82A04,
            ),
            NOP(2),
        ),
    )

    session.connect(ctl0_request)

    session.fuzz(self._test_case_name)


def fuzz_ctl0_register_reserved_bits_11_14_29(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the CTL0 register except bits 1, 7, 11, 14, 15, 16, 17, 18, and 29 after setting bits 11, 14, and 29.

    This fuzzer verifies that bits 11, 14, and 29 can not be set to zero after they have been set.
    Additionally, this fuzzer verifies that the status register is always zero if bit 14 is set.

    Strategy:
    1.) Set the ConfigFallback bit, and bits 11, 14, and 29.
    2.) Fuzz all reserved bits except bits 1, 7, 11, 14, 15, 16, 17, 18, and 29 of the CTL0 register
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
                default_value=b"\x20\x00\x4C\x00",
            ),
            Type1WritePacket(
                name="write_to_ctl0_set_bits_10_11_14_29", register_address=5
            ),
            Static(
                name="ctl0_value_set_bits_10_11_14_29",
                default_value=b"\x20\x00\x4C\x00",
            ),
            NOP(2),
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x3F\xFF\xEE\x86"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            BitstreamWord(
                name="fuzzed_ctl0_value",
                static_bits=0x00000501,
                fuzzing_mask=0x1FF82204,
            ),
            NOP(2),
        ),
    )

    session.connect(ctl0_request)

    session.fuzz(self._test_case_name)


def fuzz_ctl0_register_reserved_bits_1_7(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the CTL0 register except bits 1, 7, 11, 14, 15, 16, 17, 18, and 29 after setting bits 1 and 7.

    This fuzzer verifies that setting bit 1 of the CTL0 register leads to
    BIT14_DONE_PIN set to 1 and BIT08_MODE_PIN_M[2:0] set to 111 in the status register.
    Additionally, it verifies that bit 7 of the CTL0 register is always zero or can not be read back.

    Strategy:
    1.) Set the ConfigFallback bit, and bits 1 and 7.
    2.) Fuzz all reserved bits except bits 1, 7, 11, 14, 15, 16, 17, 18, and 29 of the CTL0 register
        while keeping the ConfigFallback bit, bits 1, 7, and the bits from the default value set.
    3.) Mark the test case as crash if bit 7 is set, BIT14_DONE_PIN is not 1, or BIT08_MODE_PIN_M[2:0] is not 111.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register5": {
            "crash_if_not_equal_to": "",
            "crash_if_some_bit_in_mask_set": "00 00 00 80",
        },
        "register7": {
            "crash_if_differs_from_default": "no",
            "crash_if_some_bits_in_mask_not set": "00 00 47 00",
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
            Type1WritePacket(name="write_to_mask_set_bits_1_7_10", register_address=6),
            Static(
                name="mask_value_set_bits_1_7_10",
                default_value=b"\x00\x00\x04\x82",
            ),
            Type1WritePacket(name="write_to_ctl0_set_bits_1_7_10", register_address=5),
            Static(
                name="ctl0_value_set_bits_1_7_10",
                default_value=b"\x00\x00\x04\x82",
            ),
            NOP(2),
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x3F\xFF\xEE\x86"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            BitstreamWord(
                name="fuzzed_ctl0_value",
                static_bits=0x00000583,
                fuzzing_mask=0x1FF82204,
            ),
            NOP(2),
        ),
    )

    session.connect(ctl0_request)

    session.fuzz(self._test_case_name)


def fuzz_ctl1_register_reserved(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the CTL1 register.

    BIT23_CAPTURE is documented for the UltraScale(+) devices but
    it is included in the fuzzing process so that we can use the default register fuzzer.
    """

    _default_register_fuzzer(self, 24, session_kwargs)
