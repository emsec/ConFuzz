from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes the configuration options register 0 and configuration options register 1.

https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
Table 9-27, page 170
Table 9-29, page 172
"""


def fuzz_cor0_register_reserved(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the COR0 register.

    Ignore the first bit because it can not be read back which is verified with the fuzzer below.

    Strategy:
    1.) Fuzz the reserved bits while keeping the bits from the default value set.
    2.) Mark test case as crash if the register value is not equal to the fuzzed_cor0_value.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register9": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "cor0_request.fuzzed_cor0_value",
        }
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    cor0_request = Request(
        name="cor0_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_cor0", register_address=9),
            BitstreamWord(
                name="fuzzed_cor0_value",
                static_bits=0x00003FEC,
                fuzzing_mask=0x7A818000,
            ),
            NOP(2),
        ),
    )

    session.connect(cor0_request)

    session.fuzz(self._test_case_name)


def fuzz_cor0_register_reserved_first_bit(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the COR0 register and verifies that the first bit can never be read back.

    Strategy:
    1.) Fuzz the reserved bits while keeping the bits from the default value set.
    2.) Mark test case as crash if the register value has the first bit set.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register9": {
            "crash_if_differs_from_default": "no",
            "crash_if_some_bits_in_mask_set": "80 00 00 00",
        }
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    cor0_request = Request(
        name="cor0_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_cor0", register_address=9),
            BitstreamWord(
                name="fuzzed_cor0_value",
                static_bits=0x00003FEC,
                fuzzing_mask=0xFA818000,
            ),
            NOP(2),
        ),
    )

    session.connect(cor0_request)

    session.fuzz(self._test_case_name)


def fuzz_cor1_register_reserved(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the COR1 register except bit 4.

    Ignore bit 4 because when setting this bit the unknown register 25 contains 00 13 07 03.

    Strategy:
    1.) Fuzz all reserved bits except bit 4 using two masks to reduce the amout of test cases.
    2.) Mark test case as crash if the register value is not equal to the fuzzed_cor1_value.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register14": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "cor1_request.fuzzed_cor1_value",
        }
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    cor1_request = Request(
        name="cor1_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_cor1", register_address=14),
            BitstreamWord(
                name="fuzzed_cor1_value",
                static_bits=0x00000000,
                fuzzing_mask=[0xFFFC0000, 0x00007CE0],
            ),
            NOP(2),
        ),
    )

    session.connect(cor1_request)

    session.fuzz(self._test_case_name)


def fuzz_cor1_register_reserved_bit_4(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the COR1 register except bit 4.

    This fuzzer verifies that the unknown register 25 always contains 00 13 07 03 after setting bit 4.
    The default value of the unknown register 25 is 08 8D 55 1C.

    Strategy:
    1.) Fuzz all reserved bits while keeping bit 4 set using two masks to reduce the amout of test cases.
    2.) Mark test case as crash if the register value is not equal to the fuzzed_cor1_value
        or the unknown register 25 does not contain 00 13 07 03.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register14": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "cor1_request.fuzzed_cor1_value",
        },
        "register25": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 13 07 03",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    cor1_request = Request(
        name="cor1_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_cor1", register_address=14),
            BitstreamWord(
                name="fuzzed_cor1_value",
                static_bits=0x00000010,
                fuzzing_mask=[0xFFFC0000, 0x00007CE0],
            ),
            NOP(2),
        ),
    )

    session.connect(cor1_request)

    session.fuzz(self._test_case_name)
