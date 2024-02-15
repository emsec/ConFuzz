from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes the configuration options register 0 and configuration options register 1.

https://docs.xilinx.com/r/en-US/ug470_7Series_Config
Table 5-30, page 107
Table 5-32, page 110
"""


def fuzz_cor0_register_reserved(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the COR0 register.

    Ignore the first four bits because they can not be read back which is verified with the fuzzer below.

    Strategy:
    1.) Fuzz bit 26 while keeping the bits from the default value set.
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
                fuzzing_mask=0x04000000,
            ),
            NOP(2),
        ),
    )

    session.connect(cor0_request)

    session.fuzz(self._test_case_name)


def fuzz_cor0_register_reserved_first_four_bits(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the COR0 register and verifies that the first four bits can never be read back.

    Strategy:
    1.) Fuzz the reserved bits while keeping the bits from the default value set.
    2.) Mark test case as crash if the register value has one of the first four bits set.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register9": {
            "crash_if_differs_from_default": "no",
            "crash_if_some_bits_in_mask_set": "F0 00 00 00",
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
                fuzzing_mask=0xF4000000,
            ),
            NOP(2),
        ),
    )

    session.connect(cor0_request)

    session.fuzz(self._test_case_name)


def fuzz_cor1_register_reserved(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of the COR1 register.

    Ignore bits 10 and 11 because these bits influence the unknown register 27.

    Strategy:
    1.) Fuzz all reserved bits except bits 10 and 11.
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
                fuzzing_mask=0xFFFC70F0,
            ),
            NOP(2),
        ),
    )

    session.connect(cor1_request)

    session.fuzz(self._test_case_name)


def _cor1_register_reserved_bits_10_11_fuzzer(
    self, crash_if_not_equal_to, static_bits, session_kwargs: dict = {}
):
    """Fuzzes the reserved bits 10 and 11 of the COR1 register.

    Ignore the first block of reserved bits (bits 18 to 31) to the reduce the amount of test cases.
    For every possible value for bits 10 and 11 fuzz all other reserved bits of the COR1 register.

    If bits 10 and 11 are set to 11 we expect the unknown register 27 to be 00 00 00 00.
    If bits 10 and 11 are set to 10 we expect the unknown register 27 to be 00 00 00 25 (note: this value seems to be board specific).
    If bits 10 and 11 are set to 01 we expect the unknown register 27 to be F3 B1 11 A0 (note: this value seems to be board specific).
    If bits 10 and 11 are set to 00 we expect the unknown register 27 to be 82 80 00 1B (note: this value seems to be board specific).

    82 80 00 1B is the default value for the unknown register 27.

    Strategy:
    1.) Set bits 10 and 11 and apply the fuzzing mask.
    2.) Mark test case as crash if the register value is not equal to the fuzzed_cor1_value
        or the unknown register 27 does not hold the expected value.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register14": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "cor1_request.fuzzed_cor1_value",
        },
        "register27": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": crash_if_not_equal_to,
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
                static_bits=static_bits,
                fuzzing_mask=0x000070F0,
            ),
            NOP(2),
        ),
    )

    session.connect(cor1_request)

    session.fuzz(self._test_case_name)


def fuzz_cor1_register_reserved_bits_10_11_set_to_11(self, session_kwargs: dict = {}):
    """Bits 10 and 11 are set to 11 and we expect the unknown register 27 to be 00 00 00 00."""

    _cor1_register_reserved_bits_10_11_fuzzer(
        self,
        crash_if_not_equal_to="00 00 00 00",
        static_bits=0x00000C00,
        session_kwargs=session_kwargs,
    )


def fuzz_cor1_register_reserved_bits_10_11_set_to_10(self, session_kwargs: dict = {}):
    """Bits 10 and 11 are set to 10 and we expect the unknown register 27 to be 00 00 00 25."""

    _cor1_register_reserved_bits_10_11_fuzzer(
        self,
        crash_if_not_equal_to="00 00 00 25",
        static_bits=0x00000800,
        session_kwargs=session_kwargs,
    )


def fuzz_cor1_register_reserved_bits_10_11_set_to_01(self, session_kwargs: dict = {}):
    """Bits 10 and 11 are set to 01 and we expect the unknown register 27 to be F3 B1 11 A0."""

    _cor1_register_reserved_bits_10_11_fuzzer(
        self,
        crash_if_not_equal_to="F3 B1 11 A0",
        static_bits=0x00000400,
        session_kwargs=session_kwargs,
    )


def fuzz_cor1_register_reserved_bits_10_11_set_to_00(self, session_kwargs: dict = {}):
    """Bits 10 and 11 are set to 00 and we expect the unknown register 27 to be 82 80 00 1B."""

    _cor1_register_reserved_bits_10_11_fuzzer(
        self,
        crash_if_not_equal_to="82 80 00 1B",
        static_bits=0x00000000,
        session_kwargs=session_kwargs,
    )
