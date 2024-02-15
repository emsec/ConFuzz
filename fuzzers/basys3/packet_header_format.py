from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes components of the packet header format.

https://docs.xilinx.com/r/en-US/ug470_7Series_Config
Table 5-20, page 100
"""


def fuzz_header_type_opcode(self, session_kwargs: dict = {}):
    """Fuzzes the header type and opcode of the packet header format.

    Strategy:
    1.) Write value to WBSTAR register.
    2.) Try reading from WBSTAR while mutating through all possible header type and opcode combinations.
    3.) Mark the test case as crash if the returned value is not zero or
        BIT29_BAD_PACKET_ERROR in the status register is not set.
    4.) Store the results for manual analysis.
    """

    session = Session(receive_data_after_fuzz=True, **session_kwargs)

    custom_register_settings = {
        "fuzz_response": {
            "probe": "yes",
            "crash_if_not_equal_to": "00 00 00 00",
        },
        "register7": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "70 00 1D 0C",
        },
        "register16": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "F0 F0 F0 F0",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            response_length=32,
            custom_register_settings=custom_register_settings,
        )
    )

    header_type_opcode_request = Request(
        name="header_type_opcode_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_wbstar", register_address=16),
            Static(name="wbstar_value", default_value=b"\xF0\xF0\xF0\xF0"),
            NOP(2),
            BitstreamWord(
                name="fuzzed_read_from_wbstar",
                static_bits=0x00020001,
                fuzzing_mask=0xF8000000,
            ),
            NOP(2),
        ),
    )

    session.connect(header_type_opcode_request)

    session.fuzz(self._test_case_name)


def fuzz_register_address(self, session_kwargs: dict = {}):
    """Fuzzes the reserved bits of Table 5-20.

    Strategy:
    1.) Write value to WBSTAR register.
    2.) Try reading from WBSTAR while fuzizng the reserved bits.
    3.) Mark test case as crash if the target does not return the written value.
    """

    session = Session(receive_data_after_fuzz=True, **session_kwargs)

    custom_register_settings = {
        "fuzz_response": {
            "probe": "yes",
            "crash_if_not_equal_to": "F0 F0 F0 F0",
        },
        "register16": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "F0 F0 F0 F0",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            response_length=32,
            custom_register_settings=custom_register_settings,
        )
    )

    register_address_request = Request(
        name="register_address_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_wbstar", register_address=16),
            Static(name="wbstar_value", default_value=b"\xF0\xF0\xF0\xF0"),
            NOP(2),
            BitstreamWord(
                name="fuzzed_read_from_wbstar",
                static_bits=0x28020001,
                fuzzing_mask=0x07FC1800,
            ),
            NOP(2),
        ),
    )

    session.connect(register_address_request)

    session.fuzz(self._test_case_name)
