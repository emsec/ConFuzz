from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes the command register.

https://docs.xilinx.com/r/en-US/ug470_7Series_Config
Table 5-25, page 102
"""


def fuzz_cmd_register_codes(self, session_kwargs: dict = {}):
    """Fuzz all command register codes that have a length of five bits."""

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register4": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "cmd_request.fuzzed_cmd_value",
        }
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    cmd_request = Request(
        name="cmd_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_cmd", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value",
                static_bits=0x00000000,
                fuzzing_mask=0x0000001F,
            ),
            NOP(2),
        ),
    )

    session.connect(cmd_request)

    session.fuzz(self._test_case_name)


def fuzz_cmd_register_irrelevant_bits(self, session_kwargs: dict = {}):
    """Fuzz the probably irrelevant bits of the command register.

    Assumption: All command register codes are only five bit wide
    and all other bits of the command register are ignored.

    Strategy:
    1.) Execute the RCRC command register code to set the CRC register to zero
        while fuzzing bit 6 to 31 of the command register.
        If only the five least significant bits are relevant the RCRC command register code
        should be executed and the CRC register should be zero.
    2.) Mark test case as crash if the CRC register is not zero.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register0": {"crash_if_equal_to": "", "crash_if_not_equal_to": "00 00 00 00"},
        "register4": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 07",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    cmd_request = Request(
        name="cmd_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_cmd", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value",
                static_bits=0x00000007,
                fuzzing_mask=[
                    0xFFFFC000,
                    0x0003FFE0,
                ],
            ),
            NOP(2),
        ),
    )

    session.connect(cmd_request)

    session.fuzz(self._test_case_name)
