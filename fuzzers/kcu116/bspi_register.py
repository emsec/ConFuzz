from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""Fuzzes the BPI/SPI configuration options register.

https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
Table 9-39, page 176
"""


def fuzz_bspi_register_reserved(self, session_kwargs: dict = {}):
    """Fuzz the reserved bits of the BSPI register."""

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register31": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to_transmitted": "bspi_request.fuzzed_bspi_value",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    bspi_request = Request(
        name="bspi_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_bspi", register_address=31),
            BitstreamWord(
                name="fuzzed_bspi_value",
                static_bits=0x0000000B,
                fuzzing_mask=0xF0000800,
            ),
            NOP(2),
        ),
    )

    session.connect(bspi_request)

    session.fuzz(self._test_case_name)
