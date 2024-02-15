from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.primitives import NOP, BitstreamWord, Type1WritePacket

"""This is a default fuzzer that can be applied to various registers."""


def _default_register_fuzzer(
    self,
    register_address: int,
    session_kwargs: dict,
    custom_register_settings: dict = {},
    sync_after_fuzz: bool = False,
) -> None:
    """Applies the default fuzzer to a specific register.

    This fuzzer disables ConfigFallback in the CTL0 register and
    writes fuzzed values to the specified register address.
    The default crash settings can be modified using the custom_register_settings argument.
    """

    session = Session(**session_kwargs)

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
            sync_after_fuzz=sync_after_fuzz,
        )
    )

    default_request = Request(
        name="default_request",
        children=(
            # Disable ConfigFallback to get a more accurate error satus.
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(
                name=f"write_to_register_{register_address}",
                register_address=register_address,
            ),
            BitstreamWord(
                name=f"fuzzed_register_{register_address}_value",
                static_bits=0x00000000,
                # These overlapping masks result in 15 duplicate test cases, but this way,
                # we fuzz all possible five-bit blocks at each position.
                # Per overlap, we have only 15 instead of 16 because
                # the static_bits value is returned only once when using multiple masks.
                fuzzing_mask=[
                    0xFFFFC000,
                    0x0003FFFF,
                ],
            ),
            NOP(2),
        ),
    )

    session.connect(default_request)

    session.fuzz(self._test_case_name)
