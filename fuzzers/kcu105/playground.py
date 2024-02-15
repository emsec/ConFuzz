from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.callbacks import programm_ultrascale_bbram
from src.primitives import *

"""Fuzzer for manually fuzzing or testing stuff."""


def fuzz_playground(self, session_kwargs: dict = {}):
    """Fuzzer for manually fuzzing or testing stuff."""

    session = Session(
        post_start_target_callbacks=[programm_ultrascale_bbram], **session_kwargs
    )

    custom_register_settings = {
        "register1": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 00",
        },
        "register5": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 05 41",
        },
        "register7": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "12 80 1d 0E",
        },
        "register16": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "42 42 42 42",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
            sync_after_fuzz=True,
        )
    )

    playground_request = Request(
        name="playground_request",
        children=(
            BitstreamWord(
                name="fuzzed_dummy_value",
                static_bits=0x20000000,
                fuzzing_mask=0x00000000,
            ),
            EncryptedXGHashUltraScaleBlock(
                name="encrypted_block",
                children=(
                    Type1WritePacket(name="write_to_wbstar", register_address=16),
                    Static("wbstar_value", default_value=b"\x42\x42\x42\x42"),
                    NOP(12),
                ),
                key_file_name="test_key.nky",
            ),
        ),
    )

    session.connect(playground_request)

    session.fuzz(self._test_case_name)
