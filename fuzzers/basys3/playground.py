from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.callbacks import write_two_frames
from src.constants import CONSTANTS
from src.primitives import *

"""Fuzzer for manually fuzzing or testing stuff."""


def fuzz_playground(self, session_kwargs: dict = {}):
    """Fuzzer for manually fuzzing or testing stuff."""

    session = Session(
        post_start_target_callbacks=[write_two_frames],
        receive_data_after_fuzz=True,
        **session_kwargs,
    )

    words_to_read = (
        5 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
        + CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS
    )

    custom_register_settings = {
        "fuzz_response": {
            "probe": "yes",
            "length": words_to_read * 32,
            "display_data_as_frames": "yes",
        },
        "register1": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 05",
        },
        "register3": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "BE EF BE EF"
            * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
            + "F0 0D F0 0D" * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
            + "00 00 00 00"
            * (
                CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
                + CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS
            ),
        },
        "register4": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 04",
        },
        "register21": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 00",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            response_length=words_to_read * 32,
            custom_register_settings=custom_register_settings,
        )
    )

    playground_request = Request(
        name="playground_request",
        children=(
            Type1WritePacket(name="write_to_cmd", register_address=4),
            Static(name="rcfg_code", default_value=b"\x00\x00\x00\x04"),
            Type1WritePacket(name="write_to_far", register_address=1),
            BitstreamWord(
                name="fuzzed_far_value",
                static_bits=0x00000000,
                fuzzing_mask=0x00000000,
            ),
            Type1ReadPacket(name="read_from_fdro", register_address=3, word_count=0),
            Type2ReadPacket(name="read_from_fdro_type_2", word_count=words_to_read),
            NOP(2),
        ),
    )

    session.connect(playground_request)

    session.fuzz(self._test_case_name)


def fuzz_enc_playground(self, session_kwargs: dict = {}):
    """Fuzzer for manually fuzzing or testing stuff."""

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register5": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 05 41",
        },
        "register7": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "50 00 1d 0E",
        },
        "register16": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "42 42 42 42",
        },
        "register26": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 98",
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
            EncryptedSeries7Block(
                name="encrypted_block",
                children=(
                    Type1WritePacket(name="write_to_wbstar", register_address=16),
                    Static("wbstar_value", default_value=b"\x42\x42\x42\x42"),
                ),
                pad_child_data=True,
                key_file_name="test_key.nky",
            ),
        ),
    )

    session.connect(playground_request)

    session.fuzz(self._test_case_name)


def fuzz_log_playground(self, session_kwargs: dict = {}):
    """Fuzzer for manually fuzzing or testing stuff."""

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register16": {
            "crash_if_differs_from_default": "yes",
            "log_transmitted_if_crashed": "playground_request.fuzzed_wbstar_value",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
        )
    )

    playground_request = Request(
        name="playground_request",
        children=(
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
            NOP(2),
            Type1WritePacket(name="write_to_wbstar", register_address=16),
            BitstreamWord(
                name="fuzzed_wbstar_value",
                static_bits=0x00000011,
                fuzzing_mask=0xFC000000,
            ),
            NOP(2),
        ),
    )

    session.connect(playground_request)

    session.fuzz(self._test_case_name)
