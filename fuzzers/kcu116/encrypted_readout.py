from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.constants import CONSTANTS
from src.primitives import (
    NOP,
    BitstreamWord,
    EncryptedXGHashUltraScaleBlock,
    SyncWord,
    Type1WritePacket,
    Type2WritePacket,
)

"""Fuzzes multiple registers and searches for encrypted content."""


def fuzz_encrypted_readout(self, session_kwargs: dict = {}):
    """Write three encrypted frames to the fabric and afterward fuzz the CTL0, CTL1, and unknown register 23.

    The CTL0 and CTL1 register are fuzzed with separated masks to reduce the number of test cases.
    For the same reason only single bits are set in the unknown register 23.

    Strategy:
    1.) Write three encrypted frames consisting of recognizable values.
    2.) Resync with the configuration engine which is always necessary after an encrypted block.
    3.) Fuzz the CTL0, CTL1, and unknown register 23.
    4.) Crash if any register contains one of the encrypted values or if the FDRO register is not zero,
        which should never be the case when loading an encrypted bitsteam.
    """

    session = Session(**session_kwargs, start_depth=2)

    custom_register_settings = {
        "DEFAULT": {
            "crash_if_differs_from_default": "no",
            "crash_if_equal_to": "F0 0D F0 0D, BE EF BE EF, DE AD C0 DE",
        },
        "register0": {
            # Overwrite the default crash setting from the default_register_settings.ini.
            "crash_if_equal_to": "F0 0D F0 0D, BE EF BE EF, DE AD C0 DE"
        },
        "register3": {
            # The FDRO register should only return zeros because encryption is enabled.
            "crash_if_differs_from_default": "yes",
            "crash_if_equal_to": "",
        },
        "register5": {
            # Overwrite the default crash setting from the default_register_settings.ini.
            "crash_if_not_equal_to": ""
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
            sync_after_fuzz=True,
        )
    )

    encrypted_readout_request = Request(
        name="encrypted_readout_request",
        children=(
            EncryptedXGHashUltraScaleBlock(
                name="encrypted_block",
                children=(
                    Type1WritePacket(name="write_to_idcode", register_address=12),
                    Static(
                        name="idcode_value",
                        default_value=CONSTANTS.BOARD_CONSTANTS.DEVICE_IDCODE,
                    ),
                    Type1WritePacket(name="write_to_far", register_address=1),
                    Static(name="far_value", default_value=b"\x00\x00\x00\x00"),
                    Type1WritePacket(name="write_to_cmd", register_address=4),
                    Static(name="wcfg_code", default_value=b"\x00\x00\x00\x01"),
                    Type1WritePacket(
                        name="write_to_fdri", register_address=2, word_count=0
                    ),
                    Type2WritePacket(
                        name="write_to_fdri_type_2",
                        word_count=3 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                    ),
                    Static(
                        name="fdri_value_1",
                        default_value=b"\xf0\x0d\xf0\x0d"
                        * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                    ),
                    Static(
                        name="fdri_value_2",
                        default_value=b"\xbe\xef\xbe\xef"
                        * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                    ),
                    Static(
                        name="fdri_value_3",
                        default_value=b"\xde\xad\xc0\xde"
                        * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                    ),
                ),
                key_file_name="test_key.nky",
            ),
            SyncWord(),
            NOP(),
            Type1WritePacket(name="write_to_ctl0", register_address=4),
            BitstreamWord(
                name="fuzzed_ctl0_value",
                static_bits=0x00000000,
                fuzzing_mask=[
                    0xFF000000,
                    0x00FF0000,
                    0x0000FF00,
                    0x000000FF,
                ],
            ),
            NOP(2),
            Type1WritePacket(name="write_to_ctl1", register_address=24),
            BitstreamWord(
                name="fuzzed_ctl1_value",
                static_bits=0x00000000,
                fuzzing_mask=[
                    0xF0000000,
                    0x0F000000,
                    0x00F00000,
                    0x000F0000,
                    0x0000F000,
                    0x00000F00,
                    0x000000F0,
                    0x0000000F,
                ],
            ),
            NOP(2),
            Type1WritePacket(name="write_to_unknown_register_23", register_address=23),
            BitstreamWord(
                name="fuzzed_unknown_register_23_value",
                static_bits=0x00000000,
                fuzzing_mask=0x00000000,
                fuzz_values=[1 << i for i in range(32)],
            ),
            NOP(2),
        ),
    )

    session.connect(encrypted_readout_request)

    session.fuzz(self._test_case_name)
