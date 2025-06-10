from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.constants import CONSTANTS
from src.primitives import *

"""Fuzzes parts of encrypted and plaintext RSA bitstreams."""


def fuzz_plaintext_rsa_bitstream(self, session_kwargs: dict = {}):
    """Fuzz a plaintext RSA bitstream by inserting multiple writes to the CMD register.

    Strategy:
    1. Disable ConfigFallback in the CTL0 register.
    2. Send a PlaintextRSABlockUltraScale block with the original RSA header and footer.
    3. Use a wrong private key to generate the RSA signature.
    4. Activate the test mode to use short RSA bitstreams to heavily improve performance.
    5. Insert three writes at the end of the bitstream to the CMD register and fuzz the written values in parallel.
    6. Crash if there is some indication that the device started correctly despite the wrong signature.
    """

    session = Session(start_depth=3, **session_kwargs)

    custom_register_settings = {
        "DEFAULT": {"probe": "no"},
        "register7": {
            "probe": "yes",
            "crash_if_differs_from_default": "no",
            # Only crash if BIT13_DONE_INTERNAL_SIGNAL_STATUS or BIT14_DONE_PIN is set.
            "crash_if_some_bits_in_mask_set": "00 00 C0 00",
        },
        "register22": {
            "probe": "yes",
            "crash_if_differs_from_default": "no",
            # Only crash if just BIT00_STATUS_VALID_0 is set.
            "crash_if_equal_to": "00 00 00 01",
        },
    }

    session.add_target(
        target=self._get_target(
            fuzz_data_logger=session._fuzz_data_logger,
            runtest=15429072,  # length of bitstreams/kcu116/leds_rsa_only_fabric.bit
            jstart=True,
            custom_register_settings=custom_register_settings,
            sync_after_fuzz=True,
        )
    )

    plaintext_rsa_bitstream_request = Request(
        name="plaintext_rsa_bitstream_request",
        children=(
            # Disable ConfigFallback in the CTL0 register.
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x05\x01"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x05\x01"),
            NOP(3),
            PlaintextRSABlockUltraScale(
                name="plaintext_rsa_block",
                children=(
                    # Original RSA header, except ConfigFallback is disabled in the CTL0 register.
                    NOP(),
                    Type1WritePacket(name="write_to_mask_1", register_address=6),
                    Static(name="mask_value_1", default_value=b"\xff\xff\xff\xff"),
                    Type1WritePacket(name="write_to_ctl0_1", register_address=5),
                    Static(name="ctl0_value_1", default_value=b"\x00\x00\x05\x01"),
                    Type1WritePacket(name="write_to_mask_2", register_address=6),
                    Static(name="mask_value_2", default_value=b"\xff\xf3\xff\xff"),
                    Type1WritePacket(name="write_to_ctl1", register_address=24),
                    Static(name="ctl1_value", default_value=b"\x00\x00\x00\x00"),
                    NOP(8),
                    Type1WritePacket(name="write_to_far_1", register_address=1),
                    Static(name="far_value_1", default_value=b"\x00\x00\x00\x00"),
                    Type1WritePacket(name="write_to_cmd_1", register_address=4),
                    Static(name="wcfg_code", default_value=b"\x00\x00\x00\x01"),
                    NOP(11),
                    # 25 or 26 frames of fabric data for plaintext test mode RSA bitstreams.
                    Static(
                        name="fabric_data",
                        default_value=b"\xde\xad\xc0\xde"
                        * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
                        * 25,
                    ),
                    # Original RSA footer, except ConfigFallback is disabled in the CTL0 register.
                    NOP(2),
                    Type1WritePacket(name="write_to_cmd_2", register_address=4),
                    Static(name="grestore_code", default_value=b"\x00\x00\x00\x0a"),
                    NOP(2),
                    Type1WritePacket(name="write_to_cmd_3", register_address=4),
                    Static(name="dghigh_code", default_value=b"\x00\x00\x00\x03"),
                    NOP(20),
                    Type1WritePacket(name="write_to_cmd_4", register_address=4),
                    Static(name="start_code", default_value=b"\x00\x00\x00\x05"),
                    NOP(),
                    Type1WritePacket(name="write_to_far_2", register_address=1),
                    Static(name="far_value_2", default_value=b"\x07\xfc\x00\x00"),
                    Type1WritePacket(name="write_to_mask_3", register_address=6),
                    Static(name="mask_value_3", default_value=b"\x00\x00\x05\x01"),
                    Type1WritePacket(name="write_to_ctl0_2", register_address=5),
                    Static(name="ctl0_value_2", default_value=b"\x00\x00\x05\x01"),
                    NOP(2),
                    Type1WritePacket(name="write_to_cmd_5", register_address=4),
                    Static(name="desync_code", default_value=b"\x00\x00\x00\x0d"),
                    NOP(119),
                ),
                children_contain_header_and_footer=True,
                key_file_name="test_key_rsa.nky",
                rsa_private_key_file_name="privateKey_wrong.pem",
                test_mode=True,
                rdw_go=False,
            ),
            Type1WritePacket(name="write_to_cmd_1", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value_1",
                static_bits=0x00000000,
                fuzzing_mask=0x0000001F,
            ),
            NOP(3),
            Type1WritePacket(name="write_to_cmd_2", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value_2",
                static_bits=0x00000000,
                fuzzing_mask=0x0000001F,
            ),
            NOP(3),
            Type1WritePacket(name="write_to_cmd_3", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value_3",
                static_bits=0x00000000,
                fuzzing_mask=0x0000001F,
            ),
            NOP(3),
            Type1WritePacket(name="write_to_cmd", register_address=4),
            Static(name="rdw_go_code", default_value=b"\x00\x00\x00\x16"),
            NOP(3),
        ),
    )

    session.connect(plaintext_rsa_bitstream_request)

    session.fuzz(self._test_case_name)


def fuzz_encrypted_rsa_bitstream(self, session_kwargs: dict = {}):
    """Fuzz a encrypted RSA bitstream by inserting multiple writes to the CMD register.

    Strategy:
    1. Disable ConfigFallback in the CTL0 register.
    2. Send a Encrypted EncryptedRSABlockUltraScale with the original RSA header and footer.
    3. Use a wrong private key to generate the RSA signature.
    4. Activate the test mode to use short RSA bitstreams to heavily improve performance.
    5. Insert three writes at the end of the bitstream to the CMD register and fuzz the written values in parallel.
    6. Crash if there is some indication that the device started correctly despite the wrong signature.
    """

    session = Session(start_depth=3, **session_kwargs)

    custom_register_settings = {
        "DEFAULT": {"probe": "no"},
        "register7": {
            "probe": "yes",
            "crash_if_differs_from_default": "no",
            # Only crash if BIT13_DONE_INTERNAL_SIGNAL_STATUS or BIT14_DONE_PIN is set.
            "crash_if_some_bits_in_mask_set": "00 00 C0 00",
        },
        "register22": {
            "probe": "yes",
            "crash_if_differs_from_default": "no",
            # Only crash if just BIT00_STATUS_VALID_0 is set.
            "crash_if_equal_to": "00 00 00 01",
        },
    }

    session.add_target(
        target=self._get_target(
            fuzz_data_logger=session._fuzz_data_logger,
            runtest=15429072,  # length of leds_rsa_only_fabric.bit
            jstart=True,
            custom_register_settings=custom_register_settings,
            sync_after_fuzz=True,
        )
    )

    encrypted_rsa_bitstream_request = Request(
        name="encrypted_rsa_bitstream_request",
        children=(
            # Disable ConfigFallback and set the DEC bit in the CTL0 register.
            Type1WritePacket(name="write_to_mask", register_address=6),
            Static(name="mask_value", default_value=b"\x00\x00\x05\x41"),
            Type1WritePacket(name="write_to_ctl0", register_address=5),
            Static(name="ctl0_value", default_value=b"\x00\x00\x05\x41"),
            NOP(3),
            EncryptedRSABlockUltraScale(
                name="encrypted_rsa_block",
                children=(
                    # Original RSA header, except ConfigFallback is disabled in the CTL0 register.
                    NOP(),
                    Type1WritePacket(name="write_to_mask_1", register_address=6),
                    Static(name="mask_value_1", default_value=b"\xff\xff\xff\xff"),
                    Type1WritePacket(name="write_to_ctl0_1", register_address=5),
                    Static(name="ctl0_value_1", default_value=b"\x00\x00\x05\x41"),
                    Type1WritePacket(name="write_to_mask_2", register_address=6),
                    Static(name="mask_value_2", default_value=b"\xff\xf3\xff\xff"),
                    Type1WritePacket(name="write_to_ctl1", register_address=24),
                    Static(name="ctl1_value", default_value=b"\x00\x00\x00\x00"),
                    NOP(8),
                    Type1WritePacket(name="write_to_far_1", register_address=1),
                    Static(name="far_value_1", default_value=b"\x00\x00\x00\x00"),
                    Type1WritePacket(name="write_to_cmd_1", register_address=4),
                    Static(name="wcfg_code", default_value=b"\x00\x00\x00\x01"),
                    NOP(11),
                    # 24 frames of fabric data for encrypted test mode RSA bitstreams.
                    Static(
                        name="fabric_data",
                        default_value=b"\xde\xad\xc0\xde"
                        * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
                        * 24,
                    ),
                    # Original RSA footer, except ConfigFallback is disabled in the CTL0 register.
                    NOP(2),
                    Type1WritePacket(name="write_to_cmd_2", register_address=4),
                    Static(name="grestore_code", default_value=b"\x00\x00\x00\x0a"),
                    NOP(2),
                    Type1WritePacket(name="write_to_cmd_3", register_address=4),
                    Static(name="dghigh_code", default_value=b"\x00\x00\x00\x03"),
                    NOP(20),
                    Type1WritePacket(name="write_to_cmd_4", register_address=4),
                    Static(name="start_code", default_value=b"\x00\x00\x00\x05"),
                    NOP(),
                    Type1WritePacket(name="write_to_far_2", register_address=1),
                    Static(name="far_value_2", default_value=b"\x07\xfc\x00\x00"),
                    Type1WritePacket(name="write_to_mask_3", register_address=6),
                    Static(name="mask_value_3", default_value=b"\x00\x00\x05\x41"),
                    Type1WritePacket(name="write_to_ctl0_2", register_address=5),
                    Static(name="ctl0_value_2", default_value=b"\x00\x00\x05\x41"),
                    NOP(2),
                    Type1WritePacket(name="write_to_cmd_5", register_address=4),
                    Static(name="desync_code", default_value=b"\x00\x00\x00\x0d"),
                    NOP(119),
                ),
                children_contain_header_and_footer=True,
                key_file_name="test_key_rsa.nky",
                rsa_private_key_file_name="privateKey_wrong.pem",
                enable_encryption=False,
                test_mode=True,
                rdw_go=False,
            ),
            Type1WritePacket(name="write_to_cmd_1", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value_1",
                static_bits=0x00000000,
                fuzzing_mask=0x0000001F,
            ),
            NOP(3),
            Type1WritePacket(name="write_to_cmd_2", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value_2",
                static_bits=0x00000000,
                fuzzing_mask=0x0000001F,
            ),
            NOP(3),
            Type1WritePacket(name="write_to_cmd_3", register_address=4),
            BitstreamWord(
                name="fuzzed_cmd_value_3",
                static_bits=0x00000000,
                fuzzing_mask=0x0000001F,
            ),
            NOP(3),
            Type1WritePacket(name="write_to_cmd", register_address=4),
            Static(name="rdw_go_code", default_value=b"\x00\x00\x00\x16"),
            NOP(3),
        ),
    )

    session.connect(encrypted_rsa_bitstream_request)

    session.fuzz(self._test_case_name)
