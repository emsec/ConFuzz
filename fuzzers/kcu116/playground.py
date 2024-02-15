from boofuzz.blocks import Request
from boofuzz.primitives import Static
from boofuzz.sessions import Session
from src.constants import CONSTANTS
from src.models import AESKey, UltraScaleKeyFile
from src.primitives import *

"""Fuzzer for manually fuzzing or testing stuff."""


def fuzz_playground(self, session_kwargs: dict = {}):
    """Fuzzer for manually fuzzing or testing stuff."""

    session = Session(**session_kwargs)

    custom_register_settings = {
        "register0": {
            "crash_if_equal_to": "",
            "crash_if_not_equal_to": "00 00 00 00",
        },
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
            "crash_if_not_equal_to": "12 90 7D FE",
        },
        "register21": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 00",
        },
        "register22": {
            "crash_if_differs_from_default": "no",
            "crash_if_not_equal_to": "00 00 00 01",
        },
    }

    with open(
        os.path.join(CONSTANTS.BITSTREAMS_DIR, "leds_rsa_only_fabric.bit"), "rb"
    ) as f:
        fabric_data = f.read()

    session.add_target(
        target=self._get_target(
            fuzz_data_logger=session._fuzz_data_logger,
            runtest=len(fabric_data),
            jstart=True,
            custom_register_settings=custom_register_settings,
            sync_after_fuzz=True,
        )
    )

    # Values from test_key_rsa.nky
    device = "xcku5p"
    encrypt_key_select = "bbram"
    rsa_public_key_modulus = "00:ba:d1:d1:63:a8:19:23:fd:27:54:ea:d0:e0:d7:e3:c7:f7:ce:56:e7:4c:50:5b:8b:21:d0:0d:be:0d:23:02:ef:9c:e4:4d:a5:b0:71:b8:90:08:b2:ce:11:69:5a:f0:64:22:27:22:03:ad:a5:7b:7e:4a:4a:82:a7:26:2e:3c:da:28:dc:38:c1:9b:dc:71:d2:b8:75:0c:e5:04:52:4d:3c:4a:7f:a3:6b:d3:b5:27:e3:31:93:bc:f4:fa:98:56:38:23:4a:16:06:5a:41:44:43:ab:29:55:39:1b:67:74:29:3b:66:17:89:59:13:8a:9a:f5:34:29:5e:ac:7a:3b:d7:4c:ac:45:55:7f:ea:65:e2:a9:cc:27:06:db:b8:c4:5f:e5:60:c9:25:3b:dd:32:99:69:9e:3a:3e:75:c3:c1:ce:dd:da:49:ae:13:cb:be:0f:93:ab:b7:17:51:33:cf:37:9a:0a:87:24:a4:70:f6:75:7b:ff:6f:a3:45:da:74:de:3d:5c:f3:ef:fe:45:9c:82:4a:3a:9a:e2:2e:45:43:d5:4c:e2:12:57:bd:65:d5:4b:0e:bc:a1:24:c8:36:d2:f9:83:4c:26:0f:22:73:f6:6e:05:01:82:d9:1a:25:df:e8:05:a4:c4:b2:f9:e9:fe:17:34:fb:d1:5f:fa:f4:db:4b"
    rsa_public_key_digest = "011D39BAD5107DB6678AF67FE87AA9B86B5D163CBBF1547D7AC435A9CBB5CB5731A3ADA2E8A99849D6628D39D6D52376"
    key = "fb0ed5a1ca4e5e797f35eae370fa889881f0d96e541fd54dff28b8fdcae9fbf8"
    iv = "f1b69808f6c303f388a5353e"
    length = "00000000"

    playground_request = Request(
        name="playground_request",
        children=(
            BitstreamWord(
                name="fuzzed_dummy_value",
                static_bits=0x20000000,
                fuzzing_mask=0x00000000,
            ),
            EncryptedRSABlockUltraScale(
                name="encrypted_block",
                children=(Static(default_value=fabric_data)),
                # key_file_name="test_key_rsa.nky",
                key_file=UltraScaleKeyFile(
                    device=device,
                    encrypt_key_select=encrypt_key_select.upper(),
                    rsa_public_key_modulus=bytes.fromhex(
                        rsa_public_key_modulus.replace(":", "")[2:]
                    ),
                    rsa_public_key_digest=bytes.fromhex(rsa_public_key_digest),
                    aes_keys=[
                        AESKey(
                            key=bytes.fromhex(key),
                            iv=bytes.fromhex(iv),
                            length=bytes.fromhex(length),
                        )
                    ],
                ),
                rsa_private_key_file_name="privateKey.pem",
            ),
        ),
    )

    session.connect(playground_request)

    session.fuzz(self._test_case_name)
