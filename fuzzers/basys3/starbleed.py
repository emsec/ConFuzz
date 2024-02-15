from boofuzz.blocks import Request
from boofuzz.sessions import Session
from src.models import FuzzPosition
from src.primitives import FuzzedBitstream

"""Fuzzes an encrypted bitstream to find the Starbleed bug.

https://www.usenix.org/conference/usenixsecurity20/presentation/ender
"""


def fuzz_starbleed(self, session_kwargs: dict = {}):
    """Mutate the given encrypted bitstream so that the Starbleed bug is found.

    The fuzzing mask mutates all bits of the packet header except the reserved bits.
    This mask is XORed to 40 words of the specified bitstream starting at the word after the sync word.

    The encrypted fabric of the specified bitsteam contains the words "F0 0D F0 0D", "BE EF BE EF", or "DE AD C0 DE".
    Hence, a crash is logged if any of these words occur in any register.
    Further, a crash is logged if the FDRO register is not zero,
    which should never be the case when loading an encrypted bitstream.
    """

    session = Session(**session_kwargs)

    custom_register_settings = {
        "DEFAULT": {
            "crash_if_differs_from_default": "no",
            "crash_if_equal_to": "F0 0D F0 0D, BE EF BE EF, DE AD C0 DE",
        },
        "register0": {
            # Overwrite the default crash setting from the default_register_settings.ini.
            "crash_if_equal_to": "F0 0D F0 0D, BE EF BE EF, DE AD C0 DE",
        },
        "register3": {
            # The FDRO register should only return zeros because encryption is enabled.
            "crash_if_differs_from_default": "yes",
            "crash_if_equal_to": "",
        },
        "register5": {
            # Overwrite the default crash setting from the default_register_settings.ini.
            "crash_if_not_equal_to": "",
        },
    }

    session.add_target(
        self._get_target(
            session._fuzz_data_logger,
            custom_register_settings=custom_register_settings,
            sync_after_restart=False,
            sync_after_fuzz=True,
        )
    )

    starbleed_request = Request(
        name="starbleed_request",
        children=(
            FuzzedBitstream(
                name="starbleed_bitstream",
                file_name="write_fdri_bbram_test_key.bit",
                fuzzing_mask=0xF803E7FF,
                fuzzing_position=FuzzPosition(index_start=4, word_count=40),
            )
        ),
    )

    session.connect(starbleed_request)

    session.fuzz(self._test_case_name)
