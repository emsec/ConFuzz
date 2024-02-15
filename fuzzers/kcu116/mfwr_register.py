from fuzzers.default_register_fuzzer import _default_register_fuzzer

"""Fuzzes the MFWR register.

https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
page 171
"""


def fuzz_mfwr_register(self, session_kwargs: dict = {}):
    """Use the default register fuzzer to fuzz the MFWR register."""

    _default_register_fuzzer(self, 10, session_kwargs)
