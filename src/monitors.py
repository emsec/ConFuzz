import configparser
import os
import time

from boofuzz.exception import BoofuzzError
from boofuzz.fuzz_logger import FuzzLogger
from boofuzz.helpers import hex_str
from boofuzz.monitors import BaseMonitor
from boofuzz.primitives import Static

from .connections import OpenOCDConnection
from .constants import CONSTANTS
from .models import (
    Bitstream,
    ConfigurationRegister,
    RegisterCrashSettings,
    RegisterData,
    RegisterInfo,
    RegisterName,
)
from .primitives import (
    NOP,
    SyncWord,
    Type1ReadPacket,
    Type1WritePacket,
    Type2ReadPacket,
)


class OpenOCDMonitor(BaseMonitor):
    """Extend boofuzz by adding a BaseMonitor that can be configured to watch a device via OpenOCD."""

    def __init__(
        self,
        fuzz_data_logger: FuzzLogger,
        openocd_connection: OpenOCDConnection,
        register_settings: str = None,
        custom_register_settings: dict = {},
        sleep_after_restart: float = None,
        wait_for_configuration: bool = False,
        sync_after_restart: bool = True,
        sleep_after_fuzz: float = 0.0,
        sync_after_fuzz: bool = False,
        try_auto_sync_after_fuzz: bool = False,
    ):
        self._fuzz_data_logger = fuzz_data_logger
        self._openocd_connection = openocd_connection

        config = configparser.ConfigParser()
        config.read(
            os.path.join(
                CONSTANTS.REGISTER_SETTINGS_BASE_DIR,
                CONSTANTS.REGISTER_SETTINGS_DEFAULT_INI,
            )
        )
        # The most recently added configuration has the highest priority,
        # this allows us to overwrite existing keys.
        # Other keys from the previous configuration keep existing.
        config.read(
            os.path.join(
                CONSTANTS.REGISTER_SETTINGS_DIR, CONSTANTS.REGISTER_SETTINGS_DEFAULT_INI
            )
        )
        if register_settings:
            config.read(
                os.path.join(CONSTANTS.REGISTER_SETTINGS_DIR, register_settings)
            )
        config.read_dict(custom_register_settings)

        if sleep_after_restart is None:
            if wait_for_configuration:
                self._sleep_after_restart = (
                    CONSTANTS.BOARD_CONSTANTS.RESTART_DELAY_CONFIGURATION
                )
            else:
                self._sleep_after_restart = CONSTANTS.BOARD_CONSTANTS.RESTART_DELAY
        else:
            if sleep_after_restart < 0:
                raise ValueError("sleep_after_restart has to be >= 0")
            self._sleep_after_restart = sleep_after_restart
        self._sync_after_restart = sync_after_restart

        restart_cmds = [
            # https://sourceforge.net/p/openocd/code/ci/master/tree/tcl/cpld/xilinx-xc7.cfg
            # https://sourceforge.net/p/openocd/code/ci/master/tree/tcl/cpld/xilinx-xcu.cfg
            f"{CONSTANTS.BOARD_CONSTANTS.OPENOCD_TAP_NAME}_program $tap",
            # Wait until the restart is completed.
            f"after {self._sleep_after_restart * 1000}",
        ]

        if self._sync_after_restart:
            # Send the sync word and prevent the output using the list command.
            # See src/connections.py for more detailed explanations.
            restart_cmds.append("irscan $tap 0x05; drscan $tap 32 0x66AA9955; list;")

        self._restart_cmds = "; ".join(restart_cmds)

        if sleep_after_fuzz < 0:
            raise ValueError("sleep_after_fuzz has to be >= 0")
        self._sleep_after_fuzz = sleep_after_fuzz
        self._sync_after_fuzz = sync_after_fuzz
        self._try_auto_sync_after_fuzz = try_auto_sync_after_fuzz

        self._state: list[ConfigurationRegister] = []
        self._fuzz_response: ConfigurationRegister = None
        self._probe_bitstreams: list[Bitstream] = [Bitstream(SyncWord().render())]

        for section in config.sections():
            # Only consider registers that are configured to be probed.
            if config[section].getboolean("probe"):
                address = config[section].getint("address")
                name = RegisterName(config[section].get("name"))
                length = config[section].getint("length")

                register = ConfigurationRegister(
                    RegisterInfo(
                        address,
                        name,
                        length,
                        config[section].getboolean("display_data_as_frames"),
                        config[section].get("log_transmitted_if_crashed"),
                        config[section].get("log_transmitted_if_not_crashed"),
                    ),
                    RegisterCrashSettings(
                        config[section].getboolean("crash_if_differs_from_default"),
                        config[section].get("crash_if_equal_to"),
                        config[section].get("crash_if_not_equal_to"),
                        config[section].get("crash_if_some_bits_in_mask_set"),
                        config[section].get("crash_if_some_bits_in_mask_not_set"),
                        config[section].get("crash_if_all_bits_in_mask_set"),
                        config[section].get("crash_if_all_bits_in_mask_not_set"),
                        config[section].get("crash_if_not_equal_to_transmitted"),
                    ),
                    RegisterData(),
                )

                if section.startswith("register"):
                    self._state.append(register)

                    # Additional commands are needed to read from FDRO register.
                    if section == "register3":
                        # https://docs.xilinx.com/r/en-US/ug470_7Series_Config
                        # Table 6-5, page 125, readback command sequence from step 7
                        self._probe_bitstreams.append(
                            Bitstream(
                                b"".join(
                                    primitive.render()
                                    for primitive in [
                                        Type1WritePacket(
                                            name="write_to_cmd", register_address=4
                                        ),
                                        Static(
                                            name="rcfg_code",
                                            default_value=b"\x00\x00\x00\x04",
                                        ),
                                        Type1WritePacket(
                                            name="write_to_far", register_address=1
                                        ),
                                        Static(
                                            name="far_value",
                                            default_value=bytes.fromhex(
                                                config[section].get("far_value")
                                            ),
                                        ),
                                        Type1ReadPacket(
                                            name="read_from_fdro",
                                            register_address=3,
                                            word_count=0,
                                        ),
                                        Type2ReadPacket(
                                            name="read_from_fdro_type_2",
                                            word_count=length // 32,
                                        ),
                                        NOP(2),
                                    ]
                                ),
                                response_length=length,
                            )
                        )
                    else:
                        # https://docs.xilinx.com/r/en-US/ug470_7Series_Config
                        # Table 6-4, page 124, readback command sequence from step 3
                        self._probe_bitstreams.append(
                            Bitstream(
                                b"".join(
                                    primitive.render()
                                    for primitive in [
                                        Type1ReadPacket(
                                            name=f"read_from_{name}",
                                            register_address=address,
                                            word_count=length // 32,
                                        ),
                                        NOP(2),
                                    ]
                                ),
                                response_length=length,
                            )
                        )
                elif section == "fuzz_response":
                    # There is no default value to compare against.
                    register.crash_settings.differs_from_default = False
                    self._fuzz_response = register

        self._state_length = len(self._state)

        self._current_test_case_crashes = 0
        self._fuzz_node_names = None
        self._current_mutation_context = None

        return

    def alive(self):
        self._fuzz_data_logger.log_info(
            f"Restart target so the device is in a clean state"
        )
        self.restart_target()

        self._fuzz_data_logger.log_info(
            "Save default values for all configuration registers that are configured to be probed"
        )
        self._probe_state(set_default_values=True)

        # Reset again because probing FDRO changes the state.
        self._fuzz_data_logger.log_info(
            "Restart target so the device is in a clean state"
        )
        self.restart_target()

        return True

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        # Delete the register data from the last fuzzing test case.
        for i in range(self._state_length):
            self._state[i].data.__init__()

        # Do the same for the fuzz response.
        if self._fuzz_response:
            self._fuzz_response.data.__init__()

        # Reset values for the current test case.
        self._current_test_case_crashes = 0
        self._fuzz_node_names = None
        self._current_mutation_context = None

        return

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        if self._sleep_after_fuzz:
            time.sleep(self._sleep_after_fuzz)

        if not self._sync_after_fuzz and self._try_auto_sync_after_fuzz:
            self._fuzz_data_logger.open_test_step("Try auto sync after fuzz")

            status_register_value = self._openocd_connection.send_bitstreams(
                [
                    Bitstream(
                        b"".join(
                            primitive.render()
                            for primitive in [
                                Type1ReadPacket(
                                    name="read_from_stat", register_address=7
                                ),
                                NOP(2),
                            ]
                        ),
                        response_length=32,
                    )
                ]
            )[0]

            if status_register_value == b"\x00\x00\x00\x00":
                self._fuzz_data_logger.log_info(
                    "Send sync word because status register is zero"
                )

                # The first probe bitstream is just the sync word.
                self._openocd_connection.send_bitstreams(self._probe_bitstreams[:1])
            else:
                self._fuzz_data_logger.log_info(
                    "No resync necessary because the status register is not zero"
                )

        self._probe_state()

        # Save all primitives of the current fuzz node and the current mutation context
        # to generate the current mutation of the primitive specified in the "not_equal_to_transmitted",
        # "log_transmitted_if_crashed", or "log_transmitted_if_not_crashed" setting.
        self._fuzz_node_names = session.fuzz_node.names
        self._current_mutation_context = session._current_mutation_context

        if session.last_recv and self._fuzz_response is not None:
            self._fuzz_response.data.current_value = session.last_recv
            self._current_test_case_crashes += self._detect_crashes_in_register(
                self._fuzz_response, session.results_path
            )

        for register in self._state:
            self._current_test_case_crashes += self._detect_crashes_in_register(
                register, session.results_path
            )

        if self._current_test_case_crashes > 0:
            return False
        else:
            return True

    def post_start_target(self, target=None, fuzz_data_logger=None, session=None):
        # Not needed for now.
        return

    def retrieve_data(self):
        # Not needed for now.
        return None

    def set_options(self, *args, **kwargs):
        # Not needed for now.
        return

    def get_crash_synopsis(self):
        # Only return the number of crashes for the current test case
        # because all relevant information is already logged.

        return f"{self._current_test_case_crashes} crashes"

    def start_target(self):
        # Not necessary when using OpenOCD.
        return True

    def stop_target(self):
        # Not necessary when using OpenOCD.
        return True

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        self._openocd_connection.send_command(self._restart_cmds)

        return True

    def _probe_state(self, set_default_values: bool = False) -> None:
        """Save the values of all configuration registers that are configured to be probed."""

        if not set_default_values:
            self._fuzz_data_logger.open_test_step("Probe state")

        if self._state_length == 0:
            self._fuzz_data_logger.log_info("No registers to probe")
            return

        if not set_default_values and self._sync_after_fuzz:
            probe_bitstreams_responses = self._openocd_connection.send_bitstreams(
                self._probe_bitstreams
            )
        else:
            # Skip the first probe bitstream which is just the sync word.
            probe_bitstreams_responses = self._openocd_connection.send_bitstreams(
                self._probe_bitstreams[1:]
            )

        if set_default_values:
            log_message = "Default values, crash settings, and log settings"

            for i in range(self._state_length):
                self._state[i].info.default_value = probe_bitstreams_responses[i]

                log_message += (
                    f"\n{self._state[i].info.get_id()} - {hex_str(self._state[i].info.default_value[:16])}"
                    f'{" ... (truncated to 128 bit)" if self._state[i].info.length > 16 else ""}\n'
                    f"{self._state[i].display_data(self._state[i].info.default_value)}"
                    f"{self._state[i].crash_settings}\n"
                    f"log_transmitted_if_crashed: {self._state[i].info.log_transmitted_if_crashed}\n"
                    f"log_transmitted_if_not_crashed: {self._state[i].info.log_transmitted_if_not_crashed}\n"
                )

            self._fuzz_data_logger.log_info(log_message)
        else:
            for i in range(self._state_length):
                self._state[i].data.current_value = probe_bitstreams_responses[i]

    def _detect_crashes_in_register(
        self, register: ConfigurationRegister, results_path: str
    ) -> int:
        """Check if certain conditions are met so that the given register should be marked as crashed."""

        crashes = 0

        self._fuzz_data_logger.open_test_step(f"Check {register.info.get_id()}")
        self._fuzz_data_logger.log_info(
            f"Current value: {hex_str(register.data.current_value[:16])}"
            f'{" (truncated to 128 bit)" if register.info.length > 16 else ""}\n\n'
            f"{register.display_data(register.data.current_value)}"
        )

        if register.crash_settings.differs_from_default and register.info.default_value:
            self._fuzz_data_logger.log_check(
                f"Differs from default value: {hex_str(register.info.default_value)}?"
            )
            if register.data.current_value != register.info.default_value:
                register.data.differs_from_default = True
                crashes += 1
                self._fuzz_data_logger.log_info("Crash - default value is different")

        if register.crash_settings.equal_to:
            self._fuzz_data_logger.log_check(
                f'Equal to: {", ".join(hex_str(value) for value in register.crash_settings.equal_to)}?'
            )
            if register.data.current_value in register.crash_settings.equal_to:
                register.data.equal_to = True
                crashes += 1
                self._fuzz_data_logger.log_info(f"Crash - equal to")

        if register.crash_settings.not_equal_to:
            self._fuzz_data_logger.log_check(
                f'Not equal to: {", ".join(hex_str(value) for value in register.crash_settings.not_equal_to)}?'
            )
            if register.data.current_value not in register.crash_settings.not_equal_to:
                register.data.not_equal_to = True
                crashes += 1
                self._fuzz_data_logger.log_info(f"Crash - not equal to")

        if register.crash_settings.some_bits_in_mask_set:
            self._fuzz_data_logger.log_check(
                f"Some bits in mask set: {hex_str(register.crash_settings.some_bits_in_mask_set)}?"
            )

            for i in range(register.info.length):
                if (
                    register.data.current_value[i]
                    & register.crash_settings.some_bits_in_mask_set[i]
                    != 0
                ):
                    register.data.some_bits_in_mask_set = True
                    crashes += 1
                    self._fuzz_data_logger.log_info(f"Crash - some bits in mask set")
                    break

        if register.crash_settings.some_bits_in_mask_not_set:
            self._fuzz_data_logger.log_check(
                f"Some bits in mask not set: {hex_str(register.crash_settings.some_bits_in_mask_not_set)}?"
            )

            for i in range(register.info.length):
                if (
                    register.data.current_value[i]
                    & register.crash_settings.some_bits_in_mask_not_set[i]
                    != register.crash_settings.some_bits_in_mask_not_set[i]
                ):
                    register.data.some_bits_in_mask_not_set = True
                    crashes += 1
                    self._fuzz_data_logger.log_info(
                        f"Crash - some bits in mask not set"
                    )
                    break

        if register.crash_settings.all_bits_in_mask_set:
            self._fuzz_data_logger.log_check(
                f"All bits in mask set: {hex_str(register.crash_settings.all_bits_in_mask_set)}?"
            )

            if all(
                value_byte & mask_byte == mask_byte
                for value_byte, mask_byte in zip(
                    register.data.current_value,
                    register.crash_settings.all_bits_in_mask_set,
                )
            ):
                register.data.all_bits_in_mask_set = True
                crashes += 1
                self._fuzz_data_logger.log_info(f"Crash - all bits in mask set")

        if register.crash_settings.all_bits_in_mask_not_set:
            self._fuzz_data_logger.log_check(
                f"All bits in mask not set: {hex_str(register.crash_settings.all_bits_in_mask_not_set)}?"
            )

            if all(
                ~value_byte & mask_byte == mask_byte
                for value_byte, mask_byte in zip(
                    register.data.current_value,
                    register.crash_settings.all_bits_in_mask_not_set,
                )
            ):
                register.data.all_bits_in_mask_not_set = True
                crashes += 1
                self._fuzz_data_logger.log_info(f"Crash - all bits in mask not set")

        if register.crash_settings.not_equal_to_transmitted:
            if (
                register.crash_settings.not_equal_to_transmitted
                not in self._fuzz_node_names
            ):
                raise BoofuzzError(
                    f'not_equal_to_transmitted error: primitive "{register.crash_settings.not_equal_to_transmitted}" does not exist'
                )

            # Get the primitive specified with the "not_equal_to_transmitted" setting.
            specified_primitive = self._fuzz_node_names[
                register.crash_settings.not_equal_to_transmitted
            ]
            # Regenerate the current mutation of this primitive to compare it to the current register value.
            not_equal_to_transmitted = specified_primitive.render(
                self._current_mutation_context
            )

            self._fuzz_data_logger.log_check(
                f"Not equal to transmitted: {hex_str(not_equal_to_transmitted)}?"
            )

            if register.data.current_value != not_equal_to_transmitted:
                register.data.not_equal_to_transmitted = True
                crashes += 1
                self._fuzz_data_logger.log_info(f"Crash - not equal to transmitted")

        log_message = f"{crashes} crashes in {register.info.get_id()}\n"

        value_to_log = None
        log_file_name = None

        if crashes > 0:
            self._fuzz_data_logger.log_fail(log_message)

            if register.info.log_transmitted_if_crashed:
                if (
                    register.info.log_transmitted_if_crashed
                    not in self._fuzz_node_names
                ):
                    raise BoofuzzError(
                        f'log_transmitted_if_crashed error: primitive "{register.info.log_transmitted_if_crashed}" does not exist'
                    )

                # Get the primitive specified with the "log_transmitted_if_crashed" setting.
                specified_primitive = self._fuzz_node_names[
                    register.info.log_transmitted_if_crashed
                ]
                # Regenerate the current mutation of this primitive to compare it to the current register value.
                value_to_log = specified_primitive.render(
                    self._current_mutation_context
                )

                log_file_name = (
                    f"log_transmitted_if_crashed_{register.info.get_id()}.log"
                )
        else:
            self._fuzz_data_logger.log_pass(log_message)

            if register.info.log_transmitted_if_not_crashed:
                if (
                    register.info.log_transmitted_if_not_crashed
                    not in self._fuzz_node_names
                ):
                    raise BoofuzzError(
                        f'log_transmitted_if_not_crashed error: primitive "{register.info.log_transmitted_if_not_crashed}" does not exist'
                    )

                # Get the primitive specified with the "log_transmitted_if_not_crashed" setting.
                specified_primitive = self._fuzz_node_names[
                    register.info.log_transmitted_if_not_crashed
                ]
                # Regenerate the current mutation of this primitive to compare it to the current register value.
                value_to_log = specified_primitive.render(
                    self._current_mutation_context
                )

                log_file_name = (
                    f"log_transmitted_if_not_crashed_{register.info.get_id()}.log"
                )

        if value_to_log and log_file_name:
            with open(os.path.join(results_path, log_file_name), "a") as f:
                f.write(
                    f"{hex_str(value_to_log)}\t\t"
                    f'{int.from_bytes(value_to_log, "big"):0{len(value_to_log) * 8}b}\t\t'
                    f"{self._fuzz_data_logger.most_recent_test_id}\n"
                )

        return crashes
