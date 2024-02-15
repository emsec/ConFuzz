import argparse

from boofuzz.connections import ITargetConnection
from boofuzz.fuzz_logger import FuzzLogger
from boofuzz.sessions import Target
from src.connections import OpenOCDConnection
from src.constants import CONSTANTS
from src.monitors import OpenOCDMonitor

# Store OpenOCD process in a global variable the process can be killed
# if the fuzzer finishes or exits with an exception.
openocd_process = None


class MainFuzzer:
    """Loads the correct constants, prepares command line dependent session arguments, and starts the fuzzer."""

    def __init__(
        self,
        fuzzer_name: str,
        board: str = CONSTANTS.BOARD,
        test_case_name: str = None,
        db_filename: str = None,
        index_start: int = None,
        index_end: int = None,
        register_settings: str = None,
        quiet: bool = False,
        slack_notification: bool = False,
        debug: bool = False,
        no_openocd_server: bool = False,
        openocd_port: int = CONSTANTS.OPENOCD_DEFAULT_PORT,
        openocd_bus_port: str = None,
        count_test_cases: bool = False,
    ) -> None:
        CONSTANTS.update_board(board)

        match CONSTANTS.BOARD:
            case "basys3":
                import fuzzers.basys3 as fuzzers
            case "kcu105":
                import fuzzers.kcu105 as fuzzers
            case "kcu116":
                import fuzzers.kcu116 as fuzzers
            case "xem8320":
                import fuzzers.xem8320 as fuzzers

        # test_case_name is used as argument to call session.fuzz() in the fuzzer.
        self._test_case_name = test_case_name
        self._register_settings = register_settings
        self._debug = debug
        self._no_openocd_server = no_openocd_server
        self._openocd_port = openocd_port
        self._openocd_bus_port = openocd_bus_port

        # Define default session_kwargs.
        # https://boofuzz.readthedocs.io/en/stable/source/Session.html
        # All session_kwargs can still be overwritten by individual fuzzers.
        session_kwargs = {
            # Restart the device after every test case to be in a clear state again.
            "restart_interval": 1,
            "crash_threshold_request": 128,
            "crash_threshold_element": 128,
            "reuse_target_connection": True,
            "fuzzer_name": fuzzer_name,
        }

        # Handle session keyword arguments that are dependent on command line arguments.
        if db_filename:
            session_kwargs["db_filename"] = db_filename
        if index_start:
            session_kwargs["index_start"] = index_start
        if index_end:
            session_kwargs["index_end"] = index_end
        if quiet:
            session_kwargs.update(
                {
                    # Only log to database.
                    "fuzz_loggers": [],
                    # Set web_port to None to disable the web app.
                    "web_port": None,
                    "keep_web_open": False,
                    "fuzz_db_keep_only_n_pass_cases": 3,
                }
            )
        session_kwargs["slack_notification"] = slack_notification
        session_kwargs["count_test_cases"] = count_test_cases

        getattr(fuzzers, f"fuzz_{fuzzer_name}")(self, session_kwargs)

    def _get_target(
        self,
        fuzz_data_logger: FuzzLogger,
        custom_connection: ITargetConnection = None,
        response_length: int = 0,
        runtest: int = 0,
        jstart: bool = False,
        custom_register_settings: dict = {},
        sleep_after_restart: float = None,
        wait_for_configuration: bool = False,
        sync_after_restart: bool = True,
        sleep_after_fuzz: float = 0.0,
        sync_after_fuzz: bool = False,
    ) -> Target:
        """Prepare a Target object with connection and monitor for the current fuzzer."""

        global openocd_process

        openocd_connection = OpenOCDConnection(
            "localhost",
            fuzz_data_logger,
            self._debug,
            self._no_openocd_server,
            self._openocd_port,
            self._openocd_bus_port,
            response_length,
            runtest,
            jstart,
        )

        openocd_process = openocd_connection.openocd_process

        if custom_connection:
            connection = custom_connection
        else:
            connection = openocd_connection

        return Target(
            connection=connection,
            monitors=[
                OpenOCDMonitor(
                    fuzz_data_logger,
                    openocd_connection,
                    self._register_settings,
                    custom_register_settings,
                    sleep_after_restart,
                    wait_for_configuration,
                    sync_after_restart,
                    sleep_after_fuzz,
                    sync_after_fuzz,
                )
            ],
        )


if __name__ == "__main__":

    def parse_args() -> argparse.Namespace:
        """Parse command line arguments."""

        def openocd_port_type(openocd_port: str) -> int:
            """Validate the given OpenOCD port."""

            openocd_port = int(openocd_port)

            if openocd_port < 0 or openocd_port > 65535:
                raise argparse.ArgumentTypeError(
                    "valid OpenOCD ports range from 0 to 65535"
                )

            return openocd_port

        parser = argparse.ArgumentParser(
            description="A Xilinx FPGA configuration engine fuzzer using boofuzz and OpenOCD."
        )

        parser.add_argument(
            "-fn",
            "--fuzzer-name",
            default=None,
            required=True,
            help=(
                "Pass in the name of the fuzzer function that should be executed. "
                "The fuzzer function has to be defined in the /fuzzers directory. "
                'Pass the name without "fuzz_" at the beginning.'
            ),
        )
        parser.add_argument(
            "-b",
            "--board",
            default=CONSTANTS.BOARD,
            choices=CONSTANTS.AVAILABLE_BOARDS,
            help=(
                "Specify which development board is going to be fuzzed. "
                "For each board are individual constants defined in src/constants.py."
            ),
        )
        parser.add_argument(
            "-dbf",
            "--db-filename",
            default=None,
            help="Pass in the relative path to an existing .db file to continue the fuzzing process in the same results file.",
        )
        parser.add_argument(
            "-tcn",
            "--test-case-name",
            default=None,
            help="Pass in a request or test case name to fuzz only a single request or test case.",
        )
        parser.add_argument(
            "-is",
            "--index-start",
            default=None,
            type=int,
            help=(
                "First test case index to execute. "
                "Can be used independently from index-end."
            ),
        )
        parser.add_argument(
            "-ie",
            "--index-end",
            default=None,
            type=int,
            help=(
                "Last test case index to execute. "
                "Can be used independently from index-start."
            ),
        )
        parser.add_argument(
            "-rs",
            "--register-settings",
            default=None,
            help=(
                "Name of a .ini file in REGISTER_SETTINGS_DIR. "
                "This .ini file can be used to overwrite or extend the default register settings. "
                "Contents of this file might be overwritten by the custom_register_settings defined in the fuzzer."
            ),
        ),
        parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help=(
                "Quiet mode does not start the boofuzz web app and only logs to the database. "
                "Also disk usage is minimized by only saving passing test cases if they precede a failure or error."
            ),
        )
        parser.add_argument(
            "-sn",
            "--slack-notification",
            action="store_true",
            help=(
                "When a fuzzer stopped send a slack notification with a fuzzing summary. "
                "The slack notification is sent using Incoming Webhooks (https://api.slack.com/messaging/webhooks). "
                "The Webhook URL can be changed in the constants.py."
            ),
        ),
        parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            help=(
                "The debugging mode logs and prints the OpenOCD commands and responses. "
                "Additionally the last transmitted bitstream is logged as .bit file in the results directory of the fuzzer."
            ),
        ),
        parser.add_argument(
            "-nos",
            "--no-openocd-server",
            action="store_true",
            help=(
                "Do not start an OpenOCD server. "
                "The OpenOCD server needs to be started manually when this argument is used."
            ),
        ),
        parser.add_argument(
            "-op",
            "--openocd-port",
            default=CONSTANTS.OPENOCD_DEFAULT_PORT,
            type=openocd_port_type,
            help=(
                "Specifies the TCP port that is used by the OpenOCD server. "
                "Valid ports range from 0 to 65535. "
                'The value is passed as "tcl_port" config command when the OpenOCD server is started.'
            ),
        )
        parser.add_argument(
            "-obp",
            "--openocd-bus-port",
            default=None,
            help=(
                "Specifies the physical USB port of the target device. "
                "This argument is necessary when multiple devices are connected to the host. "
                'The value is passed as "adapter usb location" config command when the OpenOCD server is started.'
            ),
        )
        parser.add_argument(
            "-ctc",
            "--count-test-cases",
            action="store_true",
            help="Don't start the fuzzer and only return the total number of test cases.",
        )

        return parser.parse_args()

    args = parse_args()

    try:
        MainFuzzer(**vars(args))
    finally:
        # Make sure that the OpenOCD process is killed, regardless of how the script was terminated.
        if openocd_process:
            openocd_process.kill()
