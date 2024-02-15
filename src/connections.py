import os
import subprocess
import time

from boofuzz.connections import TCPSocketConnection
from boofuzz.exception import BoofuzzTargetConnectionFailedError
from boofuzz.fuzz_logger import FuzzLogger

from .constants import CONSTANTS
from .helpers import swap_endianness_and_bits
from .models import Bitstream


class OpenOCDConnection(TCPSocketConnection):
    """This connection communicates via a TCP socket with an OpenOCD server.

    This class is derived from the OpenOCD RPC example:
    https://sourceforge.net/p/openocd/code/ci/master/tree/contrib/rpc_examples/ocd_rpc_example.py

    The response_length, runtest, and jstart arguments are only used for the
    actual fuzzing data that is sent during every test case.
    """

    # If OpenOCD is not installed system wide a path to the OpenOCD binary can be specified.
    # A trailing backslash is necessary if a path is specified.
    OPENOCD_PATH = ""
    # Repeatedly try to open the connection until the timeout (in seconds) is reached
    # to give the OpenOCD server time to start.
    OPEN_CONNECTION_TIMEOUT = 1
    # Every command and response is terminated with the command token 0x1A.
    # https://openocd.org/doc/html/Tcl-Scripting-API.html#Tcl-RPC-server
    COMMAND_TOKEN = "\x1A"
    # If a bitstream consits of more than 104856 bytes (26214 32-bit words)
    # the drscan command in the OpenOCD .cfg file leads to a segmentation fault (exit code 139).
    # Apparently in this case the number of arguments the drscan command can handle is exceeded.
    # By defining this limit the bitstream is separated into multiple
    # drscan commands consiting of 104856 bitstream bytes at the most
    # and therefore limiting the amount of bit fields passed to the drscan command to 26214.
    DRSCAN_LIMIT = 104856
    # OpenOCD can only process a sequence of commands that is smaller than TCL_LINE_MAX,
    # hence we split the commands sequence into chunks if the are too long in sum.
    # https://sourceforge.net/p/openocd/code/ci/master/tree/src/server/tcl_server.c
    TCL_LINE_MAX = 4194304
    # Set buffer size as it is in the OpenOCD RPC example.
    BUFFER_SIZE = 4096

    def __init__(
        self,
        host: str,
        fuzz_data_logger: FuzzLogger,
        debug: bool = False,
        no_openocd_server: bool = False,
        openocd_port: int = CONSTANTS.OPENOCD_DEFAULT_PORT,
        openocd_bus_port: str = None,
        response_length: int = 0,
        runtest: int = 0,
        jstart: bool = False,
    ):
        super(OpenOCDConnection, self).__init__(
            host, openocd_port, send_timeout=60.0, recv_timeout=60.0
        )

        self._host = host
        self._fuzz_data_logger = fuzz_data_logger

        self._debug = debug
        self._openocd_port = openocd_port
        self._openocd_bus_port = openocd_bus_port
        self._response_length = response_length
        self._runtest = runtest
        self._jstart = jstart

        self.openocd_process = None
        self._received_data = b""

        if not no_openocd_server:
            self._start_openocd_server()

        # Open the connection on initialization because the OpenOCDMonitor needs
        # this connection before it would be opened by boofuzz.
        try_until = time.time() + OpenOCDConnection.OPEN_CONNECTION_TIMEOUT
        while time.time() <= try_until:
            try:
                super(OpenOCDConnection, self).open()
            except BoofuzzTargetConnectionFailedError:
                continue
            else:
                return

        # If the connection could not be opened before the timeout was reached
        # try one final time and do not surpress exceptions this time.
        super(OpenOCDConnection, self).open()

    def open(self):
        # The connection has already been opened during initialization,
        # hence we skip this call when boofuzz tries to open the connection.
        return

    def recv(self, max_bytes):
        # Only used by boofuzz to receive a response to the fuzzed request.

        data = self._received_data

        # Never return the same data more than once.
        self._received_data = b""

        return data

    def send(self, data):
        # Only used by boofuzz to send the fuzzed request.

        if self._debug:
            # The fuzzer name is appended to RESULTS_DIR in the init function of the Session object.
            with open(
                os.path.join(
                    CONSTANTS.RESULTS_DIR,
                    f"{self._fuzz_data_logger.most_recent_test_id}.bit",
                ),
                "wb",
            ) as f:
                f.write(data)

        self._received_data = self.send_bitstreams(
            [Bitstream(data, self._response_length, self._runtest, self._jstart)]
        )[0]

        data_length = len(data)

        # Limit the returned length so the loggers truncate the sent data to reduce storage and improve performance.
        # See src/constants.py for a more detailed explanation.
        if data_length <= CONSTANTS.ALWAYS_TRUNCATE_SEND_DATA_LIMIT:
            return data_length
        else:
            self._fuzz_data_logger.log_info(
                f"Truncated transmitted data to {CONSTANTS.ALWAYS_TRUNCATE_SEND_DATA_LIMIT} bytes. Actually {data_length} bytes were sent."
            )

            return CONSTANTS.ALWAYS_TRUNCATE_SEND_DATA_LIMIT

    def _start_openocd_server(self) -> None:
        """Starts an OpenOCD server as a separate subprocess."""

        init_cmds = [
            # https://openocd.org/doc/html/Server-Configuration.html#TCP_002fIP-Ports"
            f"tcl_port {self._openocd_port}",
            f"set tap {CONSTANTS.BOARD_CONSTANTS.OPENOCD_TAP_NAME}.tap",
        ]

        if self._openocd_bus_port:
            # https://openocd.org/doc/html/Debug-Adapter-Configuration.html#Adapter-Configuration
            init_cmds.append(f"adapter usb location {self._openocd_bus_port}")

        if self._debug:
            # Print OpenOCD output to console of the main process.
            stdout = None

            # Set an individual Telnet port for each instance to debug the cluster fuzzer.
            init_cmds.append(f"telnet_port {self._openocd_port + 100}")
        else:
            # Do not print any OpenOCD output.
            stdout = subprocess.DEVNULL

            # Disable the Telnet service unless the debug mode is enabled.
            # This service is enabled by default.
            init_cmds.append("telnet_port disabled")

        # Store OpenOCD process so it can be killed in the main_fuzzer.py.
        self.openocd_process = subprocess.Popen(
            args=[
                f"{OpenOCDConnection.OPENOCD_PATH}openocd",
                "--file",
                os.path.join(
                    CONSTANTS.STATIC_DIR, CONSTANTS.BOARD_CONSTANTS.OPENOCD_BASE_CFG
                ),
                "--command",
                "; ".join(init_cmds),
            ],
            stdout=stdout,
            stderr=stdout,
        )

        self._fuzz_data_logger.log_info("OpenOCD server started.")
        if self._debug:
            self._fuzz_data_logger.log_info(
                subprocess.list2cmdline(self.openocd_process.args)
            )

    def send_bitstreams(self, bitstreams: list[Bitstream]) -> list[bytes]:
        """Transforms a bitstream into an OpenOCD command and sends it to the OpenOCD server.

        Depending on the response_length, runtest, and jstart arguments a response is returned
        and additional commands to start the target device are appended.

        The OpenOCD and Xilinx documentation contain more information about the used commands:
        https://openocd.org/doc/html/JTAG-Commands.html
        https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
        Table 6-3, page 95
        """

        cmds = ['set data ""; ']

        for bitstream in bitstreams:
            data = swap_endianness_and_bits(bitstream.data)
            data_length = len(data)

            cmds.append("irscan $tap 0x05; ")  # CFG_IN

            for i in range(0, data_length, OpenOCDConnection.DRSCAN_LIMIT):
                drscan = "drscan $tap"
                # Select minimum because i + DRSCAN_LIMIT might exceed the bitstream_data_length.
                for j in range(
                    i, min(data_length, i + OpenOCDConnection.DRSCAN_LIMIT), 4
                ):
                    drscan += f' 32 0x{int.from_bytes(data[j : j + 4], "big"):08X}'
                # The list command is used to surpress the output of the drscan command.
                # Only for the last command of a sequence response is returned.
                # The list command creates an empty list which is represented as an empty string.
                # https://stackoverflow.com/questions/17885809/how-to-keep-commands-quiet-in-tcl
                # This saves a lot of bandwidth because otherwise the drscan would be completely echoed.
                cmds.append(f"{drscan}; list; ")

            if bitstream.response_length > 0:
                cmds.append("irscan $tap 0x04; ")  # CFG_OUT
                # Append the read value + "," to the data variable in order to
                # return the responses to all bitstreams at once.
                cmds.append(
                    f'append data [drscan $tap {bitstream.response_length} 0] ","; '
                )

            if bitstream.runtest > 0:
                cmds.append(f"runtest {bitstream.runtest}; ")

            if bitstream.jstart:
                cmds.append("irscan $tap 0xC0; ")  # JSTART

        cmds.append("return $data; ")

        cmds_to_send = ""
        received_data = ""
        for cmd in cmds:
            if len(cmds_to_send) + len(cmd) < OpenOCDConnection.TCL_LINE_MAX:
                cmds_to_send += cmd
            else:
                received_data += self.send_command(cmds_to_send)
                cmds_to_send = cmd
        received_data += self.send_command(cmds_to_send)

        # Remove the last "," of the received data.
        # Then transform the responses separately and return them as a list.
        # The first list entry is the response to the first bitstream with a reponse_length > 0 and so on.
        formatted_data = [
            swap_endianness_and_bits(bytearray.fromhex(response))
            for response in received_data[:-1].split(",")
        ]

        return formatted_data

    def send_command(self, cmd: str) -> str:
        """Send arbitrary commands to the OpenOCD server and receive a response."""

        if self._debug:
            self._fuzz_data_logger.log_info(f"OpenOCD cmd: {cmd}")

        super(OpenOCDConnection, self).send(
            (cmd + OpenOCDConnection.COMMAND_TOKEN).encode("utf-8")
        )

        received_data = self._receive_data()

        if self._debug:
            self._fuzz_data_logger.log_info(f"OpenOCD response: {received_data}")

        return received_data

    def _receive_data(self) -> str:
        """Receive data over the TCP socket until no data or the command token is received."""

        data = bytearray()
        while True:
            chunk = super(OpenOCDConnection, self).recv(OpenOCDConnection.BUFFER_SIZE)
            data += chunk
            # If there is no response we still break the loop to avoid infinite loops because the
            # TCPSocketConnection might return b"" if there was an error.
            if (
                chunk == b""
                or bytes(OpenOCDConnection.COMMAND_TOKEN, encoding="utf-8") in chunk
            ):
                break

        # Decode the response and remove the trailing command token 0x1A.
        return data.decode("utf-8")[:-1]
