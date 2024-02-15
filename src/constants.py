class BASYS3:
    """Device specific constants for the Basys3 board.

    https://www.xilinx.com/products/boards-and-kits/1-54wqge.html
    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    """

    OPENOCD_TAP_NAME = "xc7"
    # Located in STATIC_DIR.
    OPENOCD_BASE_CFG = "openocd-digilent-basys3.cfg"

    XILINX_SERIES = "series_7"
    DEVICE_IDCODE = b"\x03\x62\xd0\x93"  # 7A35T
    # Frame length in 32-bit words.
    FRAME_LENGTH = 101
    # There are no pipelining words for the 7-series.
    # https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    # Step 8., page 182
    PIPELINING_WORDS = 0
    # The time in seconds it takes to restart the device.
    # Commands sent to the configuration engine before the restart is complete are ignored.
    # Since the first command sent after the restart is the sync word, all subsequent commands will also fail.
    RESTART_DELAY = 0.002  # 2 ms
    # If the device is automatically configured after restart (e. g. by loading a bitstream from flash),
    # the design on the device crashes if the configuration engine is accessed before the design finished loading.
    # Therefore, the fuzzer is delayed by the specified amount of time after the device restarts.
    RESTART_DELAY_CONFIGURATION = 0.054  # 54 ms

    # FABRIC_SIZE and ROW_END_POSITIONS are needed to construct valid RSA bitstreams.
    # Since the 7-series does not support RSA bitstreams, these values are set to None.
    FABRIC_SIZE = None
    ROW_END_POSITIONS = None


class KCU105:
    """Device specific constants for the KCU105 board.

    https://www.xilinx.com/products/boards-and-kits/kcu105.html
    https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    """

    OPENOCD_TAP_NAME = "xcu"
    OPENOCD_BASE_CFG = "kcu105.cfg"

    XILINX_SERIES = "ultrascale"
    DEVICE_IDCODE = b"\x03\x82\x20\x93"  # KU040
    FRAME_LENGTH = 123
    PIPELINING_WORDS = 10
    RESTART_DELAY = 0.003  # 3 ms
    RESTART_DELAY_CONFIGURATION = 0.135  # 135 ms

    FABRIC_SIZE = 4001190
    # The ROW_END_POSITIONS still need to be determined for the KU040.
    # Therefore RSA bitstreams are only supported for the KCU116 currently.
    ROW_END_POSITIONS = None


class KCU116:
    """Device specific constants for the KCU116 board.

    https://www.xilinx.com/products/boards-and-kits/ek-u1-kcu116-g.html
    https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    """

    OPENOCD_TAP_NAME = "xcu"
    OPENOCD_BASE_CFG = "kcu116.cfg"

    XILINX_SERIES = "ultrascaleplus"
    DEVICE_IDCODE = b"\x04\xA6\x20\x93"  # KU5P
    FRAME_LENGTH = 93
    PIPELINING_WORDS = 25
    RESTART_DELAY = 0.005  # 5 ms
    RESTART_DELAY_CONFIGURATION = 0.218  # 218 ms

    # FABRIC_SIZE and ROW_END_POSITIONS are needed to construct valid RSA bitstreams.
    # FABRIC_SIZE (in 32-bit words) = number of configuration frames * number of words per frame
    # https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    # Table 1-4 (Configuration Array Size), page 18
    # This value includes the two frames of zeros that need to be added after each row.
    # https://f4pga.readthedocs.io/projects/prjxray/en/latest/architecture/configuration.html
    FABRIC_SIZE = 3857268
    # These values specify the end of each row in the fabric.
    # Before the first row the RSA header is included.
    # After the last row and the two frames of zeros the RSA footer follows.
    ROW_END_POSITIONS = [
        # https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
        # Table 9-21, page 164
        0x2C4E24,  # End of first row, block type 000 (CLB, I/O, CLK)
        0x589EB0,  # End of second row, block type 000 (CLB, I/O, CLK)
        0x84EF3C,  # End of third row, block type 000 (CLB, I/O, CLK)
        0xB13FC8,  # End of fourth row, block type 000 (CLB, I/O, CLK)
        0xBFCAB0,  # End of first row, block type 001 (block RAM content)
        0xCE5598,  # End of second row, block type 001 (block RAM content)
        0xDCE080,  # End of third row, block type 001 (block RAM content)
        0xEB6B68,  # End of fourth row, block type 001 (block RAM content)
    ]


class XEM8320:
    """Device specific constants for the XEM8320 board.

    https://opalkelly.com/products/xem8320/
    https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    """

    OPENOCD_TAP_NAME = "xcu"
    OPENOCD_BASE_CFG = "xem8320.cfg"

    XILINX_SERIES = "ultrascaleplus"
    DEVICE_IDCODE = b"\x04\xA6\x40\x93"  # AU25P
    FRAME_LENGTH = 93
    PIPELINING_WORDS = 25
    RESTART_DELAY = 0.005  # 5 ms
    RESTART_DELAY_CONFIGURATION = 0.218  # 218 ms (untested)

    # FABRIC_SIZE and ROW_END_POSITIONS are identical to the KCU116.
    FABRIC_SIZE = 3857268
    ROW_END_POSITIONS = [
        # https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
        # Table 9-21, page 164
        0x2C4E24,  # End of first row, block type 000 (CLB, I/O, CLK)
        0x589EB0,  # End of second row, block type 000 (CLB, I/O, CLK)
        0x84EF3C,  # End of third row, block type 000 (CLB, I/O, CLK)
        0xB13FC8,  # End of fourth row, block type 000 (CLB, I/O, CLK)
        0xBFCAB0,  # End of first row, block type 001 (block RAM content)
        0xCE5598,  # End of second row, block type 001 (block RAM content)
        0xDCE080,  # End of third row, block type 001 (block RAM content)
        0xEB6B68,  # End of fourth row, block type 001 (block RAM content)
    ]


class CONSTANTS:
    """This class contains all constants for the framework."""

    # The currently defined value is the default board that is used
    # if no board is specified via command line arguments.
    BOARD = "basys3"
    # For each available board a BOARD_CONSTANTS class (with all uppercase letters in the title) is necessary.
    AVAILABLE_BOARDS = ["basys3", "kcu105", "kcu116", "xem8320"]
    BOARD_CONSTANTS = BASYS3

    BITSTREAMS_DIR = "bitstreams/" + BOARD
    REGISTER_SETTINGS_BASE_DIR = "register_settings"
    REGISTER_SETTINGS_DEFAULT_INI = "default_register_settings.ini"
    REGISTER_SETTINGS_DIR = "register_settings/" + BOARD
    STATIC_DIR = "static/" + BOARD
    # RESULTS_DIR is updated in the init function of the Session object to append the fuzzer name.
    RESULTS_DIR = "results/" + BOARD

    # The default TCP port for the OpenOCD server.
    # Valid ports range from 0 to 65535.
    # The value is passed as "tcl_port" config command when the OpenOCD server is started.
    # https://openocd.org/doc/html/Server-Configuration.html#TCP_002fIP-Ports"
    OPENOCD_DEFAULT_PORT = 6666

    # By default, boofuzz's FuzzLoggerDb only truncates the transmitted data if no crash has occured.
    # This is problematic when sending large amounts of data, as the web interface crashes and
    # performance is drastically reduced.
    # This paramater introduces a hard limit where the sent data is always truncated
    # for every logger by limiting the length that the send function returns in the OpenOCDConnection.
    # This has no effect on the actual transmitted data, which is never truncated.
    ALWAYS_TRUNCATE_SEND_DATA_LIMIT = 1024

    # https://api.slack.com/messaging/webhooks
    SLACK_WEBHOOK_URL = "https://httpbin.org/post"

    def update_board(board: str) -> None:
        """Updates all board dependent constants."""

        # No changes necessary.
        if board == CONSTANTS.BOARD:
            return

        if board not in CONSTANTS.AVAILABLE_BOARDS:
            raise ValueError(f'"{board}" is not a valid board')

        CONSTANTS.BOARD = board
        CONSTANTS.BOARD_CONSTANTS = globals()[board.upper()]

        CONSTANTS.BITSTREAMS_DIR = "bitstreams/" + board
        CONSTANTS.REGISTER_SETTINGS_DIR = "register_settings/" + board
        CONSTANTS.STATIC_DIR = "static/" + board
        CONSTANTS.RESULTS_DIR = "results/" + board
