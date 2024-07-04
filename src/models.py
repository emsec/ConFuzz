import enum
from dataclasses import dataclass

from boofuzz.exception import BoofuzzError
from boofuzz.helpers import hex_str

from .constants import CONSTANTS


@dataclass
class FuzzPosition:
    """This class is used to determine the positions of the FuzzedBitstream primitive that will be fuzzed.

    index_start is the first byte of the first 32-bit word that will be fuzzed. The first index is zero.
    word_count defines how many words after the given index_start will be fuzzed.
    """

    index_start: int
    word_count: int

    def __post_init__(self):
        if self.index_start < 0:
            raise ValueError("index_start has to be >= 0")

        if self.word_count < 1:
            raise ValueError("word_count has to be >= 1")


@dataclass
class Series7KeyFile:
    """Stores the parsed data from .nky files for 7-series devices."""

    device: str
    aes_key: bytes  # 256 bits
    aes_iv: bytes  # 128 bits
    hmac_key: bytes  # 256 bits


@dataclass
class AESKey:
    """AES key, AES IV, and length of the encrypted content for UltraScale(+) devices."""

    key: bytes  # 256 bits
    iv: bytes  # 96 bits
    length: bytes  # 32 bits


@dataclass
class UltraScaleKeyFile:
    """Stores the parsed data from .nky files for UltraScale(+) devices."""

    device: str
    encrypt_key_select: str  # BBRAM or EFUSE
    rsa_public_key_modulus: bytes  # 2048 bits
    rsa_public_key_digest: bytes  # 384 bits
    aes_keys: list[AESKey]


@dataclass
class Bitstream:
    """Bitstream object that is sent to the target using the send_bitstreams() function of the OpenOCDConnection.

    data contains the bitstream as bytes and response_length defines how many bits are expected as response.

    The runtest command ist necessary to correctly process RSA bitstreams (Read-Decrypt-Write).
    In contrast to the documentation the command ist also necessary when processing unencrypted RSA bitstreams.
    https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    page 130
    More information about the runtest command can be found here:
    https://openocd.org/doc-release/html/JTAG-Commands.html#Low-Level-JTAG-Commands

    The JSTART boundary-scan command clocks the startup sequence.
    https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    Table 6-3, page 95, page 99
    """

    data: bytes
    response_length: int = 0  # In bits
    runtest: int = 0
    jstart: bool = False

    def __post_init__(self):
        if self.response_length < 0:
            raise ValueError("response_length has to be >= 0")

        if self.response_length % 32 != 0:
            raise ValueError("response_length has to be a multiple of 32")

        if self.runtest < 0:
            raise ValueError("runtest has to be >= 0")


class RegisterName(enum.Enum):
    """All possible configuration register names."""

    CRC = "CRC"
    FAR = "FAR"
    FDRI = "FDRI"
    FDRO = "FDRO"
    CMD = "CMD"
    CTL0 = "CTL0"
    MASK = "MASK"
    STAT = "STAT"
    LOUT = "LOUT"
    COR0 = "COR0"
    MFWR = "MFWR"
    # Register 11 is called CBC in UG470 and AES_IV in UG570.
    # Nevertheless it has the same functionality.
    CBC = "CBC"
    AES_IV = "AES_IV"
    IDCODE = "IDCODE"
    AXSS = "AXSS"
    COR1 = "COR1"
    WBSTAR = "WBSTAR"
    TIMER = "TIMER"
    # The Precomputed Readback CRC Register exists only in UG470.
    RBCRC_SW = "RBCRC_SW"
    BOOTSTS = "BOOTSTS"
    CTL1 = "CTL1"
    BSPI = "BSPI"
    UNKNOWN = "unknown"
    # Allow the fuzz response to be treated as register to easily check for crashes.
    FUZZ_RESPONSE = "fuzz_response"


@dataclass
class RegisterInfo:
    """Configuration register information that does not change during fuzzing."""

    address: int
    name: RegisterName
    length: int
    display_data_as_frames: bool
    log_transmitted_if_crashed: str
    log_transmitted_if_not_crashed: str
    default_value: bytes = None

    def __post_init__(self):
        if self.length < 0:
            raise ValueError("length has to be >= 0")

        if self.length % 32 != 0:
            raise ValueError("length has to be a multiple of 32")

        # Store length in bytes.
        self.length //= 8

    def get_id(self) -> str:
        """Return a register id as string."""

        return f"{self.name.value}:{self.address}"


@dataclass
class RegisterCrashSettings:
    """Defines under which conditions a register is marked as crash."""

    differs_from_default: bool
    equal_to: list[bytes]
    not_equal_to: list[bytes]
    some_bits_in_mask_set: bytes
    some_bits_in_mask_not_set: bytes
    all_bits_in_mask_set: bytes
    all_bits_in_mask_not_set: bytes
    not_equal_to_transmitted: str

    def __post_init__(self):
        # Convert string to a list of bytes.
        for attribute in ["equal_to", "not_equal_to"]:
            value = self.__getattribute__(attribute)
            if isinstance(value, str) and value:
                value_list = [
                    bytes.fromhex(value.removeprefix("0x"))
                    for value in value.split(", ")
                ]
            else:
                value_list = []
            self.__setattr__(attribute, value_list)

        # Store hex strings as bytes.
        for attribute in [
            "some_bits_in_mask_set",
            "some_bits_in_mask_not_set",
            "all_bits_in_mask_set",
            "all_bits_in_mask_not_set",
        ]:
            value = self.__getattribute__(attribute)
            if isinstance(value, str) and value:
                value = bytes.fromhex(value.removeprefix("0x"))
            else:
                value = None
            self.__setattr__(attribute, value)


@dataclass
class RegisterData:
    """Stores the current status of a register."""

    differs_from_default: bool = False
    equal_to: bool = False
    not_equal_to: bool = False
    some_bits_in_mask_set: bool = False
    some_bits_in_mask_not_set: bool = False
    all_bits_in_mask_set: bool = False
    all_bits_in_mask_not_set: bool = False
    not_equal_to_transmitted: bool = False

    current_value: bytes = None


@dataclass
class ConfigurationRegister:
    """Combines all information about a configuration register.

    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    Table 5-23, page 101
    https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
    Table 9-19, page 162
    """

    info: RegisterInfo
    crash_settings: RegisterCrashSettings
    data: RegisterData

    def __post_init__(self):
        # Make sure the specified masks have the correct length.
        for attribute in [
            "some_bits_in_mask_set",
            "some_bits_in_mask_not_set",
            "all_bits_in_mask_set",
            "all_bits_in_mask_not_set",
        ]:
            mask = self.crash_settings.__getattribute__(attribute)
            if mask and len(mask) != self.info.length:
                raise BoofuzzError("mask length has to match the register length")

    def _default_register_representation(self, value: bytes) -> str:
        """Return the default register representation if no information about the meaning of the single bits is available."""

        return f'BIT00_UNKNOWN\t{" ".join(f"{byte:08b}" for byte in value)}\n'

    def display_data(self, value: bytes) -> str:
        """Get detailed bit descriptions for the current register data as described in the Xilinx documentation.

        FDRO output or large amounts of data can be displayed as frames.
        These frames consist of FRAME_LENGTH 32-bit words and are displayed as bytes.
        """

        if self.info.display_data_as_frames:
            # One frame has 4 * FRAME_LENGTH bytes.
            # Leftover bytes are the pipelining words.
            frames = [
                value[i : i + 4 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH]
                for i in range(
                    0, self.info.length, 4 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH
                )
            ]

            data = ""
            frame_number = len(frames) - 1
            # Display pipelining words seperately at the end if they exist.
            # https://docs.xilinx.com/v/u/en-US/ug570-ultrascale-configuration
            # Step 8., page 182
            if CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS > 0:
                pipelining_words = frames[-1]
                frames.pop()
                frame_number -= 1
            for frame in frames[:-1]:
                data += f"FRAME {frame_number}:\n{hex_str(frame)}\n"
                frame_number -= 1
            data += f"DUMMY FRAME:\n{hex_str(frames[-1])}\n"
            if CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS > 0:
                data += f"{CONSTANTS.BOARD_CONSTANTS.PIPELINING_WORDS} pipelining words:\n{hex_str(pipelining_words)}\n"

            return data
        else:
            # value[0] contains bits 31 to 24
            # value[1] contains bits 23 to 16
            # value[2] contains bits 15 to 8
            # value[3] contains bits 7 to 0
            match self.info.name:
                case RegisterName.FAR:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7":
                            return (
                                f"BIT26_UNKNOWN\t\t{value[0] >> 2:06b}\n"
                                f"BIT23_Block Type\t\t{value[0] & 0x3:02b} {(value[1] >> 7) & 0x1}\n"
                                f"BIT22_Top/Bottom Bit\t{(value[1] >> 6) & 0x1}\n"
                                f"BIT17_Row Address\t\t{(value[1] >> 1) & 0x1F:05b}\n"
                                f"BIT07_Column Address\t{value[1] & 0x1} {value[2]:08b} {(value[3] >> 7) & 0x1}\n"
                                f"BIT00_Minor Address\t{value[3] & 0x7F:07b}\n"
                            )
                        case "ultrascale":
                            return (
                                f"BIT26_Reserved\t\t{value[0] >> 2:06b}\n"
                                f"BIT23_Block Type\t\t{value[0] & 0x3:02b} {(value[1] >> 7) & 0x1}\n"
                                f"BIT17_Row Address\t\t{(value[1] >> 1) & 0x3F:06b}\n"
                                f"BIT07_Column Address\t{value[1] & 0x1} {value[2]:08b} {(value[3] >> 7) & 0x1}\n"
                                f"BIT00_Minor Address\t{value[3] & 0x7F:07b}\n"
                            )
                        case "ultrascaleplus":
                            return (
                                f"BIT27_UNKNOWN\t\t{value[0] >> 3:05b}\n"
                                f"BIT24_Block Type\t\t{value[0] & 0x7:03b}\n"
                                f"BIT18_Row Address\t\t{value[1] >> 2:06b}\n"
                                f"BIT08_Column Address\t{value[1] & 0x3:02b} {value[2]:08b}\n"
                                f"BIT00_Minor Address\t{value[3]:08b}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case RegisterName.CTL0:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7" | "ultrascale" | "ultrascaleplus":
                            if (
                                CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES == "ultrascale"
                                or CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES
                                == "ultrascaleplus"
                            ):
                                bit07_description = "Reserved"
                            else:
                                bit07_description = "FARSRC"

                            return (
                                f"BIT31_EFUSE_KEY\t\t{(value[0] >> 7) & 0x1}\n"
                                f"BIT30_ICAP_SELECT\t\t{(value[0] >> 6) & 0x1}\n"
                                f"BIT13_Reserved\t\t{value[0] & 0x3F:06b} {value[1]:08b} {(value[2] >> 5) & 0x7:03b}\n"
                                f"BIT12_OverTempPowerDown\t{(value[2] >> 4) & 0x1}\n"
                                f"BIT11_Reserved\t\t{(value[2] >> 3) & 0x1}\n"
                                f"BIT10_ConfigFallback\t{(value[2] >> 2) & 0x1}\n"
                                f"BIT09_Reserved\t\t{(value[2] >> 1) & 0x1}\n"
                                f"BIT08_GLUTMASK_B\t\t{value[2] & 0x1}\n"
                                f"BIT07_{bit07_description}\t\t{(value[3] >> 7) & 0x1}\n"
                                f"BIT06_DEC\t\t\t{(value[3] >> 6) & 0x1}\n"
                                f"BIT04_SBITS[1:0]\t\t{(value[3] >> 4) & 0x3:02b}\n"
                                f"BIT03_PERSIST\t\t{(value[3] >> 3) & 0x1}\n"
                                f"BIT01_Reserved\t\t{(value[3] >> 1) & 0x3:02b}\n"
                                f"BIT00_GTS_USR_B\t\t{value[3] & 0x1}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case RegisterName.STAT:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7":
                            return (
                                # BIT27 to BIT31 according to Vivado 2021.2:
                                f"BIT31_Reserved\t\t{(value[0] >> 7) & 0x1}\n"
                                f"BIT30_CFGBVS_PIN\t\t{(value[0] >> 6) & 0x1}\n"
                                f"BIT29_BAD_PACKET_ERROR\t{(value[0] >> 5) & 0x1}\n"
                                f"BIT28_PUDC_B_PIN\t\t{(value[0] >> 4) & 0x1}\n"
                                f"BIT27_SECURITY_AUTH_ERROR\t{(value[0] >> 3) & 0x1}\n"
                                # BIT27 to BIT31 according to documentation:
                                # f"BIT27_Reserved\t\t{(value[0] >> 3) & 0x1F:05b}\n"
                                f"BIT25_BUS_WIDTH\t\t{(value[0] >> 1) & 0x3:02b}\n"
                                f"BIT21_Reserved\t\t{value[0] & 0x1} {(value[1] >> 5) & 0x7:03b}\n"
                                f"BIT18_STARTUP_STATE\t{(value[1] >> 2) & 0x7:03b}\n"
                                f"BIT17_XADC_OVER_TEMP\t{(value[1] >> 1) & 0x1}\n"
                                f"BIT16_DEC_ERROR\t\t{value[1] & 0x1}\n"
                                f"BIT15_ID_ERROR\t\t{(value[2] >> 7) & 0x1}\n"
                                f"BIT14_DONE\t\t{(value[2] >> 6) & 0x1}\n"
                                f"BIT13_RELEASE_DONE\t{(value[2] >> 5) & 0x1}\n"
                                f"BIT12_INIT_B\t\t{(value[2] >> 4) & 0x1}\n"
                                f"BIT11_INIT_COMPLETE\t{(value[2] >> 3) & 0x1}\n"
                                f"BIT08_MODE\t\t{value[2] & 0x7:03b}\n"
                                f"BIT07_GHIGH_B\t\t{(value[3] >> 7) & 0x1}\n"
                                f"BIT06_GWE\t\t\t{(value[3] >> 6) & 0x1}\n"
                                f"BIT05_GTS_CFG_B\t\t{(value[3] >> 5) & 0x1}\n"
                                f"BIT04_EOS\t\t\t{(value[3] >> 4) & 0x1}\n"
                                f"BIT03_DCI_MATCH\t\t{(value[3] >> 3) & 0x1}\n"
                                f"BIT02_MMCM_LOCK\t\t{(value[3] >> 2) & 0x1}\n"
                                f"BIT01_PART_SECURED\t{(value[3] >> 1) & 0x1}\n"
                                f"BIT00_CRC_ERROR\t\t{value[3] & 0x1}\n"
                            )
                        case "ultrascale" | "ultrascaleplus":
                            return (
                                f"BIT31_Reserved\t\t\t\t{(value[0] >> 7) & 0x1}\n"
                                f"BIT30_CFGBVS_PIN\t\t\t\t{(value[0] >> 6) & 0x1}\n"
                                f"BIT29_BAD_PACKET_ERROR\t\t\t{(value[0] >> 5) & 0x1}\n"
                                f"BIT28_PUDC_B_PIN\t\t\t\t{(value[0] >> 4) & 0x1}\n"
                                f"BIT27_SECURITY_AUTH_ERROR\t\t\t{(value[0] >> 3) & 0x1}\n"
                                f"BIT25_CFG_BUS_WIDTH_DETECTION\t\t{(value[0] >> 1) & 0x3:02b}\n"
                                f"BIT24_Reserved\t\t\t\t{value[0] & 0x1}\n"
                                f"BIT21_SECURITY_STATUS\t\t\t\t{(value[1] >> 5) & 0x7:03b}\n"
                                f"BIT18_CFG_STARTUP_STATE_MACHINE_PHASE\t{(value[1] >> 2) & 0x7:03b}\n"
                                f"BIT17_SYSTEM_MONITOR_OVER_TEMP\t\t{(value[1] >> 1) & 0x1}\n"
                                f"BIT16_SECURITY_VIOLATION\t\t\t{value[1] & 0x1}\n"
                                f"BIT15_IDCODE_ERROR\t\t\t{(value[2] >> 7) & 0x1}\n"
                                f"BIT14_DONE_PIN\t\t\t\t{(value[2] >> 6) & 0x1}\n"
                                f"BIT13_DONE_INTERNAL_SIGNAL_STATUS\t\t{(value[2] >> 5) & 0x1}\n"
                                f"BIT12_INIT_B_PIN\t\t\t\t{(value[2] >> 4) & 0x1}\n"
                                f"BIT11_INIT_B_INTERNAL_SIGNAL_STATUS\t{(value[2] >> 3) & 0x1}\n"
                                f"BIT08_MODE_PIN_M[2:0]\t\t\t{value[2] & 0x7:03b}\n"
                                f"BIT07_GHIGH_B_STATUS\t\t\t{(value[3] >> 7) & 0x1}\n"
                                f"BIT06_GWE_STATUS\t\t\t\t{(value[3] >> 6) & 0x1}\n"
                                f"BIT05_GTS_CFG_B_STATUS\t\t\t{(value[3] >> 5) & 0x1}\n"
                                f"BIT04_END_OF_STARTUP_(EOS)_STATUS\t\t{(value[3] >> 4) & 0x1}\n"
                                f"BIT03_DCI_MATCH_STATUS\t\t\t{(value[3] >> 3) & 0x1}\n"
                                f"BIT02_MMCM_PLL_LOCK\t\t\t{(value[3] >> 2) & 0x1}\n"
                                f"BIT01_DECRYPTOR_ENABLED\t\t\t{(value[3] >> 1) & 0x1}\n"
                                f"BIT00_CRC_ERROR\t\t\t\t{value[3] & 0x1}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case RegisterName.COR0:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7":
                            return (
                                f"BIT31_Reserved\t{(value[0] >> 7) & 0x1}\n"
                                f"BIT30_Reserved\t{(value[0] >> 6) & 0x1}\n"
                                f"BIT29_Reserved\t{(value[0] >> 5) & 0x1}\n"
                                f"BIT28_Reserved\t{(value[0] >> 4) & 0x1}\n"
                                f"BIT27_PWRDWN_STAT\t{(value[0] >> 3) & 0x1}\n"
                                f"BIT26_Reserved\t{(value[0] >> 2) & 0x1}\n"
                                f"BIT25_DONE_PIPE\t{(value[0] >> 1) & 0x1}\n"
                                f"BIT24_DRIVE_DONE\t{value[0] & 0x1}\n"
                                f"BIT23_SINGLE\t{(value[1] >> 7) & 0x1}\n"
                                f"BIT17_OSCFSEL\t{(value[1] >> 1) & 0x3F:06b}\n"
                                f"BIT15_SSCLKSRC\t{value[1] & 0x1} {(value[2] >> 7) & 0x1}\n"
                                f"BIT12_DONE_CYCLE\t{(value[2] >> 4) & 0x7:03b}\n"
                                f"BIT09_MATCH_CYCLE\t{(value[2] >> 1) & 0x7:03b}\n"
                                f"BIT06_LOCK_CYCLE\t{value[2] & 0x1} {(value[3] >> 6) & 0x3:02b}\n"
                                f"BIT03_GTS_CYCLE\t{(value[3] >> 3) & 0x7:03b}\n"
                                f"BIT00_GWE_CYCLE\t{value[3] & 0x7:03b}\n"
                            )
                        case "ultrascale" | "ultrascaleplus":
                            return (
                                f"BIT27_Reserved\t{value[0] >> 3:05b}\n"
                                f"BIT26_ECLK_EN\t{(value[0] >> 2) & 0x1}\n"
                                f"BIT25_Reserved\t{(value[0] >> 1) & 0x1}\n"
                                f"BIT24_DRIVE_DONE\t{value[0] & 0x1}\n"
                                f"BIT23_Reserved\t{(value[1] >> 7) & 0x1}\n"
                                f"BIT17_OSCFSEL\t{(value[1] >> 1) & 0x3F:06b}\n"
                                f"BIT15_Reserved\t{value[1] & 0x1} {(value[2] >> 7) & 0x1}\n"
                                f"BIT12_DONE_CYCLE\t{(value[2] >> 4) & 0x7:03b}\n"
                                f"BIT09_MATCH_CYCLE\t{(value[2] >> 1) & 0x7:03b}\n"
                                f"BIT06_LOCK_CYCLE\t{value[2] & 0x1} {(value[3] >> 6) & 0x3:02b}\n"
                                f"BIT03_GTS_CYCLE\t{(value[3] >> 3) & 0x7:03b}\n"
                                f"BIT00_GWE_CYCLE\t{value[3] & 0x7:03b}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case RegisterName.COR1:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7":
                            return (
                                f"BIT18_Reserved\t\t\t{value[0]:08b} {(value[1] >> 2) & 0x3F:06b}\n"
                                f"BIT17_PERSIST_DEASSERT_AT_DESYNC\t{(value[1] >> 1) & 0x1}\n"
                                f"BIT15_RBCRC_ACTION\t\t{value[1] & 0x1} {(value[2] >> 7) & 0x1}\n"
                                f"BIT10_Reserved\t\t\t{(value[2] >> 2) & 0x1F:05b}\n"
                                f"BIT09_RBCRC_NO_PIN\t\t{(value[2] >> 1) & 0x1}\n"
                                f"BIT08_RBCRC_EN\t\t\t{value[2] & 0x1}\n"
                                f"BIT04_Reserved\t\t\t{(value[3] >> 4) & 0xF:04b}\n"
                                f"BIT02_BPI_1ST_READ_CYCLE\t\t{(value[3] >> 2) & 0x3:02b}\n"
                                f"BIT00_BPI_PAGE_SIZE\t\t{value[3] & 0x3:02b}\n"
                            )
                        case "ultrascale" | "ultrascaleplus":
                            return (
                                f"BIT18_Reserved\t\t{value[0]:08b} {(value[1] >> 2) & 0x3F:06b}\n"
                                f"BIT15_RBCRC_ACTION\t{value[1] & 0x3:02b} {(value[2] >> 7) & 0x1}\n"
                                f"BIT10_Reserved\t\t{(value[2] >> 2) & 0x1F:05b}\n"
                                f"BIT09_RBCRC_NO_PIN\t{(value[2] >> 1) & 0x1}\n"
                                f"BIT08_RBCRC_EN\t\t{value[2] & 0x1}\n"
                                f"BIT04_Reserved\t\t{(value[3] >> 4) & 0xF:04b}\n"
                                f"BIT02_BPI_1ST_READ_CYCLE\t{(value[3] >> 2) & 0x3:02b}\n"
                                f"BIT00_BPI_PAGE_SIZE\t{value[3] & 0x3:02b}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case RegisterName.WBSTAR:
                    # No differences.
                    return (
                        f"BIT30_RS[1:0]\t{(value[0] >> 6) & 0x3:02b}\n"
                        f"BIT29_RS_TS_B\t{(value[0] >> 5) & 0x1}\n"
                        f"BIT00_START_ADDR\t{value[0] & 0x1F:05b} {value[1]:08b} {value[2]:08b} {value[3]:08b}\n"
                    )
                case RegisterName.TIMER:
                    # No differences.
                    return (
                        f"BIT31_TIMER_USR_MON\t{(value[0] >> 7) & 0x1}\n"
                        f"BIT30_TIMER_CFG_MON\t{(value[0] >> 6) & 0x1}\n"
                        f"BIT00_TIMER_VALUE\t\t{value[0] & 0x3F:06b} {value[1]:08b} {value[2]:08b} {value[3]:08b}\n"
                    )
                case RegisterName.BOOTSTS:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7":
                            return (
                                f"BIT16_Reserved\t\t{value[0]:08b} {value[1]:08b}\n"
                                f"BIT15_HMAC_ERROR_1\t{(value[2] >> 7) & 0x1}\n"
                                f"BIT14_WRAP_ERROR_1\t{(value[2] >> 6) & 0x1}\n"
                                f"BIT13_CRC_ERROR_1\t\t{(value[2] >> 5) & 0x1}\n"
                                f"BIT12_ID_ERROR_1\t\t{(value[2] >> 4) & 0x1}\n"
                                f"BIT11_WTO_ERROR_1\t\t{(value[2] >> 3) & 0x1}\n"
                                f"BIT10_IPROG_1\t\t{(value[2] >> 2) & 0x1}\n"
                                f"BIT09_FALLBACK_1\t\t{(value[2] >> 1) & 0x1}\n"
                                f"BIT08_VALID_1\t\t{value[2] & 0x1}\n"
                                f"BIT07_HMAC_ERROR_0\t{(value[3] >> 7) & 0x1}\n"
                                f"BIT06_WRAP_ERROR_0\t{(value[3] >> 6) & 0x1}\n"
                                f"BIT05_CRC_ERROR_0\t\t{(value[3] >> 5) & 0x1}\n"
                                f"BIT04_ID_ERROR_0\t\t{(value[3] >> 4) & 0x1}\n"
                                f"BIT03_WTO_ERROR_0\t\t{(value[3] >> 3) & 0x1}\n"
                                f"BIT02_IPROG_0\t\t{(value[3] >> 2) & 0x1}\n"
                                f"BIT01_FALLBACK_0\t\t{(value[3] >> 1) & 0x1}\n"
                                f"BIT00_VALID_0\t\t{value[3] & 0x1}\n"
                            )
                        case "ultrascale" | "ultrascaleplus":
                            return (
                                f"BIT15_Reserved\t\t\t{value[0]:08b} {value[1]:08b} {(value[2] >> 7) & 0x1}\n"
                                f"BIT14_WRAP_ERROR_1\t\t{(value[2] >> 6) & 0x1}\n"
                                f"BIT13_CRC_ERROR_1\t\t\t{(value[2] >> 5) & 0x1}\n"
                                f"BIT12_ID_ERROR_1\t\t\t{(value[2] >> 4) & 0x1}\n"
                                f"BIT11_WATCHDOG_TIMEOUT_ERROR_1\t{(value[2] >> 3) & 0x1}\n"
                                f"BIT10_INTERNAL_PROG_1\t\t{(value[2] >> 2) & 0x1}\n"
                                f"BIT09_FALLBACK_1\t\t\t{(value[2] >> 1) & 0x1}\n"
                                f"BIT08_STATUS_VALID_1\t\t{value[2] & 0x1}\n"
                                f"BIT07_Reserved\t\t\t{(value[3] >> 7) & 0x1}\n"
                                f"BIT06_WRAP_ERROR_0\t\t{(value[3] >> 6) & 0x1}\n"
                                f"BIT05_CRC_ERROR_0\t\t\t{(value[3] >> 5) & 0x1}\n"
                                f"BIT04_ID_ERROR_0\t\t\t{(value[3] >> 4) & 0x1}\n"
                                f"BIT03_WATCHDOG_TIMEOUT_ERROR_0\t{(value[3] >> 3) & 0x1}\n"
                                f"BIT02_INTERNAL_PROG_0\t\t{(value[3] >> 2) & 0x1}\n"
                                f"BIT01_FALLBACK_0\t\t\t{(value[3] >> 1) & 0x1}\n"
                                f"BIT00_STATUS_VALID_0\t\t{value[3] & 0x1}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case RegisterName.CTL1:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7":
                            return f"BIT00_Reserved\t{value[0]:08b} {value[1]:08b} {value[2]:08b} {value[3]:08b}\n"
                        case "ultrascale" | "ultrascaleplus":
                            return (
                                f"BIT24_Reserved\t{value[0]:08b}\n"
                                f"BIT23_CAPTURE\t{(value[1] >> 7) & 0x1}\n"
                                f"BIT00_Reserved\t{value[1] & 0x7F:07b} {value[2]:08b} {value[3]:08b}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case RegisterName.BSPI:
                    match CONSTANTS.BOARD_CONSTANTS.XILINX_SERIES:
                        case "series_7":
                            return (
                                f"BIT28_Reserved\t\t\t{(value[0] >> 4) & 0xF:04b}\n"
                                f"BIT27_BPI_sync_mode\t\t{(value[0] >> 3) & 0x1}\n"
                                f"BIT12_Read Configuration Register\t{value[0] & 0x7:03b} {value[1]:08b} {(value[2] >> 4) & 0xF:04b}\n"
                                f"BIT10_Reserved\t\t\t{(value[2] >> 2) & 0x3:02b}\n"
                                f"BIT08_SPI_buswidth\t\t{value[2] & 0x3:02b}\n"
                                f"BIT00_SPI_read_opcode\t\t{value[3]:08b}\n"
                            )
                        case "ultrascale" | "ultrascaleplus":
                            return (
                                f"BIT28_Reserved\t\t{(value[0] >> 4) & 0xF:04b}\n"
                                f"BIT27_BPI_SYNC_MODE\t{(value[0] >> 3) & 0x1}\n"
                                f"BIT12_BPI_SYNC_RCR\t{value[0] & 0x7:03b} {value[1]:08b} {(value[2] >> 4) & 0xF:04b}\n"
                                f"BIT11_Reserved\t\t{(value[2] >> 3) & 0x1}\n"
                                f"BIT10_SPI_32BIT_ADDR\t{(value[2] >> 2) & 0x1}\n"
                                f"BIT08_SPI_BUSWIDTH\t{value[2] & 0x3:02b}\n"
                                f"BIT00_SPI_READ_OPCODE\t{value[3]:08b}\n"
                            )
                        case _:
                            return self._default_register_representation(value)
                case _:
                    return self._default_register_representation(value)


@dataclass
class UltraScaleBbramControlWord:
    """This class calculates the control word for UltraScale(+) devices
    that is stored together with the AES key in the BBRAM."""

    # DPA_COUNT specifies the initial load value for the configuration counter.
    # Once the count reaches 0, the BBRAM is erased.
    dpa_count: int = 0
    # Enables the BBRAM Configuration Counting DPA Protection mechanism.
    # 0x1 is diabled and 0x2 is enabled.
    dpa_protect: int = 0x1
    # DPA_MODE specifies under what conditions the DPA_COUNT should be decremented.
    # The 2 choices are INVALID_CONFIGURATIONS (0x1), which is the typical DPA setting,
    # and ALL_CONFIGURATIONS (0x2), which decrement the count on every configuration
    # so that the device has a fixed number of configurations to be used.
    dpa_mode: int = 0x1
    # OBFUSCATE_KEY specifies if the programmed key is obfuscated.
    # 0x1 is not obfuscated and 0x2 is obfuscated.
    obfuscate_key: int = 0x1
    # Contains the current control word.
    # If no value is passed, the value is constructed based on the parameters above.
    # Otherwise the parameters above are ignored and just the ECC value is updated.
    value: int = 0

    def __post_init__(self):
        if self.value == 0:
            if self.dpa_count < 0 or self.dpa_count > 255:
                raise ValueError("dpa_count must be >= 0 and <= 255")

            for attribute in ["dpa_protect", "dpa_mode", "obfuscate_key"]:
                value = self.__getattribute__(attribute)
                if value != 0x1 and value != 0x2:
                    raise ValueError(f"{attribute} must be 0x1 or 0x2")

            # Bits 7 and 8, and bits 10 and 11 are always set to 0x1.
            RESERVED_BITS = 0x1

            self.value = (
                self.dpa_count << 24
                | self.dpa_count << 16
                | self.dpa_protect << 14
                | self.dpa_mode << 12
                | RESERVED_BITS << 10
                | self.obfuscate_key << 8
                | RESERVED_BITS << 6
            )

        self._calculate_ecc()

    def _calculate_ecc(self):
        """Calculate the ECC value for the for the control word over the 26 most significant bits
        and store it in the lowest six bits.

        The functions calc_row_ecc_bbram_ultra and calc_ecc_bbram_ultra stem from the XilsKey library
        and have been translated with ChatGPT-3.5.
        The original functions can be found here:
        https://github.com/Xilinx/embeddedsw/blob/master/lib/sw_services/xilskey/src/xilskey_bbram.c
        Commit: 8fca1ac929453ba06613b5417141483b4c2d8cf3
        """

        def calc_row_ecc_bbram_ultra(value_bits, mask):
            """static INLINE u8 XilSKey_Calc_Row_Ecc_Bbram_Ultra(u8 *Value, u8 *Mask)"""

            xor_val = 0
            for bit, m in zip(value_bits, mask):
                xor_val ^= bit & m
            return xor_val

        def calc_ecc_bbram_ultra(control_word):
            """static INLINE u32 XilSKey_Calc_Ecc_Bbram_ultra(u32 ControlWord)"""

            P0_Mask = 0x36AD555
            P1_Mask = 0x2D9B333
            P2_Mask = 0x1C78F0F
            P3_Mask = 0x03F80FF
            P4_Mask = 0x0007FFF

            P0Mask = [(P0_Mask >> i) & 1 for i in range(26)]
            P1Mask = [(P1_Mask >> i) & 1 for i in range(26)]
            P2Mask = [(P2_Mask >> i) & 1 for i in range(26)]
            P3Mask = [(P3_Mask >> i) & 1 for i in range(26)]
            P4Mask = [(P4_Mask >> i) & 1 for i in range(26)]

            # Ecc should be calculated on upper 26 bits
            value = control_word >> 6
            value_bits = [(value >> i) & 1 for i in range(26)]

            xor_val0 = calc_row_ecc_bbram_ultra(value_bits, P0Mask)
            xor_val1 = calc_row_ecc_bbram_ultra(value_bits, P1Mask)
            xor_val2 = calc_row_ecc_bbram_ultra(value_bits, P2Mask)
            xor_val3 = calc_row_ecc_bbram_ultra(value_bits, P3Mask)
            xor_val4 = calc_row_ecc_bbram_ultra(value_bits, P4Mask)

            xor_val5 = 0
            for row in range(26):
                xor_val5 ^= value_bits[row]

            xor_val5 ^= xor_val4 ^ xor_val3 ^ xor_val2 ^ xor_val1 ^ xor_val0

            value = (value << 6) | (
                (xor_val5 << 0)
                | (xor_val4 << 1)
                | (xor_val3 << 2)
                | (xor_val2 << 3)
                | (xor_val1 << 4)
                | (xor_val0 << 5)
            )

            return value

        self.value = calc_ecc_bbram_ultra(self.value)
