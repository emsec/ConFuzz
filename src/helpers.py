import requests

from boofuzz.fuzz_logger import FuzzLogger

from .constants import CONSTANTS

# lookup table for byte with reversed bit order
LUT = bytes(int(f"{byte:08b}"[::-1], 2) for byte in range(256))


def swap_endianness_and_bits(data: bytes | bytearray) -> bytes:
    """Swap the bytewise endianness for every 32-bit word in data and additionally swap the bits in every byte.

    Note: len(data) has to be a multiple of 4.
    """

    # Convert data to a bytearray to use multiple assignment for performant element swapping.
    data = bytearray(data)

    # Swap the bytewise endianness for every 32-bit word in data.
    # Example: 0x41424344 51525354 -> 0x44434241 54535251
    data[0::4], data[3::4] = data[3::4], data[0::4]
    data[1::4], data[2::4] = data[2::4], data[1::4]

    # Swap the bits in each byte as described in the Xilinx documentation.
    # https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    # Figure 5-1, page 76
    return bytes(data.translate(LUT))


def send_slack_notification(fuzz_data_logger: FuzzLogger, text: str) -> None:
    """Send a Slack notification using Incoming Webhooks.

    https://api.slack.com/messaging/webhooks
    """

    if CONSTANTS.SLACK_WEBHOOK_URL:
        try:
            request = requests.post(CONSTANTS.SLACK_WEBHOOK_URL, json={"text": text})
            error_msg = "Slack notification has been sent"
        except requests.exceptions.RequestException as e:
            error_msg = f"Slack notification failed with exception:\n{e}"
        else:
            if request.status_code != 200:
                error_msg = (
                    f"Slack notification failed with status code: {request.status_code}"
                )
    else:
        error_msg = 'The constant "SLACK_WEBHOOK_URL" is not set'

    fuzz_data_logger.log_info(error_msg)


def calculate_ultrascale_bbram_crc(aes_key_chunks: list[int], control_word: int):
    """Calculate the CRC value based on the AES key and the control word.
    On UltraScale(+) devices the CRC value is also written to the BBRAM.

    The function row_crc_calculation stems from the XilsKey library and has been translated with ChatGPT-3.5.
    The original function can be found here:
    https://github.com/Xilinx/embeddedsw/blob/master/lib/sw_services/xilskey/src/xilskey_utils.c
    Commit: 8fca1ac929453ba06613b5417141483b4c2d8cf3
    """

    def row_crc_calculation(PrevCRC, Data, Addr):
        """u32 XilSKey_RowCrcCalculation(u32 PrevCRC, u32 Data, u32 Addr)"""

        REVERSE_POLYNOMIAL = 0x82F63B78

        Crc = PrevCRC
        Value = Data
        Row = Addr

        for Index in range(32):
            if (((Value & 0x1) ^ Crc) & 0x1) != 0:
                Crc = (Crc >> 1) ^ REVERSE_POLYNOMIAL
            else:
                Crc = Crc >> 1
            Value = Value >> 1

        for Index in range(5):
            if (((Row & 0x1) ^ Crc) & 0x1) != 0:
                Crc = (Crc >> 1) ^ REVERSE_POLYNOMIAL
            else:
                Crc = Crc >> 1
            Row = Row >> 1

        return Crc

    crc = 0

    crc = row_crc_calculation(crc, control_word, 9)
    for i in range(8):
        crc = row_crc_calculation(crc, aes_key_chunks[i], 8 - i)

    return crc
