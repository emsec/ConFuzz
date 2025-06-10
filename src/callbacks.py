import os

from boofuzz.primitives import Static

from .constants import CONSTANTS
from .helpers import calculate_ultrascale_bbram_crc
from .models import Bitstream, UltraScaleBbramControlWord
from .primitives import NOP, Type1WritePacket, Type2WritePacket


def write_two_frames(target=None, fuzz_data_logger=None, session=None, sock=None):
    """Write two frames of known data to frame address zero.

    fdri_value_3 is just a buffer frame and is not actually written to the fabric.

    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    Table 5-19, page 96, write sequence picked from sample bitstream
    """

    target._target_connection.send_bitstreams(
        [
            Bitstream(
                b"".join(
                    primitive.render()
                    for primitive in [
                        Type1WritePacket(name="write_to_mask", register_address=6),
                        Static(name="mask_value", default_value=b"\x00\x00\x04\x00"),
                        Type1WritePacket(name="write_to_ctl0", register_address=5),
                        Static(name="ctl0_value", default_value=b"\x00\x00\x04\x00"),
                        NOP(2),
                        Type1WritePacket(name="write_to_idcode", register_address=12),
                        Static(
                            name="idcode_value",
                            default_value=CONSTANTS.BOARD_CONSTANTS.DEVICE_IDCODE,
                        ),
                        Type1WritePacket(name="write_to_far", register_address=1),
                        Static(name="far_value", default_value=b"\x00\x00\x00\x00"),
                        Type1WritePacket(name="write_to_cmd", register_address=4),
                        Static(name="wcfg_code", default_value=b"\x00\x00\x00\x01"),
                        Type1WritePacket(
                            name="write_to_fdri", register_address=2, word_count=0
                        ),
                        Type2WritePacket(
                            name="write_to_fdri_type_2",
                            word_count=3 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                        ),
                        Static(
                            name="fdri_value_1",
                            default_value=b"\xf0\x0d\xf0\x0d"
                            * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                        ),
                        Static(
                            name="fdri_value_2",
                            default_value=b"\xbe\xef\xbe\xef"
                            * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                        ),
                        Static(
                            name="fdri_value_3",
                            default_value=b"\xde\xad\xc0\xde"
                            * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH,
                        ),
                        NOP(2),
                    ]
                )
            )
        ]
    )


def programm_ultrascale_bbram(
    target=None, fuzz_data_logger=None, session=None, sock=None
):
    """Programs the AES key to the BBRAM of UltraScale(+) devices.

    DPA protection and key obfuscation can be enabled by configuring the control word.
    The ECC value in the control word and the CRC checksum are calculated automatically.

    The OpenOCD commands in this function are derived from the JTAG commands in the XilSkey library.
    The JTAG sequence was kept as similar as possible.
    However, it should be possible to omit some OpenOCD commands to optimize for speed.

    The instruction opcodes of the irscan commands can be found in these files:
    ~/Xilinx/Vivado/2021.2/data/parts/xilinx/kintexu/public/bsdl/xcku040_ffva1156.bsd (KCU105)
    ~/Xilinx/Vivado/2021.2/data/parts/xilinx/kintexuplus/public/bsdl/xcku5p_ffvb676.bsd (KCU116)
    All available OpenOCD JTAG commands are listed here:
    https://openocd.org/doc-release/html/JTAG-Commands.html#Low-Level-JTAG-Commands
    The original JTAG sequence can be found in the specified functions in this file:
    https://github.com/Xilinx/embeddedsw/blob/master/lib/sw_services/xilskey/src/xilskey_jscmd.c
    Commit: 8fca1ac929453ba06613b5417141483b4c2d8cf3

    Caution: This function was only tested with the KCU105 and XEM8320 boards.
    """

    if not hasattr(session, "program_ultrascale_bbram_cmd"):
        # Configure the control word.
        CONTROL_WORD = UltraScaleBbramControlWord().value
        # Specify which AES key should be programmed.
        AES_KEY = "FB0ED5A1CA4E5E797F35EAE370FA889881F0D96E541FD54DFF28B8FDCAE9FBF8"

        aes_key_chunks = [AES_KEY[i : i + 8] for i in range(0, len(AES_KEY), 8)]
        aes_key_chunks_string = " ".join(aes_key_chunks)
        session.program_ultrascale_bbram_crc = calculate_ultrascale_bbram_crc(
            [int(chunk, 16) for chunk in aes_key_chunks], CONTROL_WORD
        )

        cmds = []

        # extern int Bbram_Init_Ultra(void);
        cmds.append("pathmove RESET; ")
        cmds.append("pathmove RUN/IDLE; ")

        cmds.append("irscan $tap 0x14 -endstate RUN/IDLE; ")  # ISC_NOOP

        cmds.append("after 100; ")

        # extern int Bbram_ProgramKey_Ultra(XilSKey_Bbram *InstancePtr)
        cmds.append("pathmove RUN/IDLE; ")

        cmds.append("irscan $tap 0x10 -endstate IRPAUSE; ")  # ISC_ENABLE
        cmds.append("drscan $tap 5 0x15 -endstate RUN/IDLE; ")
        cmds.append("runtest 12; ")

        cmds.append("drscan $tap 5 0x15 -endstate RUN/IDLE; ")
        cmds.append("runtest 12; ")

        cmds.append("pathmove RUN/IDLE; ")

        cmds.append("irscan $tap 0x12 -endstate IRPAUSE; ")  # XSC_PROGRAM_KEY
        cmds.append("drscan $tap 32 0xFFFFFFFF -endstate RUN/IDLE; ")
        cmds.append("runtest 9; ")

        cmds.append("irscan $tap 0x11 -endstate IRPAUSE; ")  # ISC_PROGRAM
        cmds.append(f"drscan $tap 32 0x{CONTROL_WORD:08X} -endstate RUN/IDLE; ")
        cmds.append("runtest 1; ")

        cmds.append(f"foreach chunk {{{aes_key_chunks_string}}} {{ ")
        cmds.append("irscan $tap 0x11 -endstate IRPAUSE; ")  # ISC_PROGRAM
        cmds.append("drscan $tap 32 0x$chunk -endstate RUN/IDLE; ")
        cmds.append("runtest 1; ")
        cmds.append("}; ")

        # Key programming still works if the CRC checksum is omitted.
        cmds.append("irscan $tap 0x11 -endstate IRPAUSE; ")  # ISC_PROGRAM
        cmds.append(
            f"drscan $tap 32 0x{session.program_ultrascale_bbram_crc:08X} -endstate RUN/IDLE; "
        )
        cmds.append("runtest 1; ")

        cmds.append("pathmove RUN/IDLE; ")

        # extern int Bbram_VerifyKey_Ultra(u32 *Crc)
        cmds.append("pathmove RUN/IDLE; ")

        cmds.append("irscan $tap 0x15 -endstate RUN/IDLE; ")  # ISC_READ
        cmds.append("for { set i 0 }  { $i < 10 } { incr i } { ")
        # Only the value read in the 10th iteration contains the CRC checksum.
        cmds.append("set crc_verify [drscan $tap 37 0 -endstate RUN/IDLE]; ")
        cmds.append("runtest 1; ")
        cmds.append("}; ")

        # extern void Bbram_DeInit_Ultra(void)
        cmds.append("pathmove RUN/IDLE; ")

        cmds.append("irscan $tap 0x12 -endstate RUN/IDLE; ")  # XSC_PROGRAM_KEY
        cmds.append("drscan $tap 32 0x00000000 -endstate RUN/IDLE; ")
        cmds.append("runtest 8; ")

        # void Bbram_Close_Ultra(void)
        cmds.append("irscan $tap 0x16 -endstate RUN/IDLE; ")  # ISC_DISABLE
        cmds.append("runtest 12; ")

        cmds.append("pathmove RUN/IDLE; ")
        cmds.append("runtest 10; ")

        cmds.append("pathmove RUN/IDLE; ")
        cmds.append("runtest 6; ")

        cmds.append("irscan $tap 0x3F -endstate RUN/IDLE; ")  # BYPASS

        cmds.append("pathmove RESET; ")
        cmds.append("pathmove RUN/IDLE; ")

        # With the XEM8320 board we have to wait 4 ms before resynchronizing with the configuration engine.
        # Otherwise, the sync word and thus subsequent commands are ignored.
        cmds.append("after 4; ")

        # Resynchronize with configuration engine after programming the BBRAM.
        cmds.append("irscan $tap 0x05; ")  # CFG_IN
        cmds.append("drscan $tap 32 0x66AA9955; ")

        cmds.append("return $crc_verify; ")

        # Save the command in the session object,
        # so that it does not has to be regenerated every time the function is called.
        session.program_ultrascale_bbram_cmd = "".join(cmds)

    crc_verify = target._target_connection.send_command(
        session.program_ultrascale_bbram_cmd
    )
    # The lowest five bits are not part of the CRC checksum.
    crc_verify = int(crc_verify, 16) >> 5

    if session.program_ultrascale_bbram_crc == crc_verify:
        fuzz_data_logger.log_info(
            "AES key has been successfully programmed to the BBRAM"
        )
    else:
        fuzz_data_logger.log_info(
            "AES key programming to the BBRAM failed: CRC mismatch"
        )
