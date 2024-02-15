import hashlib
import hmac
import os

from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.PublicKey import RSA

from boofuzz.blocks import Request
from boofuzz.fuzzable import Fuzzable
from boofuzz.fuzzable_block import FuzzableBlock
from boofuzz.primitives import Static

from .constants import CONSTANTS
from .helpers import swap_endianness_and_bits
from .models import AESKey, FuzzPosition, Series7KeyFile, UltraScaleKeyFile


class SyncWord(Static):
    """Primitive for a sync word.

    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    Table 5-3, page 75
    """

    _id = 0

    def __init__(self, *args, **kwargs):
        # Append id to name because boofuzz needs all primitives to have an individual name.
        SyncWord._id += 1

        super(SyncWord, self).__init__(
            name=f"SyncWord{SyncWord._id}",
            default_value=b"\xAA\x99\x55\x66",
            *args,
            **kwargs,
        )


class NOP(Static):
    """Primitive for a NOP command.

    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    Table 5-21, page 100
    """

    _id = 0

    def __init__(self, nop_count: int = 1, *args, **kwargs):
        # Append id to name because boofuzz needs all primitives to have an individual name.
        NOP._id += 1

        super(NOP, self).__init__(
            name=f"NOP{NOP._id}",
            default_value=b"\x20\x00\x00\x00" * nop_count,
            *args,
            **kwargs,
        )


class Type1Packet(Static):
    """Primitive for a Type 1 Packet.

    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    Table 5-20, page 100
    """

    def __init__(
        self,
        name: str,
        opcode: str,
        register_address: int,
        word_count: int,
        *args,
        **kwargs,
    ):
        if opcode != "read" and opcode != "write":
            raise ValueError('opcode has to be "read" or "write"')

        if register_address < 0 or register_address > 31:
            raise ValueError("register_address has to be >= 0 and <= 31")

        # 2**11 = 2048
        if word_count < 0 or word_count > 2047:
            raise ValueError("word_count has to be >= 0 and <= 2047")

        # Header Type
        value = 0b001

        # Opcode
        value <<= 2
        if opcode == "read":
            value |= 0b01
        else:
            value |= 0b10

        # Register Address
        value <<= 14
        value |= register_address

        # Reserved
        value <<= 2

        # Word Count
        value <<= 11
        value |= word_count

        super(Type1Packet, self).__init__(
            name=name, default_value=value.to_bytes(4, "big"), *args, **kwargs
        )


class Type1ReadPacket(Type1Packet):
    """Primitive for a Type 1 Packet with the "Read" (01) opcode."""

    def __init__(
        self, name: str, register_address: int, word_count: int = 1, *args, **kwargs
    ):
        super(Type1ReadPacket, self).__init__(
            name=name,
            opcode="read",
            register_address=register_address,
            word_count=word_count,
            *args,
            **kwargs,
        )


class Type1WritePacket(Type1Packet):
    """Primitive for a Type 1 Packet with the "Write" (10) opcode."""

    def __init__(
        self, name: str, register_address: int, word_count: int = 1, *args, **kwargs
    ):
        super(Type1WritePacket, self).__init__(
            name=name,
            opcode="write",
            register_address=register_address,
            word_count=word_count,
            *args,
            **kwargs,
        )


class Type2Packet(Static):
    """Primitive for a Type 2 Packet.

    https://docs.xilinx.com/r/en-US/ug470_7Series_Config
    Table 5-22, page 101
    """

    def __init__(self, name: str, opcode: str, word_count: int, *args, **kwargs):
        if opcode != "read" and opcode != "write":
            raise ValueError('opcode has to be "read" or "write"')

        # 2**27 = 134217728
        if word_count < 0 or word_count > 134217727:
            raise ValueError("word_count has to be >= 0 and <= 134217727")

        # Header Type
        value = 0b010

        # Opcode
        value <<= 2
        if opcode == "read":
            value |= 0b01
        else:
            value |= 0b10

        # Word Count
        value <<= 27
        value |= word_count

        super(Type2Packet, self).__init__(
            name=name, default_value=value.to_bytes(4, "big"), *args, **kwargs
        )


class Type2ReadPacket(Type2Packet):
    """Primitive for a Type 2 Packet with the "Read" (01) opcode."""

    def __init__(self, name: str, word_count: int, *args, **kwargs):
        super(Type2ReadPacket, self).__init__(
            name=name, opcode="read", word_count=word_count, *args, **kwargs
        )


class Type2WritePacket(Type2Packet):
    """Primitive for a Type 2 Packet with the "Write" (10) opcode."""

    def __init__(self, name: str, word_count: int, *args, **kwargs):
        super(Type2WritePacket, self).__init__(
            name=name, opcode="write", word_count=word_count, *args, **kwargs
        )


class BitstreamWord(Fuzzable):
    """Custom Fuzzable which represents a single 32 bit long bitstream word.

    https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html#making-your-own-block-primitive

    Static_bits is the base value in which fuzzed bits have to be 0.
    All set bits in fuzzing_mask are fuzzed by generating all possible submasks.
    If fuzzing_mask is a list of masks all possible submasks for every mask are generated.

    If the fuzzing_mask is set to zero only the static bits are returned.

    Example:
    static_bits  = 0x28 00 e0 01 = 0b00101000 00000000 11100000 00000001
    fuzzing_mask = 0x00 00 00 0e = 0b00000000 00000000 00000000 00001110
    =>
    mutation 1   = 0x28 00 e0 0f = 0b00101000 00000000 11100000 00001111
    mutation 2   = 0x28 00 e0 0d = 0b00101000 00000000 11100000 00001101
    mutation 3   = 0x28 00 e0 0b = 0b00101000 00000000 11100000 00001011
    mutation 4   = 0x28 00 e0 09 = 0b00101000 00000000 11100000 00001001
    mutation 5   = 0x28 00 e0 07 = 0b00101000 00000000 11100000 00000111
    mutation 6   = 0x28 00 e0 05 = 0b00101000 00000000 11100000 00000101
    mutation 7   = 0x28 00 e0 03 = 0b00101000 00000000 11100000 00000011
    mutation 8   = 0x28 00 e0 01 = 0b00101000 00000000 11100000 00000001
    """

    def __init__(
        self,
        name: str,
        static_bits: int,
        fuzzing_mask: int | list[int],
        default_value: bytes = None,
        fuzz_values: list[bytes] = None,
        *args,
        **kwargs,
    ):
        if static_bits < 0 or static_bits >= 0x100000000:
            raise ValueError("static_bits has to be >= 0 and < 0x100000000")

        if not isinstance(fuzzing_mask, list):
            fuzzing_mask_list = [fuzzing_mask]
        else:
            fuzzing_mask_list = fuzzing_mask

        for fuzzing_mask in fuzzing_mask_list:
            if fuzzing_mask < 0 or fuzzing_mask >= 0x100000000:
                raise ValueError("fuzzing_mask has to be >= 0 and < 0x100000000")

            if static_bits & fuzzing_mask != 0:
                raise ValueError(
                    "static_bits and fuzzing_mask can not have set bits at the same positions"
                )

        self._static_bits = static_bits
        self._fuzzing_mask_list = fuzzing_mask_list

        super(BitstreamWord, self).__init__(
            name=name,
            default_value=default_value,
            fuzzable=True,
            fuzz_values=fuzz_values,
            *args,
            **kwargs,
        )

    def mutations(self, default_value):
        # Generate all submasks for each fuzzing mask and
        # yield the result of a bitwise OR of the current submask and the static bits.
        # https://cp-algorithms.com/algebra/all-submasks.html
        for fuzzing_mask in self._fuzzing_mask_list:
            sub_mask = fuzzing_mask
            while sub_mask > 0:
                yield self._static_bits | sub_mask
                sub_mask = (sub_mask - 1) & fuzzing_mask

        # Yield the static bits as an extra mutation because
        # the algorithm above does not consider the submask equal to zero.
        yield self._static_bits

    def encode(self, value, mutation_context):
        if isinstance(value, int):
            return value.to_bytes(4, "big")
        elif isinstance(value, bytes):
            return value
        else:
            return b""

    def num_mutations(self, default_value):
        return (
            sum(
                [
                    2 ** fuzzing_mask.bit_count()
                    for fuzzing_mask in self._fuzzing_mask_list
                ]
            )
            # Count the submask equal to zero only once.
            - len(self._fuzzing_mask_list)
            + 1
        )


class FuzzedBitstream(Fuzzable):
    """Custom Fuzzable which will apply the given fuzzing masks to the given positions of the given bitstream.

    https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html#making-your-own-block-primitive

    file_name is the name of the bitstream file that will be mutated. The bitstream has to be placed in BITSTREAMS_DIR.
    All set bits in fuzzing_mask are fuzzed by generating all possible submasks.
    If fuzzing_mask is a list of masks all possible submasks for every mask are generated.
    With the fuzzing_position argument we can define to which positions of the bitstream the fuzzing masks will be applied.
    It is possible to only give a starting position (first position is zero) and the generated submasks will be applied to
    the 32-bit word starting at this address and all following words.
    Otherwise we can pass a single FuzzPosition object or a list of FuzzPosition objects as fuzzing_position.
    The index_start parameter of the FuzzPosition specifies the first byte of the first 32-bit word that will be fuzzed.
    The word_count parameter defines how many 32-bit words will be fuzzed.

    If we pass an empty list as fuzzing_position only the original bitstream will be returned.

    Examples:
    bitstream    = 00000000 00000000 FFFFFFFF
    fuzzing_mask = [0x00000001, 0x00000010]

    Example 1:
    fuzzing_position = 0
    =>
    position:    0 1 2 3  4 5 6 7  8 9 ...
    mutation 1 = 00000001 00000000 FFFFFFFF (word at position 0, first mask)
    mutation 2 = 00000010 00000000 FFFFFFFF (word at position 0, second mask)
    mutation 3 = 00000000 00000001 FFFFFFFF (word at position 4, first mask)
    mutation 4 = 00000000 00000010 FFFFFFFF (word at position 4, second mask)
    mutation 5 = 00000000 00000000 FFFFFFFE (word at position 8, first mask)
    mutation 6 = 00000000 00000000 FFFFFFEF (word at position 8, second mask)
    mutation 7 = 00000000 00000000 FFFFFFFF (original bitstream)

    Example 2:
    fuzzing_position = 7
    =>
    position:    0 1 2 3  4 5 6 7  8 9 ...
    mutation 1 = 00000000 00000000 FFFFFEFF (word at position 7, first mask)
    mutation 2 = 00000000 00000000 FFFFEFFF (word at position 7, second mask)
    mutation 3 = 00000000 00000000 FFFFFFFF (original bitstream)

    Example 3:
    fuzzing_position = FuzzPosition(3, 2)
    =>
    position:    0 1 2 3  4 5 6 7  8 9 ...
    mutation 1 = 00000000 00000100 FFFFFFFF (word at position 3, first mask)
    mutation 2 = 00000000 00001000 FFFFFFFF (word at position 3, second mask)
    mutation 3 = 00000000 00000000 FFFFFEFF (word at position 7, first mask)
    mutation 4 = 00000000 00000000 FFFFEFFF (word at position 7, second mask)
    mutation 5 = 00000000 00000000 FFFFFFFF (original bitstream)

    Example 4:
    fuzzing_position = [FuzzPosition(0, 2), FuzzPosition(3, 1)]
    =>
    position:    0 1 2 3  4 5 6 7  8 9 ...
    mutation 1 = 00000001 00000000 FFFFFFFF (word at position 0, first mask)
    mutation 2 = 00000010 00000000 FFFFFFFF (word at position 0, second mask)
    mutation 3 = 00000000 00000001 FFFFFFFF (word at position 4, first mask)
    mutation 4 = 00000000 00000010 FFFFFFFF (word at position 4, second mask)
    mutation 5 = 00000000 00000100 FFFFFFFF (word at position 3, first mask)
    mutation 6 = 00000000 00001000 FFFFFFFF (word at position 3, second mask)
    mutation 7 = 00000000 00000000 FFFFFFFF (original bitstream)
    """

    def __init__(
        self,
        name: str,
        file_name: str,
        fuzzing_mask: int | list[int],
        fuzzing_position: int | FuzzPosition | list[FuzzPosition],
        *args,
        **kwargs,
    ):
        with open(os.path.join(CONSTANTS.BITSTREAMS_DIR, file_name), "rb") as f:
            self._bitstream = bytearray(f.read())

        # If the bitstream starts with 0x0009 this indicates that the bitstream contains a bitstream header.
        # This is usually the case if the bitstream has been generated by Vivado or other official tools by Xilinx.
        # We cut the header because everything before the sync word is ignored by the configuration engine anyways.
        if self._bitstream.startswith(b"\x00\x09"):
            self._bitstream = self._bitstream[
                self._bitstream.index(SyncWord().render()) :
            ]

        self._bitstream_length = len(self._bitstream)

        if self._bitstream_length % 4 != 0:
            raise ValueError(
                f'the length of the bitstream "{file_name}" must be a multiple of 4'
            )

        if not isinstance(fuzzing_mask, list):
            fuzzing_mask_list = [fuzzing_mask]
        else:
            fuzzing_mask_list = fuzzing_mask

        for fuzzing_mask in fuzzing_mask_list:
            if fuzzing_mask < 0 or fuzzing_mask >= 0x100000000:
                raise ValueError("fuzzing_mask has to be >= 0 and < 0x100000000")

        self._fuzzing_mask_list = fuzzing_mask_list

        if isinstance(fuzzing_position, int):
            # Start from given position and fuzz all follwing words.
            # Ignore bytes at the end that do not form a whole word.
            fuzzing_position_list = [
                FuzzPosition(
                    fuzzing_position, (self._bitstream_length - fuzzing_position) // 4
                )
            ]
        elif not isinstance(fuzzing_position, list):
            fuzzing_position_list = [fuzzing_position]
        else:
            fuzzing_position_list = fuzzing_position

        for fuzzing_position in fuzzing_position_list:
            if (
                fuzzing_position.index_start + fuzzing_position.word_count * 4
                > self._bitstream_length
            ):
                raise ValueError("fuzzing_position will exceed bitstream length")

        self._fuzzing_position_list = fuzzing_position_list

        super(FuzzedBitstream, self).__init__(
            name=name,
            default_value=None,
            fuzzable=True,
            fuzz_values=None,
            *args,
            **kwargs,
        )

    def mutations(self, default_value):
        # This function works similar to the mutations function of the BitstreamWord primitive above.
        # The difference is that we will always yield a complete bitstream.
        # For all specified positions in this bitstream we will apply all generated submasks.
        # Apply means XORing the current submask to the current position of the original bitstream.
        for fuzzing_position in self._fuzzing_position_list:
            for word_index in range(fuzzing_position.word_count):
                # word_position is the first byte of the word at the currently fuzzed position.
                word_position = fuzzing_position.index_start + word_index * 4
                # Store the unmodiefied word at the currently fuzzed position.
                original_word = self._bitstream[word_position : word_position + 4]
                # Copy the original bitstream so we can modify it without losing the original.
                mutated_bitstream = self._bitstream.copy()
                for fuzzing_mask in self._fuzzing_mask_list:
                    sub_mask = fuzzing_mask
                    while sub_mask > 0:
                        sub_mask_bytes = sub_mask.to_bytes(4, "big")
                        # Apply the current submask to the currently fuzzed position.
                        for mask_index in range(4):
                            mutated_bitstream[word_position + mask_index] = (
                                original_word[mask_index] ^ sub_mask_bytes[mask_index]
                            )
                        yield mutated_bitstream
                        sub_mask = (sub_mask - 1) & fuzzing_mask

        # Yield the unchanged bitstream as an extra mutation because
        # the algorithm above does not consider the submask equal to zero.
        yield self._bitstream

    def encode(self, value, mutation_context):
        if isinstance(value, bytearray):
            return bytes(value)
        else:
            return b""

    def num_mutations(self, default_value):
        total_word_count = sum(
            fuzzing_position.word_count
            for fuzzing_position in self._fuzzing_position_list
        )

        return (
            sum(
                [
                    2 ** fuzzing_mask.bit_count() * total_word_count
                    for fuzzing_mask in self._fuzzing_mask_list
                ]
            )
            # Count the submask equal to zero only once.
            - len(self._fuzzing_mask_list) * total_word_count
            + 1
        )


class EncryptedSeries7Block(FuzzableBlock):
    """Custom FuzzableBlock which encrypts its child objects.

    https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html#boofuzz.FuzzableBlock

    The content of this block will be encrypted and authenticated in a way
    that it can be loaded on a Xilinx 7-series FPGA without producing an error.
    The content is encrypted by using AES-CBC and authenticated by a HMAC using SHA-256.
    Additionally necessary, unencrypted commands will be added to the bitstream.

    The block content must consist of multiple 32-bit words so that the length of the block (in bytes) is a multiple of 4.
    The pad_child_data argument can be used to automatically pad the content of the block with NOPs to match the HMAC blocksize.

    Either a key_file_name of a .nky file in the STATIC_DIR or individual values for aes_key, aes_iv, and hmac_key have to be provieded.

    The enable_encryption argument can be used to disable the automatic activation of the encryption settings.
    By default the DEC option in the CTL0 register is activated
    and the efuse_key argument is used to decide if the AES key is read from BBRAM or eFUSE.
    If enable_encryption is disabled the encryption commands have to be set manually
    in the bitstream before the EncryptedSeries7Block primitive.

    If the return_plaintext argument is enabled the block is rendered in its final structure but unencrypted.
    """

    def __init__(
        self,
        name: str = None,
        request: Request = None,
        children=None,
        pad_child_data: bool = False,
        key_file_name: str = None,
        aes_key: str = None,
        aes_iv: str = None,
        hmac_key: str = None,
        enable_encryption: bool = True,
        efuse_key: bool = False,
        return_plaintext: bool = False,
        *args,
        **kwargs,
    ):
        self._pad_child_data = pad_child_data

        if key_file_name:
            self._parse_series_7_key_file(key_file_name)
        elif aes_key and aes_iv and hmac_key:
            self._key_file = Series7KeyFile(
                device=None,
                aes_key=bytes.fromhex(aes_key),
                aes_iv=bytes.fromhex(aes_iv),
                hmac_key=bytes.fromhex(hmac_key),
            )
        else:
            raise ValueError("missing key material")

        self._hmac_key_ipad = bytes(byte ^ 0x36 for byte in self._key_file.hmac_key)
        self._hmac_key_opad = bytes(byte ^ 0x5C for byte in self._hmac_key_ipad)
        self._aes_iv_swapped = swap_endianness_and_bits(self._key_file.aes_iv)

        self._enable_encryption = enable_encryption
        self._efuse_key = efuse_key

        self._return_plaintext = return_plaintext

        super(EncryptedSeries7Block, self).__init__(
            name=name, request=request, children=children, *args, **kwargs
        )

    def encode(self, value, mutation_context):
        encrypted_data = self._get_encrypted_data(self.get_child_data(mutation_context))

        unencrypted_commands = self._get_enable_encryption_commands()
        unencrypted_commands += [
            Type1WritePacket(name="write_to_cbc", register_address=11, word_count=4),
            Static(name="aes_iv", default_value=self._key_file.aes_iv),
            Type1WritePacket(name="write_to_unknown_register_26", register_address=26),
            Static(
                name="encrypted_data_length_in_words",
                default_value=(len(encrypted_data) // 4).to_bytes(4, "big"),
            ),
        ]
        unencrypted_data = b"".join(
            primitive.render() for primitive in unencrypted_commands
        )

        # Add 16 NOPs as in an original encrypted bitstream.
        # At least two of these NOPs are actually necessary.
        final_nops = NOP(16).render()

        return unencrypted_data + encrypted_data + final_nops

    def _parse_series_7_key_file(self, key_file_name: str) -> Series7KeyFile:
        """Parse a .nky file for 7-series devices."""

        device = None
        aes_key = None
        aes_iv = None
        hmac_key = None

        with open(os.path.join(CONSTANTS.STATIC_DIR, key_file_name)) as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip(";\n").split()
                if line[0] == "Device":
                    device = line[1]
                elif line[0] == "Key" and line[1] == "0":
                    aes_key = bytes.fromhex(line[2])
                elif line[0] == "Key" and line[1] == "StartCBC":
                    aes_iv = bytes.fromhex(line[2])
                elif line[0] == "Key" and line[1] == "HMAC":
                    hmac_key = bytes.fromhex(line[2])

        if aes_key and aes_iv and hmac_key:
            self._key_file = Series7KeyFile(device, aes_key, aes_iv, hmac_key)
        else:
            raise ValueError("error when parsing .nky file: missing key(s)")

    def _get_encrypted_data(self, data: bytes) -> bytes:
        """Encrypt the given data in a format that is valid for Xilinx 7-series FPGAs."""

        data_length = len(data)

        # We can not encrypt less than one 32-bit word.
        if data_length < 4:
            raise ValueError("data_length has to be >= 4")

        # We can only encrypt a multiple of 32-bit words.
        if data_length % 4 != 0:
            raise ValueError("data_length must be a multiple of 4")

        if self._pad_child_data:
            # Pad with NOPs so that the length of child_data is a multiple of the HMAC blocksize.
            # The HMAC blocksize is 64 byte.
            data += NOP((64 - data_length % 64) // 4).render()
            data_length = len(data)

        if data_length % 64 != 0:
            raise ValueError(
                "data_length has to be a multiple of the HMAC blocksize (16 words / 64 bytes / 512 bits)"
            )

        hmac_tag = hmac.new(self._hmac_key_ipad, data, hashlib.sha256).digest()

        data_to_encrypt = (
            self._key_file.hmac_key
            + b"\x36" * 32
            + data
            + b"\x80"
            + b"\x00" * 59
            + ((data_length + 64) * 8).to_bytes(4, "big")  # In bits
            + b"\x00" * 256
            + self._hmac_key_opad
            + b"\x5C" * 32
            + b"\x00" * 32
            + b"\x80"
            + b"\x00" * 29
            + b"\x03\x00"
            + hmac_tag
        )

        if self._return_plaintext:
            return data_to_encrypt

        data_to_encrypt = swap_endianness_and_bits(data_to_encrypt)

        cipher = AES.new(self._key_file.aes_key, AES.MODE_CBC, self._aes_iv_swapped)
        ciphertext = cipher.encrypt(data_to_encrypt)

        return swap_endianness_and_bits(ciphertext)

    def _get_enable_encryption_commands(self) -> list[Fuzzable]:
        """Returns a list of commands that are necessary to enable the encryption.

        If the enable_encryption argument is False an empty list is returned.
        The efuse_key parameter decides if the EFUSE_KEY bit in the CTL0 register is set.
        """

        if self._enable_encryption:
            if self._efuse_key:
                # Set the EFUSE_KEY bit, disable ConfigFallback and set the DEC bit of the CTL0 register.
                default_value = b"\x80\x00\x04\x40"
            else:
                # Only disable ConfigFallback and set the DEC bit of the CTL0 register.
                default_value = b"\x00\x00\x04\x40"

            return [
                Type1WritePacket(name="write_to_mask", register_address=6),
                Static(name="mask_value", default_value=default_value),
                Type1WritePacket(name="write_to_ctl0", register_address=5),
                Static(name="ctl0_value", default_value=default_value),
            ]
        else:
            return []


class AuthenticatedUltraScaleBlock(FuzzableBlock):
    """Custom FuzzableBlock which authenticates its child objects.

    https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html#boofuzz.FuzzableBlock

    This is a parent block for authenticated UltraScale(+) blocks.
    There are three different authentication/encryption modes:
    - AES-GCM + X-GHASH
    - AES-GCM + RSA
    - unencrypted + RSA
    This block contains functions that are shared accross all three modes.
    """

    def __init__(
        self,
        name: str,
        request: Request,
        children,
        key_file_name: str,
        key_file: UltraScaleKeyFile,
        enable_encryption: bool,
        efuse_key: bool,
        *args,
        **kwargs,
    ):
        if key_file_name:
            self._parse_ultrascale_key_file(key_file_name)
        elif key_file:
            self._key_file = key_file
        else:
            raise ValueError("key_file_name or key_file need to be provided")

        self._enable_encryption = enable_encryption
        self._set_aes_key_source(efuse_key)

        super(AuthenticatedUltraScaleBlock, self).__init__(
            name=name, request=request, children=children, *args, **kwargs
        )

    def _parse_ultrascale_key_file(self, key_file_name: str) -> UltraScaleKeyFile:
        """Parse a .nky file for  UltraScale(+) devices."""

        device = None
        encrypt_key_select = None
        rsa_public_key_modulus = None
        rsa_public_key_digest = None
        aes_keys = []

        with open(os.path.join(CONSTANTS.STATIC_DIR, key_file_name)) as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip(";\n").split()
                if line[0] == "Device":
                    device = line[1]
                elif line[0] == "EncryptKeySelect":
                    # Apply upper() to be sure the if case in the init function matches.
                    encrypt_key_select = line[1].upper()
                elif line[0] == "RsaPublicKeyModulus":
                    rsa_public_key_modulus = line[1].replace(":", "")

                    # The modulus in .nky files generated by Vivado actually is actually 2056 bits long
                    # because it has an additional \x00 byte at the beginning of this field.
                    # If this byte exists, cut it.
                    if len(
                        rsa_public_key_modulus
                    ) == 514 and rsa_public_key_modulus.startswith("00"):
                        rsa_public_key_modulus = rsa_public_key_modulus[2:]

                    rsa_public_key_modulus = bytes.fromhex(rsa_public_key_modulus)
                elif line[0] == "RsaPublicKeyDigest":
                    rsa_public_key_digest = bytes.fromhex(line[1])
                elif line[0].startswith("Key"):
                    aes_key = bytes.fromhex(line[1])
                elif line[0].startswith("StartIV"):
                    if aes_key:
                        # Unlinke the 7-series AES IV the AES IV for UltraScale devices is only 96 bits long.
                        # Therefore select only the first 12 bytes as IV because the IVs in the .nky files are padded
                        # with zeros to 16 bytes or include a length value for the rolling keys feature.
                        aes_iv_and_length = bytes.fromhex(line[1])
                        aes_keys.append(
                            AESKey(
                                aes_key, aes_iv_and_length[:12], aes_iv_and_length[12:]
                            )
                        )
                        aes_key = None
                    else:
                        raise ValueError(f'iv "{line[0]}" has no matching AES key')

        if rsa_public_key_modulus or aes_keys:
            self._key_file = UltraScaleKeyFile(
                device,
                encrypt_key_select,
                rsa_public_key_modulus,
                rsa_public_key_digest,
                aes_keys,
            )
        else:
            raise ValueError("error when parsing .nky file: missing key(s)")

    def _set_aes_key_source(self, efuse_key: bool) -> None:
        """Set the right AES key source depending on the provided value or the .nky file."""

        if efuse_key is not None:
            self._efuse_key = efuse_key
        elif self._key_file.encrypt_key_select == "BBRAM":
            self._efuse_key = False
        elif self._key_file.encrypt_key_select == "EFUSE":
            self._efuse_key = True
        else:
            raise ValueError("unknown AES key source")

    def _get_enable_encryption_commands(self) -> list[Fuzzable]:
        """Returns a list of commands that are necessary to enable the encryption.

        If the enable_encryption argument is False an empty list is returned.
        """

        if self._enable_encryption:
            if self._efuse_key:
                # Set the EFUSE_KEY bit, disable ConfigFallback and set the DEC bit of the CTL0 register.
                default_value = b"\x80\x00\x04\x40"
            else:
                # Only disable ConfigFallback and set the DEC bit of the CTL0 register.
                default_value = b"\x00\x00\x04\x40"

            return [
                Type1WritePacket(name="write_to_mask", register_address=6),
                Static(name="mask_value", default_value=default_value),
                Type1WritePacket(name="write_to_ctl0", register_address=5),
                Static(name="ctl0_value", default_value=default_value),
            ]
        else:
            return []


class EncryptedXGHashUltraScaleBlock(AuthenticatedUltraScaleBlock):
    """This authenticated UltraScale(+) block implements the AES-GCM + X-GHASH mode.

    The content of this block will be encrypted and authenticated in a way
    that it can be loaded on a Xilinx UltraScale(+) FPGA without producing an error.
    The content is encrypted by using AES-GCM and authenticated by a
    modified version of the GHASH algorithm used in GCM. Ender et al. call this version X-GHASH.
    More details about the UltraScale bitstream encryption and authentication
    can be found in their paper: https://ieeexplore.ieee.org/document/9786118
    Additionally necessary, unencrypted commands will be added to the bitstream.

    A key_file_name of a .nky file in the STATIC_DIR has to be provided.
    Alternatively it is possible to provide a UltraScaleKeyFile object via the key_file parameter.
    The key_file argument is overruled by the key_file_name argument.

    The enable_encryption argument can be used to disable the automatic activation of the encryption settings.
    By default the DEC option in the CTL0 register is activated
    and the EncryptKeySelect value from the .nky file determines if the AES key is read from BBRAM or eFUSE.
    The efuse_key argument can be used to override the EncryptKeySelect value from the key file.
    If enable_encryption is disabled the encryption commands have to be set manually
    in the bitstream before the EncryptedXGHashUltraScaleBlock primitive.

    If the return_plaintext argument is enabled the block is rendered in its final structure but unencrypted.
    """

    def __init__(
        self,
        name: str = None,
        request: Request = None,
        children=None,
        key_file_name: str = None,
        key_file: UltraScaleKeyFile = None,
        enable_encryption: bool = True,
        efuse_key: bool = None,
        return_plaintext: bool = False,
        *args,
        **kwargs,
    ):
        super(EncryptedXGHashUltraScaleBlock, self).__init__(
            name=name,
            request=request,
            children=children,
            key_file_name=key_file_name,
            key_file=key_file,
            enable_encryption=enable_encryption,
            efuse_key=efuse_key,
            *args,
            **kwargs,
        )

        # For this primitive we only need the first AES key and AES IV.
        # The rolling keys feature for AES-GCM with XGHASH is not implemented yet.
        # Check if there is at least one AES key because the key file could only contain RSA keys.
        if not self._key_file.aes_keys:
            raise ValueError("missing AES key material")

        self._return_plaintext = return_plaintext

        # Encrypt one block where every bit is set in AES-ECB mode.
        # The resulting ciphertext is used to derive the hash key coefficients and initial checksum.
        cipher = AES.new(self._key_file.aes_keys[0].key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(b"\xFF" * 16)

        # Precalculate the hash key coefficients.
        # These coefficients are used to calculate the checksums.
        # Calculations are done in GF(2^32) with the irreducible polynomial 0x000000C5
        # but the endianness and bits are swapped.
        self._hash_key_coefficients = [int.from_bytes(ciphertext[:4], "big")]
        for i in range(31):
            # If the lowest bit of the checksum length is set a reduction is necessary and
            # the bitswapped irreducible polynomial is XORed to the "halved" previous coefficient.
            self._hash_key_coefficients.append(
                -(self._hash_key_coefficients[i] & 0x1) & 0xA3000000
                ^ self._hash_key_coefficients[i] >> 1
            )
        # Reverse the coefficients list to match the order of the checksum bits.
        self._hash_key_coefficients.reverse()

        self._initial_checksum = int.from_bytes(ciphertext[4:8], "big")
        self._initial_checksum_length = 0x80000000

    def encode(self, value, mutation_context):
        encrypted_data = self._get_encrypted_data(self.get_child_data(mutation_context))

        unencrypted_commands = self._get_enable_encryption_commands()
        unencrypted_commands += [
            Type1WritePacket(name="write_to_aes_iv", register_address=11, word_count=4),
            # The last word of the AES_IV register contains the length of the encrypted data
            # in 32-bit words (including the GCM tag).
            Static(name="aes_iv", default_value=self._key_file.aes_keys[0].iv),
            Static(
                name="encrypted_data_length_in_words",
                default_value=(len(encrypted_data) // 4).to_bytes(4, "big"),
            ),
            # Exactly 60 NOPs are necessary.
            NOP(60),
        ]
        unencrypted_data = b"".join(
            primitive.render() for primitive in unencrypted_commands
        )

        # Add 32 NOPs as in an original encrypted bitstream.
        # At least one of these NOPs is actually necessary.
        final_nops = NOP(32).render()

        return unencrypted_data + encrypted_data + final_nops

    def _get_encrypted_data(self, data: bytes) -> bytes:
        """Encrypt the given data in a format that is valid for Xilinx UltraScale(+) FPGAs.

        More information can be found in the paper by Ender et al.

        https://ieeexplore.ieee.org/document/9786118
        FIG. 1, page 5
        """

        data_length = len(data)

        # We can not encrypt less than one 32-bit word.
        if data_length < 4:
            raise ValueError("data_length has to be >= 4")

        # We can only encrypt a multiple of 32-bit words.
        if data_length % 4 != 0:
            raise ValueError("data_length must be a multiple of 4")

        # Calculate the number of 32-bit words in data.
        data_words = data_length // 4
        # Before every chunk of seven 32-bit words a checksum is inserted in the ciphertext.
        checksum_count = data_words // 7 + 1
        # The final length of the encrypted data comprises of the number of 32-bit words of the plaintext,
        # the number of checksums, and four additional 32-bit words for the 16 byte AES GCM tag.
        encrypted_data_words = data_words + checksum_count + 4

        # Reset checksum and checksum_length for new data to be encrypted.
        self._checksum = self._initial_checksum
        self._checksum_length = self._initial_checksum_length
        # The first checksum is calculated over the final length of the encrypted data.
        self._update_checksum(encrypted_data_words)

        cipher = AES.new(
            self._key_file.aes_keys[0].key, AES.MODE_GCM, self._key_file.aes_keys[0].iv
        )

        encrypted_data = b""

        # Process the data to be encrypted in chunks of 28 bytes (seven 32-bit words).
        # Insert a checksum before each chunk.
        for i in range(0, data_length, 28):
            # Encrypt the current checksum with the current chunk of data.
            plaintext = self._checksum.to_bytes(4, "big") + data[i : i + 28]
            ciphertext = cipher.encrypt(plaintext)

            if self._return_plaintext:
                encrypted_data += plaintext
            else:
                # Add the encrypted checksum and chunk to the final encrypted data.
                encrypted_data += ciphertext

            # Update the checksum for the eight previously encrypted 32-bit words.
            for i in range(4, len(ciphertext), 4):
                self._update_checksum(int.from_bytes(ciphertext[i : i + 4], "big"))

            # Incement the checksum length by eight for the eight 32-bit words added to the encrypted data
            # and update the checksum accordingly.
            self._update_checksum_length()
            self._update_checksum(self._checksum_length)

        # Add a final checksum if the last chunk consisted of seven 32-bit words.
        # Otherwise the leftover words are not protected by a checksum (only by the GCM tag).
        # This final checksum can be omitted without producing an error
        # if the checksum_count calculation is adjusted accordingly: checksum_count = (data_words + 6) // 7
        if data_length % 28 == 0:
            # The checksum also needs to be encrypted if the return_plaintext argument is enabled
            # because otherwise the GCM tag would be wrong.
            checksum_plaintext = self._checksum.to_bytes(4, "big")
            checksum_ciphertext = cipher.encrypt(checksum_plaintext)
            if self._return_plaintext:
                encrypted_data += checksum_plaintext
            else:
                encrypted_data += checksum_ciphertext

        gcm_tag = cipher.digest()

        return encrypted_data + gcm_tag

    def _update_checksum(self, word: int) -> None:
        """Process a word and update the checksum accordingly.

        https://ieeexplore.ieee.org/document/9786118
        III B., page 3

        checksum = (old checksum + word) * H

        Since all calculations are done in GF(2^32) an addition is just a XOR.
        The multiplication can also be done using only additions because the hash key coefficients have been precomputed.
        """

        # checksum = old checksum + word
        self._checksum ^= word

        # checksum = (old checksum + word) * H
        new_checksum = 0
        for i in range(32):
            if self._checksum >> i & 0x1:
                new_checksum ^= self._hash_key_coefficients[i]

        self._checksum = new_checksum

    def _update_checksum_length(self) -> None:
        """Increment the checksum length by eight by multiplying the current length with 2^8.

        Calculations are done in GF(2^32) with the irreducible polynomial 0x20574615.
        """

        # Double and reduce the current checksum length eight times.
        for i in range(8):
            # If the leftmost bit of the checksum length is set a reduction is necessary and
            # the irreducible polynomial is XORed to the doubled checksum length.
            self._checksum_length = (
                -(self._checksum_length >> 31) & 0x120574615
                ^ self._checksum_length << 1
            )


class RSAUltraScaleBlock(AuthenticatedUltraScaleBlock):
    """This block acts as parent for all RSA authenticated UltraScale(+) bitstreams.

    The structure of a valid RSA bitstream for UltraScale(+) devices is described here:
    https://docs.xilinx.com/v/u/en-US/xapp1098-tamper-resist-designs
    Figure 3, page 10
    """

    def __init__(
        self,
        name: str,
        request: Request,
        children,
        children_contain_header_and_footer: bool,
        key_file_name: str,
        key_file: UltraScaleKeyFile,
        rsa_private_key_file_name: str,
        enable_encryption: bool,
        efuse_key: bool,
        test_mode: bool,
        rdw_go: bool,
        *args,
        **kwargs,
    ):
        super(RSAUltraScaleBlock, self).__init__(
            name=name,
            request=request,
            children=children,
            key_file_name=key_file_name,
            key_file=key_file,
            enable_encryption=enable_encryption,
            efuse_key=efuse_key,
            *args,
            **kwargs,
        )

        self._children_contain_header_and_footer = children_contain_header_and_footer
        self._test_mode = test_mode
        self._rdw_go = rdw_go

        # Check if the key file contains a RSA public key modulus because the key file could only contain AES keys.
        if not self._key_file.rsa_public_key_modulus:
            raise ValueError("missing RSA public key modulus")

        if rsa_private_key_file_name:
            with open(
                os.path.join(CONSTANTS.STATIC_DIR, rsa_private_key_file_name)
            ) as f:
                self._rsa_private_key = RSA.import_key(f.read())
        else:
            raise ValueError("missing RSA private key")

    def encode(self, value, mutation_context):
        child_data = self.get_child_data(mutation_context)

        child_data_length = len(child_data)

        # We can not sign less than one 32-bit word.
        if child_data_length < 4:
            raise ValueError("child_data_length has to be >= 4")

        # We can only sign a multiple of 32-bit words.
        if child_data_length % 4 != 0:
            raise ValueError("child_data_length must be a multiple of 4")

        if self._children_contain_header_and_footer:
            # child_data_length has to be equal to the length of a valid RSA header (32 32-bit words) +
            # the FABRIC_SIZE of the target device in 32-bit words +
            # the length of a valid RSA footer (160 32-bit words).
            if (
                child_data_length // 4
                != 32 + CONSTANTS.BOARD_CONSTANTS.FABRIC_SIZE + 160
                # If the test mode bit is set shorter RSA bitstreams are allowed.
                and not self._test_mode
            ):
                raise ValueError(
                    "child_data_length in 32-bit words has to match 32 + FABRIC_SIZE + 160"
                )

            header_fabric_footer = child_data
        else:
            # Exactly 32 32-bit words.
            rsa_header = NOP(32).render()

            # Exactly FABRIC_SIZE 32-bit words.
            if (
                child_data_length // 4 != CONSTANTS.BOARD_CONSTANTS.FABRIC_SIZE
                # If the test mode bit is set shorter RSA bitstreams are allowed.
                and not self._test_mode
            ):
                raise ValueError(
                    "child_data_length in 32-bit words has to match the FABRIC_SIZE"
                )

            fabric_data = child_data

            # Exactly 160 32-bit words.
            rsa_footer_commands = [
                # The commands DGHIGH, START, and DESYNC are necessary to finish the configuration of the device.
                Type1WritePacket(name="write_to_cmd", register_address=4),
                Static(name="grestore_code", default_value=b"\x00\x00\x00\x0A"),
                NOP(2),
                Type1WritePacket(name="write_to_cmd", register_address=4),
                Static(name="dghigh_code", default_value=b"\x00\x00\x00\x03"),
                Type1WritePacket(name="write_to_cmd", register_address=4),
                Static(name="start_code", default_value=b"\x00\x00\x00\x05"),
                Type1WritePacket(name="write_to_cmd", register_address=4),
                Static(name="desync_code", default_value=b"\x00\x00\x00\x0D"),
                NOP(150),
            ]
            rsa_footer = b"".join(
                primitive.render() for primitive in rsa_footer_commands
            )

            header_fabric_footer = rsa_header + fabric_data + rsa_footer

        data_to_sign = self._prepare_data_to_sign(header_fabric_footer)
        data_to_sign_length = len(data_to_sign)

        # Depending on the length of data_to_sign a padding needs to be added to the bitstream.
        # The padding depends on the bitrate of Keccak-384 which is 832 bits = 104 byte = 26 32-bit words.
        # This padding is also appended by the Keccak implementation of pycryptodome.
        # However we need to generate it too, to add it to the bitstream.
        # On the FPGA, the padding from the bitstream is used to verify the signature.
        # https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        # Section 5.1, page 19
        bitstream_padding_words = data_to_sign_length // 4 % 26
        if bitstream_padding_words == 25:
            bitstream_padding = b"\x80\x00\x00\x01"
        else:
            bitstream_padding = (
                b"\x00\x00\x00\x01"
                + b"\x00\x00\x00\x00" * (24 - bitstream_padding_words)
                + b"\x80\x00\x00\x00"
            )

        final_block = self._get_enable_encryption_commands()
        final_block += [
            Type1WritePacket(name="write_to_idcode", register_address=12),
            Static(
                name="idcode_value",
                default_value=CONSTANTS.BOARD_CONSTANTS.DEVICE_IDCODE,
            ),
            Type1WritePacket(
                name="write_to_rsa_data_in", register_address=26, word_count=0
            ),
            # Length of rsa_public_key, rsa_public_key_padding, rsa_signature,
            # data_to_sign, and bitstream_padding in 32-bit words.
            Type2WritePacket(
                name="write_to_rsa_data_in_type_2",
                word_count=64
                + 14
                + 64
                + data_to_sign_length // 4
                + len(bitstream_padding) // 4,
            ),
            Static(
                name="rsa_public_key",
                default_value=self._key_file.rsa_public_key_modulus,
            ),
            # For the rsa_public_key we also need to add a padding to match the bitrate of Keccak-384.
            # The RSA public key has a length of 64 32-bit words, hence a padding of 14 32-bit words needs to be added.
            # The length of public key and padding in 32-bit words is now a multiple of 26
            # which is equal to the bitrate of Keccak-384 in 32-bit words.
            # The size of this padding is always be identical because the RSA public key size does not change.
            # However the RSA public key and the padding are not part of the signed data.
            Static(
                name="rsa_public_key_padding",
                default_value=b"\x00\x00\x00\x01"
                + b"\x00\x00\x00\x00" * 12
                + b"\x80\x00\x00\x00",
            ),
            Static(
                name="rsa_signature",
                default_value=self._get_rsa_signature(data_to_sign),
            ),
            Static(name="data_to_sign", default_value=data_to_sign),
            Static(name="bitstream_padding", default_value=bitstream_padding),
        ]
        if self._rdw_go:
            final_block += [
                Type1WritePacket(name="write_to_cmd", register_address=4),
                Static(name="rdw_go_code", default_value=b"\x00\x00\x00\x16"),
                # Finally three NOPs are necessary, otherwise all registers are zero.
                NOP(3),
            ]

        return b"".join(primitive.render() for primitive in final_block)

    def _prepare_data_to_sign(self, header_fabric_footer: bytes) -> bytes:
        """The IV and length value are added to the RSA header, fabric, and RSA footer.

        Additionally the data might be encrypted."""

        raise NotImplementedError(
            "this function is implemented in PlaintextRSAUltraScaleBlock and EncryptedRSAUltrascaleBlock primitives"
        )

    def _get_rsa_signature(self, data: bytes) -> bytes:
        """Calculate the RSA signature for the given data as Xilinx does it.

        Xilinx uses RSA-2048, the Keccak-384 hash function, and a PKCS #1 v1.5 encoding.
        """

        # Convert data to a bytearray to use multiple assignment for performant element swapping.
        data = bytearray(data)

        # Swap the bytewise endianness for every 32-bit word in data.
        # Example: 0x41424344 51525354 -> 0x44434241 54535251
        data[0::4], data[3::4] = data[3::4], data[0::4]
        data[1::4], data[2::4] = data[2::4], data[1::4]

        keccak_hash = keccak.new(data=data, digest_bits=384).digest()

        # Xilinx expects the hash to be reversed.
        reversed_keccak_hash = keccak_hash[::-1]

        # Construct the PKCS #1 v1.5 encoding manually because PyCryptodome can not use keccak
        # in combination with pkcs1_15 and additionally we need to reverse the hash before signing it.
        # The number of padding bytes is always identical becaus the generated hash has always the same size.
        # https://www.rfc-editor.org/rfc/rfc8017#section-9.2
        padded_hash = b"\x00\x01" + b"\xFF" * 205 + b"\x00" + reversed_keccak_hash

        # We can not use the sign function of PyCryptodome because we manually constructed the hash.
        # Therefore we use the decrypt function of the RSA private key to sign the hash.
        rsa_signature = self._rsa_private_key._decrypt(
            int.from_bytes(padded_hash, "big")
        )

        return rsa_signature.to_bytes(256, "big")


class PlaintextRSABlockUltraScale(RSAUltraScaleBlock):
    """This authenticated UltraScale(+) block implements the unencrypted + RSA mode.

    Usually this block should only contain the fabric data for the target device as children.
    If the children_contain_header_and_footer argument is set, the RSA header and RSA footer can be customized by the fuzzer.
    The RSA header should have a length 32 32-bit words and the RSA footer a length of 160 32-bit words.
    The length of the fabric data must match the defined FABRIC_SIZE for the target device.

    The RSA public key must be provided through a .nky file by specifying the key_file_name argument.
    Alternatively it is possible to provide a UltraScaleKeyFile object via the key_file parameter.
    The key_file argument is overruled by the key_file_name argument.
    Additionally it is necessary to pass a rsa_private_key_file_name of the file containing the RSA private key.
    All key files must be located in the STATIC_DIR.

    The test_mode argument sets the TEST_MODE bit in the decryption length count.
    For plaintext RSA bitstreams 25 or 26 frames of fabric data can be written without an error.
    https://patents.google.com/patent/US9218505/en
    Column 6
    https://docs.xilinx.com/v/u/en-US/xapp1098-tamper-resist-designs
    Figure 3, page 10

    The rdw_go argument can be set to false to manually construct the subsequent commands.
    https://docs.xilinx.com/v/u/en-US/xapp1098-tamper-resist-designs
    Figure 3, page 10
    """

    def __init__(
        self,
        name: str = None,
        request: Request = None,
        children=None,
        children_contain_header_and_footer: bool = False,
        key_file_name: str = None,
        key_file: UltraScaleKeyFile = None,
        rsa_private_key_file_name: str = None,
        test_mode: bool = False,
        rdw_go: bool = True,
        *args,
        **kwargs,
    ):
        super(PlaintextRSABlockUltraScale, self).__init__(
            name=name,
            request=request,
            children=children,
            children_contain_header_and_footer=children_contain_header_and_footer,
            key_file_name=key_file_name,
            key_file=key_file,
            rsa_private_key_file_name=rsa_private_key_file_name,
            enable_encryption=False,
            efuse_key=None,
            test_mode=test_mode,
            rdw_go=rdw_go,
            *args,
            **kwargs,
        )

    def _prepare_data_to_sign(self, header_fabric_footer: bytes) -> bytes:
        """The IV and length value are added to the RSA header, fabric, and RSA footer."""

        # The AES IV is not used because the bitstream is not encrypted.
        iv = Static(name="aes_iv", default_value=b"\x00\x00\x00\x00" * 3).render()

        length_in_words = len(header_fabric_footer) // 4
        if self._test_mode:
            length_in_words ^= 0x80000000

        header_fabric_footer_length = Static(
            name="header_fabric_footer_length_in_words",
            default_value=length_in_words.to_bytes(4, "big"),
        ).render()

        return iv + header_fabric_footer_length + header_fabric_footer


class EncryptedRSABlockUltraScale(RSAUltraScaleBlock):
    """This authenticated UltraScale(+) block implements the AES-GCM + RSA mode.

    Usually this block should only contain the fabric data for the target device as children.
    If the children_contain_header_and_footer argument is set, the RSA header and RSA footer can be customized by the fuzzer.
    The RSA header should have a length 32 32-bit words and the RSA footer a length of 160 32-bit words.
    The length of the fabric data must match the defined FABRIC_SIZE for the target device.

    The RSA public key must be provided through a .nky file by specifying the key_file_name argument.
    This key file must also contain AES key material, if there are multiple AES keys the block is encrypted with rolling keys.
    The rolling keys feature has only been tested with the KCU116 and XEM8320 boards.
    Modifictions to this function might be necessary for this primitive to work with other devices.
    Alternatively it is possible to provide a UltraScaleKeyFile object via the key_file parameter.
    The key_file argument is overruled by the key_file_name argument.
    Additionally it is necessary to pass a rsa_private_key_file_name of the file containing the RSA private key.
    All key files must be located in the STATIC_DIR.

    The enable_encryption argument can be used to disable the automatic activation of the encryption settings.
    By default the DEC option in the CTL0 register is activated
    and the EncryptKeySelect value from the .nky file determines if the AES key is read from BBRAM or eFUSE.
    The efuse_key argument can be used to override the EncryptKeySelect value from the key file.
    If enable_encryption is disabled the encryption commands have to be set manually
    in the bitstream before the EncryptedRSABlockUltraScale primitive.

    If the return_plaintext argument is enabled the block is rendered in its final structure but unencrypted.

    The test_mode argument sets the TEST_MODE bit in the decryption length count.
    For encrypted RSA bitstreams 24 frames of fabric data can be written without an error.
    https://patents.google.com/patent/US9218505/en
    Column 6
    https://docs.xilinx.com/v/u/en-US/xapp1098-tamper-resist-designs
    Figure 3, page 10

    The rdw_go argument can be set to false to manually construct the subsequent commands.
    https://docs.xilinx.com/v/u/en-US/xapp1098-tamper-resist-designs
    Figure 3, page 10
    """

    def __init__(
        self,
        name: str = None,
        request: Request = None,
        children=None,
        children_contain_header_and_footer: bool = False,
        key_file_name: str = None,
        key_file: UltraScaleKeyFile = None,
        rsa_private_key_file_name: str = None,
        enable_encryption: bool = True,
        efuse_key: bool = None,
        return_plaintext: bool = False,
        test_mode: bool = False,
        rdw_go: bool = True,
        *args,
        **kwargs,
    ):
        super(EncryptedRSABlockUltraScale, self).__init__(
            name=name,
            request=request,
            children=children,
            children_contain_header_and_footer=children_contain_header_and_footer,
            key_file_name=key_file_name,
            key_file=key_file,
            rsa_private_key_file_name=rsa_private_key_file_name,
            enable_encryption=enable_encryption,
            efuse_key=efuse_key,
            test_mode=test_mode,
            rdw_go=rdw_go,
            *args,
            **kwargs,
        )

        # Check if there is at least one AES key because the key file could only contain RSA keys.
        if not self._key_file.aes_keys:
            raise ValueError("missing AES key material")

        self._return_plaintext = return_plaintext

    def _prepare_data_to_sign(self, header_fabric_footer: bytes) -> bytes:
        """The IV and length value are added to the RSA header, fabric, and RSA footer.

        Additionally the data will be encrypted using all keys in the specified key file.
        """

        if not CONSTANTS.BOARD_CONSTANTS.ROW_END_POSITIONS:
            raise ValueError(
                "for the EncryptedRSAUltraScaleBlock primitive the ROW_END_POSITIONS constant must be set"
            )

        aes_keys_count = len(self._key_file.aes_keys)

        # All keys of the key file except the first one are stored within the frames.
        # To store a complete key with IV and length value eight frames are necessary.
        # Hence an exception is raised if the fabric does not consist of enough frames to store all key material.
        # For every row we need to substract two frames from the fabric size becuase they are just buffer frames.
        if (
            aes_keys_count - 1
        ) * 8 > CONSTANTS.BOARD_CONSTANTS.FABRIC_SIZE // CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH - 2 * len(
            CONSTANTS.BOARD_CONSTANTS.ROW_END_POSITIONS
        ):
            raise ValueError("there are too many AES keys")

        # At the end of each row two frames of zeros must be inserted before the data for the next row.
        # https://f4pga.readthedocs.io/projects/prjxray/en/latest/architecture/configuration.html
        # See src/constants.py for a more detailed explanation.
        row_end_positions = CONSTANTS.BOARD_CONSTANTS.ROW_END_POSITIONS
        row_end_positions.append(len(header_fabric_footer))
        # Calculate the length of two frames of zeros in bytes.
        length_of_two_frames = 2 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH * 4

        # Remove the two frames of zeros after each row.
        data_to_encrypt = bytearray(header_fabric_footer[: row_end_positions[0]])
        for i in range(len(row_end_positions) - 1):
            data_to_encrypt += header_fabric_footer[
                row_end_positions[i] + length_of_two_frames : row_end_positions[i + 1]
            ]

        length_sum = int.from_bytes(self._key_file.aes_keys[0].length, "big") * 4
        # The first key is programmed in the BBRAM or the eFUSE of the FGPA.
        # Hence we start at the second AES key in the key file.
        for aes_key in self._key_file.aes_keys[1:]:
            # Find the index of the first byte of the first frame where a part of the current key material is stored.
            # Four AES key bytes and two AES IV or length byte are stored in a frame.
            # Hence eigth frames are necessary to store a complete key with IV and length value.
            frame_start_index = (
                length_sum - 8 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH * 4
            )
            iv_and_length = aes_key.iv + aes_key.length

            # Split the AES key and the AES IV or length bytes and place them in the frames.
            for i in range(0, len(aes_key.key), 4):
                self._inset_key_material_in_frame(
                    data_to_encrypt,
                    frame_start_index,
                    aes_key.key[i : i + 4],
                    iv_and_length[i // 2 : i // 2 + 2],
                )

                # Set frame_start_index to the first byte of the next frame.
                frame_start_index += CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH * 4

            length_sum += int.from_bytes(aes_key.length, "big") * 4

        if aes_keys_count > 1 and length_sum != len(data_to_encrypt):
            raise ValueError(
                "the sum of the length values of the AES keys does not match the length of the data to be encrypted"
            )

        if self._return_plaintext:
            ciphertext = data_to_encrypt
        else:
            ciphertext = bytearray()
            if aes_keys_count == 1:
                cipher = AES.new(
                    self._key_file.aes_keys[0].key,
                    AES.MODE_GCM,
                    self._key_file.aes_keys[0].iv,
                )

                ciphertext += cipher.encrypt(data_to_encrypt)
            else:
                index_end = 0
                for aes_key in self._key_file.aes_keys:
                    cipher = AES.new(aes_key.key, AES.MODE_GCM, aes_key.iv)

                    index_start = index_end
                    index_end += int.from_bytes(aes_key.length, "big") * 4
                    ciphertext += cipher.encrypt(data_to_encrypt[index_start:index_end])

        iv = Static(name="aes_iv", default_value=self._key_file.aes_keys[0].iv).render()

        if aes_keys_count == 1:
            length_in_words = len(ciphertext) // 4
            if self._test_mode:
                length_in_words ^= 0x80000000

            ciphertext_length_in_words = length_in_words.to_bytes(4, "big")
        else:
            if self._test_mode:
                length_in_words = int.from_bytes(self._key_file.aes_keys[0].length)
                length_in_words ^= 0x80000000

                ciphertext_length_in_words = length_in_words.to_bytes(4, "big")
            else:
                ciphertext_length_in_words = self._key_file.aes_keys[0].length
        length = Static(
            name="ciphertext_length_in_words", default_value=ciphertext_length_in_words
        ).render()

        if not self._test_mode:
            # Insert the two frames of zeros after each row.
            for i in row_end_positions[: len(row_end_positions) - 1]:
                ciphertext[i:i] = b"\x00" * length_of_two_frames

        return iv + length + ciphertext

    def _inset_key_material_in_frame(
        self,
        data_to_encrypt: bytearray,
        frame_start_index: int,
        key_bytes: bytes,
        iv_bytes: bytes,
    ) -> None:
        """This function inserts part of the key material into a specified frame.

        Four AES key bytes and two AES IV or length byte are stored in a frame.
        The bitstream has the following structure:
        RSA header + 7805 frames + 2 frames of zeros (CLB, ...; block type: 000; row 00)
                    + 7805 frames + 2 frames of zeros (CLB, ...; block type: 000; row 01)
                    + 7805 frames + 2 frames of zeros (CLB, ...; block type: 000; row 10)
                    + 7805 frames + 2 frames of zeros (CLB, ...; block type: 000; row 11)
                    + 2560 frames + 2 frames of zeros (BRAM; block type: 001; row 00)
                    + 2560 frames + 2 frames of zeros (BRAM; block type: 001; row 01)
                    + 2560 frames + 2 frames of zeros (BRAM; block type: 001; row 10)
                    + 2560 frames + 2 frames of zeros (BRAM; block type: 001; row 11) + RSA footer
        Key material in the CLB frames are stored in the three words in the middle of a frame (UltraScale+).
        Key material in the BRAM frames is expanded and then stored in the first three words of a frame (UltraScale+).
        See the expand functions below for more information about the expansion of the key material.

        The values in this function were only tested with the KCU116 board and are probably device specific.
        """

        # The RSA header consists of exactly 32 32-bit words.
        # The if-case handles the first four rows of frames (CLB, ...).
        if (
            frame_start_index
            < (7805 * 4 * CONSTANTS.BOARD_CONSTANTS.FRAME_LENGTH + 32) * 4
        ):
            position = frame_start_index + 45 * 4
            data_to_encrypt[position : position + 4] = key_bytes

            # Between the four key bytes and the IV or length bytes are two bytes of regular frame data (or zeros).
            position += 6
            data_to_encrypt[position : position + 2] = iv_bytes
        # The else-case handles the remaining rows of frames (BRAM).
        else:
            # The first byte of each word contains regular frame data (or zeros).
            position = frame_start_index + 1
            key_bytes_word_1 = self._expand_key_byte_word_1(
                key_bytes[0]
            ) + self._expand_key_byte_word_1(key_bytes[1])
            data_to_encrypt[position : position + 3] = int(
                key_bytes_word_1, 2
            ).to_bytes(3, "big")

            position += 4
            key_bytes_word_2 = self._expand_key_byte_word_2(
                key_bytes[2]
            ) + self._expand_key_byte_word_2(key_bytes[3])
            data_to_encrypt[position : position + 3] = int(
                key_bytes_word_2, 2
            ).to_bytes(3, "big")

            position += 4
            iv_bytes_word_3 = self._expand_iv_byte(iv_bytes[0]) + self._expand_iv_byte(
                iv_bytes[1]
            )
            data_to_encrypt[position : position + 3] = int(iv_bytes_word_3, 2).to_bytes(
                3, "big"
            )

    def _expand_key_byte_word_1(self, byte: bytes) -> str:
        """Expands the AES key bytes in the first word of a BRAM frame."""

        binary_string = format(byte, "08b")

        return (
            binary_string[:1]
            + "0"
            + binary_string[1:3]
            + "0"
            + binary_string[3:5]
            + "0"
            + binary_string[5:7]
            + "0"
            + binary_string[7:]
        )

    def _expand_key_byte_word_2(self, byte: bytes) -> str:
        """Expands the AES key bytes in the second word of a BRAM frame."""

        binary_string = format(byte, "08b")

        return (
            "0"
            + binary_string[:2]
            + "0"
            + binary_string[2:4]
            + "0"
            + binary_string[4:6]
            + "0"
            + binary_string[6:]
        )

    def _expand_iv_byte(self, byte: bytes) -> str:
        """Expands the AES IV and length bytes in the third word of a BRAM frame."""

        binary_string = format(byte, "08b")

        return (
            binary_string[:2]
            + "0"
            + binary_string[2:4]
            + "0"
            + binary_string[4:6]
            + "0"
            + binary_string[6:]
            + "0"
        )
