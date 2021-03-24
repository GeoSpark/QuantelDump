import sys
from typing import Tuple
import logging
from dataclasses import dataclass
from datetime import date

from bitstring import BitArray

bits_table = [
    'A', 'J', 'S', '2', 'B', 'K', 'T', '3',
    'C', 'L', 'U', '4', 'D', 'M', 'V', '5',
    'E', 'N', 'W', '6', 'F', 'P', 'X', '7',
    'G', 'Q', 'Y', '8', 'H', 'R', 'Z', '9'
]

inverse_bits_table = {
    '2': 3,  '3': 7,  '4': 11, '5': 15,
    '6': 19, '7': 23, '8': 27, '9': 31,
    'A': 0,  'B': 4,  'C': 8,  'D': 12,
    'E': 16, 'F': 20, 'G': 24, 'H': 28,
    'J': 1,  'K': 5,  'L': 9,  'M': 13,
    'N': 17, 'P': 21, 'Q': 25, 'R': 29,
    'S': 2,  'T': 6,  'U': 10, 'V': 14,
    'W': 18, 'X': 22, 'Y': 26, 'Z': 30
}

shuffle_table = [5, 11, 2, 14, 16, 9, 4, 0, 12, 17, 3, 7, 13, 1, 15, 10, 6, 8]

unshuffle_table = [7, 13, 2, 10, 6, 0, 16, 11, 17, 5, 15, 1, 8, 12, 3, 14, 4, 9]

valid_pw_chars_table = BitArray('0x0000000000003fc07fbeffe00000000000000000000000000000000000000000')


@dataclass
class PaintboxOption:
    password: str
    serial_number: int
    option: int
    checksum: int
    expiry: date or None

    def __str__(self):
        text = f'''Password: {self.password}
Serial number: {self.serial_number}
Option: {self.option}
Checksum: {self.checksum}
Expiry: {self.expiry.strftime("%d/%m/%Y") if self.expiry is not None else "None"}'''

        return text


def validate_password(password: str) -> bool:
    if len(password) != 18:
        return False

    for letter in password:
        a = ord(letter)

        if a > 255:
            return False

        if valid_pw_chars_table[a] == 0:
            return False

    return True


def hash_serial(serial_number: int) -> int:
    serial_number = serial_number ^ 0xcc995533
    d5 = ((serial_number >> 16) + 0x0dda) & 0xffff
    a3 = ((serial_number & 0xffff) + 0x0dda) & 0xffff
    d4 = ((d5 * 0x8301) + 0xdbed) & 0xffff
    d4 = (a3 * 0x501b) + (d4 ^ a3)
    return d4 ^ d5


def create_checksum_characters(checksum: int) -> str:
    b = checksum & 0x1f
    a = checksum >> 5
    return bits_table[b] + bits_table[a]


def validate_checksum(checksum: int, characters: str) -> Tuple[bool, int]:
    try:
        calculated_checksum = (inverse_bits_table[characters[0]] << 5) + inverse_bits_table[characters[1]]
    except KeyError:
        raise

    if calculated_checksum != checksum:
        return False, calculated_checksum
    else:
        return True, calculated_checksum


def swizzle(deswizzled_bytes: bytes, checksum: int) -> BitArray:
    swizzled_bits = BitArray()
    checksum_ba = BitArray(uintbe=checksum, length=32)

    for i in range(10):
        b = BitArray(uint=deswizzled_bytes[i], length=8)
        offset = 32 - (i * 3)
        r = checksum_ba[offset - 3:offset]
        b.rol(r.uint)
        offset = 32 - (i * 2)
        v = checksum_ba[offset - 8:offset]
        c = v ^ b
        swizzled_bits.append(c)

    logging.debug(f'Swizzled bytes: {swizzled_bits.hex}')

    return swizzled_bits


def deswizzle(smushed_bits: BitArray, checksum: int) -> bytes:
    deswizzled_bits = BitArray()
    checksum_ba = BitArray(uintbe=checksum, length=32)

    for i in range(10):
        offset = 32 - (i * 2)
        v = checksum_ba[offset - 8:offset]
        b = smushed_bits[i * 8:(i + 1) * 8]
        c = v ^ b
        offset = 32 - (i * 3)
        r = checksum_ba[offset - 3:offset]
        c.ror(r.uint)
        deswizzled_bits.append(c)

    logging.debug(f'Deswizzled bytes: {deswizzled_bits.hex}')

    return deswizzled_bits.bytes


def desmush_bits(smushed_bits: BitArray) -> Tuple[int, str]:
    desmushed_bytes = ''
    checksum = 0

    for idx in range(16):
        v = smushed_bits[idx * 5:(idx + 1) * 5].uint
        w = (v ^ checksum) & 0x1f
        checksum += v
        desmushed_bytes += bits_table[w]

    logging.debug(f'Calculated checksum: {checksum}')
    logging.debug(f'Desmushed string: {desmushed_bytes}')

    return checksum, desmushed_bytes


def smush_bits(unshuffled_password: str) -> Tuple[int, BitArray]:
    smushed_bits = BitArray()
    checksum = 0

    for idx in range(16):
        # Extract the 5-bit value for each character and concatenate them.
        v = inverse_bits_table[unshuffled_password[idx]]
        w = (v ^ checksum) & 0x1f
        checksum += w
        smushed_bits.append(BitArray(uint=w, length=5))

    logging.debug(f'Calculated checksum: {checksum}')
    logging.debug(f'Smushed bytes: {smushed_bits.hex}')

    return checksum, smushed_bits


def encode(input_bytes: bytes) -> bytes:
    input_buff = BitArray(input_bytes)
    encoded_bits = BitArray([0] * 80)

    for idx in range(80):
        # calculate input bit position
        d3 = ((idx + 1) * 11) % 80

        # get the input bit
        d1 = input_buff[d3]

        # invert every other bit
        if (idx & 1) == 1:
            d1 = ~d1

        # set output bit
        if d1 & 1:
            encoded_bits.invert(idx)

    logging.debug(f'Encoded bytes:    {encoded_bits.hex}')

    return encoded_bits.bytes


def decode(swizzled_bytes: bytes) -> bytes:
    decoded_bits = BitArray([0] * 80)
    input_buff = BitArray(swizzled_bytes)

    for idx in range(80):
        # calculate input bit position
        d3 = 79 - ((idx * 29) % 80)

        # get the input bit
        d1 = input_buff[d3]

        # invert every other bit
        if (idx & 1) == 0:
            d1 = ~d1

        # set output bit
        decoded_bits[idx] = d1 & 1

    logging.debug(f'Decoded bytes:    {decoded_bits.hex}')

    return decoded_bits.bytes


def shuffle_password(unshuffled_password: str) -> str:
    shuffled_password = ''

    for idx in range(18):
        j = shuffle_table[idx]
        shuffled_password += unshuffled_password[j]

    logging.debug(f'Shuffled password: {shuffled_password}')

    return shuffled_password


def unshuffle_password(password: str) -> str:
    unshuffled_password = ''

    for idx in range(18):
        j = unshuffle_table[idx]
        unshuffled_password += password[j]

    logging.debug(f'Unshuffled password: {unshuffled_password}')

    return unshuffled_password


def get_paintbox_option(serial_number: int, password: str):
    logging.info(f'Decrypting password {password} with serial number {serial_number}')

    unshuffled_password = unshuffle_password(password)
    calculated_checksum, smushed_bits = smush_bits(unshuffled_password)

    try:
        is_checksum_valid, expected_checksum = validate_checksum(calculated_checksum, unshuffled_password[17] + unshuffled_password[16])
    except KeyError:
        logging.error('Something is wrong with the unshuffled password. Aborting')
        sys.exit(-1)

    if not is_checksum_valid:
        logging.warning(f'Checksum {calculated_checksum} does not match expected checksum {expected_checksum}')
    else:
        logging.debug(f'Checksum from password: {expected_checksum}')

    deswizzled_bytes = deswizzle(smushed_bits, hash_serial(serial_number))
    decoded_bytes = decode(deswizzled_bytes)

    encoded_serial_number = int.from_bytes(decoded_bytes[0:4], byteorder='big', signed=False)

    if encoded_serial_number != serial_number:
        logging.warning(
            f'Supplied serial number {serial_number} does not match the encoded one {encoded_serial_number}')

    option_number = int.from_bytes(decoded_bytes[4:8], byteorder='big', signed=False)
    expiry = BitArray(decoded_bytes[8:])
    year = expiry[0:7].uint + 1988
    month = expiry[7:11].uint
    day = expiry[11:].uint

    try:
        expiry_date = date(year, month, day)
    except ValueError:
        expiry_date = None

    return PaintboxOption(password, encoded_serial_number, option_number, calculated_checksum, expiry_date)


def create_password(serial_number: int, option: int, expiry: date) -> PaintboxOption:
    if expiry is not None:
        year = BitArray(uint=expiry.year - 1988, length=7)
        month = BitArray(uint=expiry.month, length=4)
        day = BitArray(uint=expiry.day, length=5)
        expiry_bits = year + month + day
    else:
        expiry_bits = BitArray(16)

    input_bytes = BitArray(uintbe=serial_number, length=32)
    input_bytes.append(BitArray(uintbe=option, length=32))
    input_bytes.append(expiry_bits)
    output_buff = encode(input_bytes.bytes)
    hashed = hash_serial(serial_number)
    smushed_bits = swizzle(output_buff, hashed)
    checksum, deshuffled_password = desmush_bits(smushed_bits)
    deshuffled_password += create_checksum_characters(checksum)
    password = shuffle_password(deshuffled_password)

    if not validate_password(password):
        logging.warning(f'Generated password {password} is not valid')

    return PaintboxOption(password, serial_number, option, checksum, expiry)


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    # pb_opt = get_paintbox_option(13464, '2DMWG37TM37N5PAKXS')  # Option 46 Expiry 15/01/96
    pb_opt = get_paintbox_option(13464, '7VLVYM6T634JVNS5WY')  # Option 66 Expiry 03/07/95
    # pb_opt = get_paintbox_option(10866, 'GX9EZKC4DTGSM5ZYNV')  # Font 10064
    # pb_opt = get_paintbox_option(10000, 'VVUE2QDXV3RQQW6TRQ')  # Option 13063 Expiry 0
    print(pb_opt)
    print(create_password(13464, 66, date(1995, 7, 3)))
