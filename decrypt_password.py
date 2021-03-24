from bitstring import BitArray

bits_table = {'0': 0x00ff,
              '1': 0x00ff,
              '2': 0x0003,
              '3': 0x0007,
              '4': 0x000b,
              '5': 0x000f,
              '6': 0x0013,
              '7': 0x0017,
              '8': 0x001b,
              '9': 0x001f,
              ':': 0x00ff,
              ';': 0x00ff,
              '<': 0x00ff,
              '=': 0x00ff,
              '>': 0x00ff,
              '?': 0x00ff,
              '@': 0x00ff,
              'A': 0x0000,
              'B': 0x0004,
              'C': 0x0008,
              'D': 0x000c,
              'E': 0x0010,
              'F': 0x0014,
              'G': 0x0018,
              'H': 0x001c,
              'I': 0x00ff,
              'J': 0x0001,
              'K': 0x0005,
              'L': 0x0009,
              'M': 0x000d,
              'N': 0x0011,
              'O': 0x00ff,
              'P': 0x0015,
              'Q': 0x0019,
              'R': 0x001d,
              'S': 0x0002,
              'T': 0x0006,
              'U': 0x000a,
              'V': 0x000e,
              'W': 0x0012,
              'X': 0x0016,
              'Y': 0x001a,
              'Z': 0x001e
              }

shuffle_table = [
    0x0007, 0x000d, 0x0002, 0x000a,
    0x0006, 0x0000, 0x0010, 0x000b,
    0x0011, 0x0005, 0x000f, 0x0001,
    0x0008, 0x000c, 0x0003, 0x000e,
    0x0004, 0x0009
]

# This is a bitfield that is checked early on for valid password characters.
valid_pw_chars_table = [
    0x0000, 0x0000, 0x0000, 0xfc03,
    0xfe7d, 0xff07, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000
]

password = (10000, 'VVUE2QDXV3RQQW6TRQ')  # Option 13063 Expiry 0
# password = (13464, '2DMWG37TM37N5PAKXS')  # Option 46 Expiry 15/01/96
# password = (13464, '7VLVYM6T634JVNS5WY')  # Option 66 Expiry 03/07/95


def hash_serial(serial_number):
    serial_number = serial_number ^ 0xcc995533
    d5 = ((serial_number >> 16) + 0x10dda) & 0xffff
    a3 = ((serial_number & 0xffff) + 0x10dda) & 0xffff
    d4 = ((d5 * 0x8301) + 0xdbed) & 0xffff
    d6 = d4 ^ a3
    d4 = (a3 * 0x501b) + d6
    return d4 ^ d5


def validate_checksum(checksum, a, b):
    aa = bits_table[a] << 5
    bb = bits_table[b]
    cc = aa + bb
    if cc != checksum:
        return 1
    else:
        return 0


def swizzle(smushed_bits, checksum):
    swizzled_bits = BitArray()
    checksum_ba = BitArray(uintbe=checksum, length=32)

    for i in range(10):
        offset = 32 - (i * 2)
        v = checksum_ba[offset - 8:offset]
        b = smushed_bits[i * 8:(i + 1) * 8]
        c = v ^ b
        offset = 32 - (i * 3)
        r = checksum_ba[offset - 3:offset]
        c.ror(r.uint)
        swizzled_bits.append(c)

    return swizzled_bits.bytes


def smush_bits(descrambled_password):
    smushed_bits = BitArray()
    checksum = 0
    for idx in range(16):
        # Extract the 5-bit value for each character and concatenate them.
        v = bits_table[descrambled_password[idx]]
        v = v ^ checksum
        v = v & 0x1f
        checksum += v
        smushed_bits.append(BitArray(uint=v, length=5))
    return checksum, smushed_bits


def ror_l(value, count):
    a = BitArray(uint=value, length=32)
    a.ror(count)

    return a.uintbe


def rol_w(value, count):
    a = BitArray(uint=value, length=32)
    a.rol(count, 16, 32)

    return a.uintbe


def ror_w(value, count):
    a = BitArray(uint=value, length=32)
    a.ror(count, 16, 32)

    return a.uintbe


def swap(value):
    a = value & 0xffff
    b = value >> 16
    return (a << 16) + b


def decode(swizzled_bytes):
    output_buff = bytearray([0x00] * 10)

    for idx in range(80):
        d0 = ror_l(idx, 3)
        a0 = d0 & 0xff
        d0 = swap(d0)
        d0 = rol_w(d0, 3) & 0xffff
        d4 = idx * 0x1d
        d3 = -(d4 % 80)
        d3 += 0x4f
        d3 &= 0xffff
        d3 = BitArray(uintbe=d3, length=32)
        d3.ror(3)
        offset = d3[16:].uintbe
        d1 = swizzled_bytes[offset]
        d3 = d3[:16]
        d3.rol(3)
        d1 = (d1 << d3.uintbe) & 0xff
        d1 >>= 7

        if idx % 2 == 0:
            d1 = -d1
            d1 += 1

        d2 = ror_w(0xff7f, d0)
        output_buff[a0] = d2 & output_buff[a0]
        d1 = d1 & 0x01
        d1 <<= 7
        d1 >>= d0
        output_buff[a0] = d1 | output_buff[a0]
    return output_buff


def main():
    descrambled_password = ''

    # Descramble the incoming string.
    for idx in range(18):
        j = shuffle_table[idx]
        descrambled_password += password[1][j]

    checksum, smushed_bits = smush_bits(descrambled_password)
    is_font = validate_checksum(checksum, descrambled_password[17], descrambled_password[16])
    d6 = hash_serial(password[0])
    swizzled_bytes = swizzle(smushed_bits, d6)
    output_buff = decode(swizzled_bytes)

    serial_number = int.from_bytes(output_buff[0:4], byteorder='big', signed=False)
    option_number = int.from_bytes(output_buff[4:8], byteorder='big', signed=False)
    expiry = BitArray(output_buff[8:])
    year = expiry[0:7].uint + 88
    month = expiry[7:11].uint
    day = expiry[11:].uint

    print(BitArray(output_buff).hex)
    print(f'Is font: {is_font}')
    print(f'Serial number: {serial_number}')
    print(f'Option: {option_number}')
    print(f'Expiry: {day}/{month}/{year}')


if __name__ == '__main__':
    main()
