from bitstring import BitArray

from decrypt_password import hash_serial

bits_table = [
    'A', 'J', 'S', '2', 'B', 'K', 'T', '3',
    'C', 'L', 'U', '4', 'D', 'M', 'V', '5',
    'E', 'N', 'W', '6', 'F', 'P', 'X', '7',
    'G', 'Q', 'Y', '8', 'H', 'R', 'Z', '9'
]

deshuffle_table = [5, 11, 2, 14, 16, 9, 4, 0, 12, 17, 3, 7, 13, 1, 15, 10, 6, 8]


def encode(input_bytes):
    input_buff = BitArray(input_bytes)
    output_buff = BitArray([0] * 80)

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
            output_buff.invert(idx)

    return output_buff.bytes


def deswizzle(swizzled_bits, checksum):
    smushed_bits = BitArray()
    checksum_ba = BitArray(uintbe=checksum, length=32)

    for i in range(10):
        b = swizzled_bits[i * 8:(i + 1) * 8]
        offset = 32 - (i * 3)
        r = checksum_ba[offset - 3:offset]
        b.rol(r.uint)
        offset = 32 - (i * 2)
        v = checksum_ba[offset - 8:offset]
        c = v ^ b
        smushed_bits.append(c)

    return smushed_bits.bytes


def desmush_bits(smushed_bits):
    scrambled_password = []
    checksum = 0


    for idx in range(16):
        v = smushed_bits[idx * 5:(idx + 1) * 5].uint
        w = (v ^ checksum) & 0x1f
        checksum += v
        scrambled_password.append(bits_table[w])
    return checksum, scrambled_password


def create_checksum_characters(checksum):
    b = checksum & 0x1f
    a = checksum >> 5
    return bits_table[b], bits_table[a]


def scramble_password(descrambled_password):
    scrambled_password = ''

    for idx in range(18):
        j = deshuffle_table[idx]
        scrambled_password += descrambled_password[j]

    return scrambled_password


def main():
    params = (10000, 13063, (0, 0, 88))
    # params = (13464, 46, (15, 1, 96))
    year = BitArray(uint=params[2][2] - 88, length=7)
    month = BitArray(uint=params[2][1], length=4)
    day = BitArray(uint=params[2][0], length=5)
    date = year + month + day
    input_bytes = BitArray(uintbe=params[0], length=32)
    input_bytes.append(BitArray(uintbe=params[1], length=32))
    input_bytes.append(date)
    output_buff = encode(input_bytes)
    hashed = hash_serial(params[0])
    smushed_bytes = deswizzle(BitArray(output_buff), hashed)
    # This is wrong, and I can't figure out why. It's a brainfart, I'm sure.
    checksum, scrambled_password = desmush_bits(BitArray(smushed_bytes))
    a, b = create_checksum_characters(checksum)
    scrambled_password.append(a)
    scrambled_password.append(b)

    print(BitArray(input_bytes).hex)
    print(BitArray(output_buff).hex)
    print(BitArray(smushed_bytes).hex)
    print(checksum)
    print(''.join(scrambled_password))
    print(scramble_password(scrambled_password))

if __name__ == '__main__':
    main()
