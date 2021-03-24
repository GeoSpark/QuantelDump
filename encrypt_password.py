from bitstring import BitArray

from decrypt_password import hash_serial

bits_table = [
    'A', 'J', 'S', '2', 'B', 'K', 'T', '3',
    'C', 'L', 'U', '4', 'D', 'M', 'V', '5',
    'E', 'N', 'W', '6', 'F', 'P', 'X', '7',
    'G', 'Q', 'Y', '8', 'H', 'R', 'Z', '9'
]


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
        checksum += v
        v = v ^ checksum
        v = v & 0x1f
        scrambled_password.append(bits_table[v])
    return checksum, scrambled_password


def main():
    params = (10000, 13063, 0)
    input_bytes = BitArray(uintbe=params[0], length=32)
    input_bytes.append(BitArray(uintbe=params[1], length=32))
    input_bytes.append(BitArray(uintbe=params[2], length=16))
    output_buff = encode(input_bytes)
    hashed = hash_serial(params[0])
    smushed_bytes = deswizzle(BitArray(output_buff), hashed)
    checksum, scrambled_password = desmush_bits(BitArray(smushed_bytes))

    print(BitArray(input_bytes).hex)
    print(BitArray(output_buff).hex)
    print(BitArray(smushed_bytes).hex)
    print(checksum)
    print(''.join(scrambled_password))

    pass


if __name__ == '__main__':
    main()
