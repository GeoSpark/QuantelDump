from typing import List
from collections import OrderedDict


def parse_string_candidate(buffer: bytearray):
    # The simple case that a string's length matches its length byte.
    # Some strings aren't Pascal-style, so treat them as null-terminated if the length is 0.
    if buffer[0] == 0 or buffer[0] == len(buffer) - 1:
        return [(1, buffer[1:].decode('ascii'))]

    # The next simple case that the first byte of the string is the length. I.e. > 31
    if buffer[1] == len(buffer) - 2:
        return [(2, buffer[2:].decode('ascii'))]

    # Here we deal with two or more adjacent strings, separated by a length > 31

    # If our length byte is too big, then the first character of the string must be the length.
    offset = 1
    if buffer[0] > len(buffer) - 1:
        offset = 2

        # If we're still too long, then we're probably not a string. Better to be safe than sorry.
        if buffer[1] > len(buffer) - 2:
            return []

    strings = []

    while offset < len(buffer):
        length = buffer[offset - 1]
        strings.append((offset, buffer[offset:offset + length].decode('ascii')))
        offset = offset + length + 1

    return strings


def extract_strings(base_address: int, data_block: List[int]) -> OrderedDict:
    buffer = bytearray()
    strings = OrderedDict()
    buffer_origin = 0

    for current in range(len(data_block)):
        value = data_block[current]

        if 31 < value < 127:
            if len(buffer) == 0 and current > 0:
                buffer.append(data_block[current - 1])
                buffer_origin = current

            buffer.append(value)
        else:
            # Ignore short strings.
            if len(buffer) > 5:
                for s in parse_string_candidate(buffer):
                    # strings[base_address + buffer_origin + s[0] - 1] = s[1]
                    strings[base_address + buffer_origin + s[0] - 1] = len(s[1])

            buffer.clear()

    return strings


