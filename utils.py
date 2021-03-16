from typing import List
from collections import OrderedDict

'''Strings are tricky. Pascal strings have a byte length followed by the string rather than being null-terminated.
But not all strings in the code are Pascal-style. Also some lengths can be in the valid 7-bit ASCII range (32-127)
which makes figuring out where they start an interesting challenge. This code ignores strings less than 5 characters on the
assumption that a 4-byte numerical value could look like a valid ASCII string.
It makes an attempt to check the length of the string against its length byte, and makes a decision based on that. So far I've
not noticed any false positives, but there are a bunch of false negatives which is preferable.'''

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
                    strings[base_address + buffer_origin + s[0] - 1] = s[1]

            buffer.clear()

    return strings


def print_addr(address: int, contents: str):
    print(f'{hex(address)} {contents}')


def print_strings(data_blocks):
    for block in data_blocks:
        strings = extract_strings(block[0], block[2])

        for address, string in strings.items():
            print_addr(address, string)


def print_functions(machine_code_functions, pascal_functions):
    for k, v in machine_code_functions.items():
        print_addr(v[0], k)

    for k, v in pascal_functions.items():
        print_addr(v[1][0], k)

