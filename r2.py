from typing import List, Tuple

from utils import extract_strings


def flag_command(name: str, address_range: List[int]) -> str:
    length = address_range[1] - address_range[0]
    return f'f {name} {length} @ {hex(address_range[0])}'


def line_command(module_name: str, line: Tuple) -> str:
    return f'CL {hex(line[0])} {module_name}:{line[1]}'


def anal_function_command(function_name: str, start_address: int) -> str:
    return f'af {function_name} {hex(start_address)}'


def data_array_command(address_range: List[int]) -> str:
    length = address_range[1] - address_range[0]
    return f'Cd 1 {length} @ {hex(address_range[0])}'


def string_command(address: int, length: int) -> str:
    return f'Csa {length} @ {hex(address)}'


def preamble():
    return '''# This will cause r2 to throw out a lot of warnings, but they're harmless. 
# It's because it can't tell the difference between code and data, and the 
# Pascal compiler will occasionally put data right in the middle of a code 
# block.

e anal.arch = m68k
e anal.cpu = 68040
e asm.arch = m68k
e asm.cpu = 68040
e prj.git = false
e cfg.fortunes = 0
e asm.hint.call.indirect = false
e bin.baddr = 0x00400000
e bin.laddr = 0x00400000
e file.offset = 0x00400000
# Your modern types are useless here.
t-*
# Not sure I need this line.
o Quantel-Paintbox-Express-v1-15-002.bin 0x00400000 r-x'''


def postamble():
    return '''fs *
# Sort functions by address.
aflsa
# These are known strings that are the lookup table for producing passwords.
Cs 32 @S5_ENCRYPT
Cs 32 @S6_DECRYPT
s 0x00400000'''


def print_r2_commands(addr_blocks, machine_code_functions, modules, pascal_functions, data_blocks):
    print(preamble())

    print('fs modules')

    for k, v in modules.items():
        print(flag_command(k, v))

    print('fs functions')

    # Functions without line numbers
    for k, v in machine_code_functions.items():
        print(flag_command(k, v))

    # Functions with line numbers
    for k, v in pascal_functions.items():
        print(flag_command(k, v[1]))

    # Unknown address ranges
    print('fs unknowns')
    unknown_id = 0
    for r in addr_blocks:
        print(flag_command(f'unknown_{unknown_id:04}', r))
        unknown_id += 1

    # Globals and locals found before functions
    for block in data_blocks:
        print(data_array_command(block))
        strings = extract_strings(block[0], block[2])

        for address, string in strings.items():
            print(string_command(address, len(string)))

    # Source line numbers
    for k, v in pascal_functions.items():
        for line in v[2]:
            print(line_command(v[0], line))

    # Function analysis
    for k, v in machine_code_functions.items():
        print(anal_function_command(k, v[0]))

    for k, v in pascal_functions.items():
        print(anal_function_command(k, v[1][0]))

    print(postamble())
