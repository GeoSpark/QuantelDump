#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
It's not pretty. It's barely commented. And there's probably more bugs than in the latest AAA title.
This has only been tested on a v1-15-002 dump, YMMV for other versions.
'''

import sys
from typing import List
from collections import OrderedDict
import csv

from r2 import print_r2_commands
from utils import print_strings, print_functions

'''A list of ranges that correspond to source lines that simply have Addr in the 3rd column. This can be data or code, but it's
not known which, and the Pascal compiler had a tendency to mix them.'''
addr_blocks = [[0x400000, 0x400000]]

'''This is a dictionary with function name as the key, and an address range as the value. This is code that has byte offsets in the
dump, rather than source line numbers. This is likely to be standard library routines and other low-level code.'''
machine_code_functions = OrderedDict()

'''A dictionary of module names and address ranges. A module is any part of a function name before the last dot, if it has one.
Usually this is in upper case and will be something like S8_SECURITY or MENUCOM.'''
modules = OrderedDict()

'''A dict of function names (with module name) and a list as the key. The list has module name, address range, and line numbers.
The line numbers is a list of pairs of values [address, line number], where address is the start of the line, and the line
number is relative to the start of the module.'''
pascal_functions = OrderedDict()

'''Global and local variables usually found immediately before a function. The code assumes that global variables are placed at the
top of the module, and carry on until the first function, which is assumed to be marked by the LINK instruction (0x4E56).
It is a list of lists with start and end addresses, followed by a list of bytes (actually ints < 256).'''
data_blocks = [[0x400006, 0x40003c, []]]


def parse_hex(hex_string: str) -> int:
    '''Trim off the leading $ and interpret the string as a hex value.'''
    return int(hex_string[1:], 16)


def handle_addr_line(fields: List[str]):
    '''Addr blocks are unknowable blobs, so just store the start and end addresses.'''
    addr = parse_hex(fields[0])

    if addr_blocks[-1][1] < addr - 2:
        addr_blocks.append([addr, addr])
    else:
        addr_blocks[-1][1] = addr


def handle_machine_code_line(fields: List[str]):
    '''Machine code functions have no metadata apart from byte offset from the start of the module. The offset is appended to the
    function name, so strip it off and record just the address range.'''
    addr = parse_hex(fields[0])
    function_name = fields[2].split('+')[0].replace('$', '_')

    if function_name not in machine_code_functions:
        machine_code_functions[function_name] = [addr, 0]
    else:
        machine_code_functions[function_name][1] = addr


def handle_debug_line(fields: List[str]):
    '''Some functions have a $ in the name which r2 doesn't like, so replace it with an underscore.
    The globals data block is marked with a (+-1) so we don't treat that as code, instead we add the contents to the data_blocks
    list. When we find the first LINK instruction ($4E56) we assume that everything after that is code.
    Code line number addresses appear to be off by a WORD, so we subtract 2 from the address for each line number.'''
    addr = parse_hex(fields[0])
    signature = fields[2].replace('$', '_')
    line_number = int(fields[3])
    is_code_line = fields[4] != '(+-1)'
    content = parse_hex(fields[1])
    is_function_start = fields[1] == '$4E56'

    if '.' in signature:
        signature_parts = signature.split('.')

        module_name = '.'.join(signature_parts[:-1])

        if module_name not in modules:
            modules[module_name] = [addr, 0]
        else:
            modules[module_name][1] = addr
    else:
        module_name = 'STDLIB'

    if signature not in pascal_functions:
        if not is_function_start:
            content_bytes = divmod(content, 256)

            if len(data_blocks) == 0 or data_blocks[-1][1] < addr - 2:
                data_blocks.append([addr, 0, list()])

            # Because we might not have a datablock before a function, just add two to account for the off-by-one
            # we get for not counting the function start in the length calculation
            data_blocks[-1][1] = addr + 2
            data_blocks[-1][2].extend(content_bytes)
            return

        pascal_functions[signature] = [module_name, [addr, addr], [(addr, line_number)]]
    else:
        f = pascal_functions[signature]
        f[1][1] = addr
        lines = f[2]

        if (len(lines) == 0 or lines[-1][1] != line_number) and is_code_line:
            lines.append((addr - 2, line_number))


def parse_file(file_name: str):
    with open(file_name, 'rt') as f:
        reader = csv.reader(f, delimiter=' ', skipinitialspace=True)
        # Skip header line
        next(reader)

        for row in reader:
            if len(row) == 5:
                handle_debug_line(row)
            elif len(row) == 4:
                if row[2] == 'Addr':
                    handle_addr_line(row)
                else:
                    handle_machine_code_line(row)
            else:
                print(f'Unable to parse line: {" ".join(row)}', file=sys.stderr)


def main():
    parse_file(sys.argv[1])
    print_r2_commands(addr_blocks, machine_code_functions, modules, pascal_functions, data_blocks)
    # print_strings(data_blocks)
    # print_functions(machine_code_functions, pascal_functions)


if __name__ == '__main__':
    main()
