#!/usr/bin/env python
# -*- coding: utf-8 -*-

# It's not pretty. It's barely commented. And there's probably more bugs than in the latest AAA title.

import sys
from typing import List
from collections import OrderedDict
import csv

from r2 import print_r2_commands

addr_blocks = [[0x400000, 0x400000]]
machine_code_functions = OrderedDict()
modules = OrderedDict()
pascal_functions = OrderedDict()
# Global and local variables usually found immediately before a function.
data_blocks = [[0x400006, 0x40003c, []]]


def parse_hex(hex_string: str) -> int:
    return int(hex_string[1:], 16)


def handle_addr_line(fields: List[str]):
    addr = parse_hex(fields[0])

    if addr_blocks[-1][1] < addr - 2:
        addr_blocks.append([addr, addr])
    else:
        addr_blocks[-1][1] = addr


def handle_machine_code_line(fields: List[str]):
    addr = parse_hex(fields[0])
    function_name = fields[2].split('+')[0].replace('$', '_')

    if function_name not in machine_code_functions:
        machine_code_functions[function_name] = [addr, 0]
    else:
        machine_code_functions[function_name][1] = addr


def handle_debug_line(fields: List[str]):
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


if __name__ == '__main__':
    main()
