#!/usr/bin/env python3
import sys
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# 0000000000000000 <guest_func_26>:
func_pattern = re.compile("\s*[0-9a-fA-F]{16} \<.*?\>:\s*\n?")

def is_function(line):
    match = func_pattern.fullmatch(line)
    return match

def is_end_of_function(line):
    return line == "" or line == "\n"

func_name_pattern = re.compile(".*?\<(.*)\>")

def get_func_name(line):
    match = func_name_pattern.search(line)
    return match.group(1)


#    3633:	75 a1                	jne    35d6 <guest_func_24+0x35d6>
jump_pattern = re.compile(".*?\t.*?\tj.*\n?")

def is_jump_instruction(line):
    match = jump_pattern.fullmatch(line)
    return match

jump_offset_pattern = re.compile("\s*([0-9a-fA-F]+):.*")

def get_jump_offset(line):
    match = jump_offset_pattern.search(line)
    hex_str = "0x" + match.group(1)
    return int(hex_str, 0)

def scan_file(input_file, alignment):
    STATE_SCANNING = 0
    STATE_FOUND_FUNCTION = 1

    state = STATE_SCANNING
    function_line = ""
    count = 0

    with open(input_file, "r") as f:
        line_num = 0
        for line in f:
            line_num = line_num + 1
            if state == STATE_SCANNING and is_function(line):
                state = STATE_FOUND_FUNCTION
                function_name = get_func_name(line)
            elif state == STATE_FOUND_FUNCTION and is_end_of_function(line):
                state = STATE_SCANNING
                function_name = ""
            elif state == STATE_FOUND_FUNCTION and is_jump_instruction(line):
                offset = get_jump_offset(line)
                align = offset % alignment
                out_str = input_file + ":" + str(line_num) + \
                    " Func: " + function_name + \
                    " Aligned: " + str(align) + \
                    " || " + line
                if align != 0:
                    count = count + 1
                    print(bcolors.FAIL + out_str + bcolors.ENDC)
                else:
                    print(bcolors.OKGREEN + out_str + bcolors.ENDC)
                    

                if count > 100:
                    print("Over 100 violations")
                    sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Usage: " + sys.argv[0] + " test.asm alignment_val")
        sys.exit(1)

    scan_file(sys.argv[1], int(sys.argv[2]))


main()