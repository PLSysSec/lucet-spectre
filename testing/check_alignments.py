#!/usr/bin/env python3
import sys
import re
import argparse

class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

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
#     2e9b:	e9 d0 fe ff ff       	jmpq   2d70 <.plt>
uncond_fixed_jump = re.compile(".*?\t.*?\tjmp[a-z]*\s+[0-9a-fA-F]+.*\n?")

def is_jump_instruction(line):
    match = jump_pattern.fullmatch(line)
    uncond_match = uncond_fixed_jump.fullmatch(line)
    if uncond_match:
        return None
    return match

#     d57:	41 ff e7             	jmpq   *%r15
indirect_jump_pattern = re.compile(".*?\t.*?\tj[a-z]*\s+\*.*\n?")
def is_indirect_jump_instruction(line):
    match = indirect_jump_pattern.fullmatch(line)
    return match

jump_offset_pattern = re.compile("\s*([0-9a-fA-F]+):.*")

def get_jump_offset(line):
    match = jump_offset_pattern.search(line)
    hex_str = "0x" + match.group(1)
    return int(hex_str, 0)

# assigned later
def matches_function(func_name, func_match_pat):
    match = func_match_pat.fullmatch(func_name)
    return match

def print_ok(out_str, loginfo):
    if loginfo:
        print(bcolors.OKGREEN + out_str + bcolors.ENDC)

error_count = 0
def print_error(out_str, limit):
    print(bcolors.FAIL + out_str + bcolors.ENDC)
    global error_count
    error_count = error_count + 1
    if limit >= 0 and error_count >= limit:
        print("At least " + str(limit) + " violations")
        sys.exit(1)

def scan_file(input_file, alignment, alignment_block, func_match_pat, limit, loginfo, check_indirect_branches):
    STATE_SCANNING = 0
    STATE_FOUND_FUNCTION = 1

    state = STATE_SCANNING
    function_line = ""

    with open(input_file, "r") as f:
        line_num = 0
        for line in f:
            line_num = line_num + 1
            if state == STATE_SCANNING and is_function(line) and matches_function(get_func_name(line), func_match_pat):
                state = STATE_FOUND_FUNCTION
                function_name = get_func_name(line)
            elif state == STATE_FOUND_FUNCTION and is_end_of_function(line):
                state = STATE_SCANNING
                function_name = ""
            elif state == STATE_FOUND_FUNCTION and is_jump_instruction(line):
                offset = get_jump_offset(line)
                align = offset % alignment_block
                out_str = input_file + ":" + str(line_num) + \
                    " Func: " + function_name + \
                    " Aligned: " + str(align) + "/" + str(alignment_block) + \
                    " || " + line
                if check_indirect_branches == False and is_indirect_jump_instruction(line):
                    continue
                if align != alignment:
                    print_error(out_str, limit)
                else:
                    print_ok(out_str, loginfo)

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, add_help=True)
    parser.add_argument("file", type=str, help="Asm file to check")
    parser.add_argument("--align", type=int, default=31, help="Alignment of branches to check for")
    parser.add_argument("--alignblock", type=int, default=32, help="Alignment block size to use")
    parser.add_argument("--func", type=str, default="*", help="Function name to check")
    parser.add_argument("--limit", type=int, default=-1, help="Stop at `limit` errors")
    parser.add_argument("--loginfo", type=str2bool, default=True, help="Print log level information")
    parser.add_argument("--checkindirect", type=str2bool, default=False, help="Check indirect branches for alignment")
    args = parser.parse_args()

    func_match_pat = re.compile(args.func.replace('*', '.*'))
    scan_file(args.file, args.align, args.alignblock, func_match_pat, args.limit, args.loginfo, args.checkindirect)

    if error_count != 0:
        sys.exit(1)


main()