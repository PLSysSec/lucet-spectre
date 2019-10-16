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
#     3030: ff 25 7a 70 21 00       jmpq   *0x21707a(%rip) 
uncond_fixed_jump_addr1 = "([0-9a-fA-F]+)"
uncond_fixed_jump_addr2 = "(\*0x[0-9a-fA-F]+\(%rip\))"
uncond_fixed_jump = re.compile(".*?\t.*?\tjmp[a-z]*\s+(" + uncond_fixed_jump_addr1 + "|" + uncond_fixed_jump_addr2 + ").*\n?")

def is_jump_instruction(line):
    match = jump_pattern.fullmatch(line)
    uncond_match = uncond_fixed_jump.fullmatch(line)
    if uncond_match:
        return None
    return match

#     d57:	41 ff e7             	jmpq   *%r15
indirect_jump_pattern = re.compile(".*?\t.*?\tj[a-z]*\s+\*%r.*\n?")
def is_indirect_jump_instruction(line):
    match = indirect_jump_pattern.fullmatch(line)
    return match

# 7874:	ff d0                	callq  *%rax
indirect_call_pattern = re.compile(".*?\t.*?\tcall[a-z]*\s+\*%r.*\n?")
def is_indirect_call_instruction(line):
    match = indirect_call_pattern.fullmatch(line)
    return match

offset_pattern = re.compile("\s*([0-9a-fA-F]+):.*")

def get_line_offset(line):
    match = offset_pattern.search(line)
    hex_str = "0x" + match.group(1)
    return int(hex_str, 0)

# assigned later
def matches_function(func_name, func_match_pat):
    match = func_match_pat.fullmatch(func_name)
    return match

#    8f88:	c3                   	retq
ret_pattern = re.compile(".*?\t.*?\tret.*\n?")
def is_ret_instruction(line):
    match = ret_pattern.fullmatch(line)
    return match

def is_retpoline(function_name):
    return function_name.find("retpoline") >= 0

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
        print("Note some spurious errors exist as lucet appends data to the end of functions. Thus if you see a disallowed instruction after the last ret of a function, please ignore this")
        sys.exit(1)

def log_message(input_file, line, line_num, function_name, alignment_block):
    offset = get_line_offset(line)
    curr_align = offset % alignment_block
    out_str = input_file + ":" + str(line_num) + \
        " Func: " + function_name + \
        " Aligned: " + str(curr_align) + "/" + str(alignment_block) + \
        " || " + line
    return (out_str, curr_align)

def scan_file(args):

    func_match_pat = re.compile(args.function_filter.replace('*', '.*'))

    STATE_SCANNING = 0
    STATE_FOUND_FUNCTION = 1

    state = STATE_SCANNING
    function_line = ""

    with open(args.input_file, "r") as f:
        line_num = 0
        for line in f:
            line_num = line_num + 1
            if state == STATE_SCANNING and is_function(line) and matches_function(get_func_name(line), func_match_pat):
                state = STATE_FOUND_FUNCTION
                function_name = get_func_name(line)
            elif state == STATE_FOUND_FUNCTION and is_end_of_function(line):
                state = STATE_SCANNING
                function_name = ""
            elif state == STATE_FOUND_FUNCTION and is_indirect_call_instruction(line):
                if args.check_indirect_calls == False:
                    continue
                (out_str, curr_align) = log_message(args.input_file, line, line_num, function_name, args.alignment_block)
                print_error(out_str, args.limit)
            elif state == STATE_FOUND_FUNCTION and is_indirect_jump_instruction(line):
                if args.check_indirect_branches == False:
                    continue
                (out_str, curr_align) = log_message(args.input_file, line, line_num, function_name, args.alignment_block)
                print_error(out_str, args.limit)
            elif state == STATE_FOUND_FUNCTION and is_jump_instruction(line):
                if args.check_direct_branches == False:
                    continue
                (out_str, curr_align) = log_message(args.input_file, line, line_num, function_name, args.alignment_block)
                if curr_align != args.direct_branch_alignment:
                    print_error(out_str, args.limit)
                else:
                    print_ok(out_str, args.loginfo)
            elif state == STATE_FOUND_FUNCTION and is_ret_instruction(line):
                if args.check_returns == False:
                    continue
                (out_str, curr_align) = log_message(args.input_file, line, line_num, function_name, args.alignment_block)

                target_alignment = args.return_alignment
                if is_retpoline(function_name):
                    target_alignment = args.retpoline_return_alignment

                if curr_align != target_alignment:
                    print_error(out_str, args.limit)
                else:
                    print_ok(out_str, args.loginfo)

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
    parser.add_argument("input_file", type=str, help="Asm file to check")
    parser.add_argument("--function_filter", type=str, default="*", help="Function name to check")
    parser.add_argument("--limit", type=int, default=-1, help="Stop at `limit` errors")
    parser.add_argument("--loginfo", type=str2bool, default=False, help="Print log level information")
    parser.add_argument("--alignment_block", type=int, default=32, help="Alignment block size to use")
    parser.add_argument("--check_direct_branches", type=str2bool, default=True, help="Check for alignment of direct branches")
    parser.add_argument("--direct_branch_alignment", type=int, default=31, help="Alignment of branches to check for")
    parser.add_argument("--check_indirect_branches", type=str2bool, default=True, help="Check for presence of indirect branches")
    parser.add_argument("--check_indirect_calls", type=str2bool, default=True, help="Check for presence of indirect calls")
    parser.add_argument("--check_returns", type=str2bool, default=True, help="Check for alignment of ret instructions")
    parser.add_argument("--retpoline_return_alignment", type=int, default=29, help="Alignment of return in retpolines to check for")
    parser.add_argument("--return_alignment", type=int, default=27, help="Alignment of return to check for")
    args = parser.parse_args()

    scan_file(args)

    if error_count != 0:
        print("Note some spurious errors exist as lucet appends data to the end of functions. Thus if you see a disallowed instruction after the last ret of a function, please ignore this")
        sys.exit(1)


main()