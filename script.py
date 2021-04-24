
# This script assumes eax is used to store
# the function pointer table and throughout
# the code "call dword ptr [eax+??h]" is
# present, where ?? is an offset into the
# pointer table below

# dps command output from Windbg goes here
function_pointer_table = """
00000ae8  75f748d7 KERNEL32!LoadLibraryA
00000aec  75f7482b KERNEL32!LoadLibraryW
...
"""

LINES = function_pointer_table.splitlines()

import idautils
import idaapi
import ida_idp
import idc
import re


def get_function(offset):
    for i in range(len(LINES)):
        # Treat each line as a dword in length
        if (i * 4) - 4 == offset:
            function_name = LINES[i].split()[2]
            return function_name

for ea in idautils.Heads():
    if ida_idp.is_call_insn(ea):

        # Get disassembly at call address (ea)
        code = idc.GetDisasm(ea)
        split = code.split()
        if split[0] != 'call':
            continue
        if split[1] != 'dword':
            continue
        if split[2] != 'ptr':
            continue
        
        # Assuming eax is where the function pointer table is stored
        if 'eax+' not in split[3]:
            continue

        offset = idc.GetOperandValue(ea, 0)
        function_name = get_function(offset)
        print('Mapped %s to function %s' % (hex(offset), function_name))

        # Uncomment the code below only if the output you receive
        # from running the code above is correct

        # Write comment containing function name at address of call instruction
        #idc.MakeComm(ea, function_name)
        #print('Commented call at 0x%08x as %s', (ea, function_name))
