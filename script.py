

# For example:
# mov     eax, dword_B56D4
# call    dword ptr [eax+??h]
function_pointer_dword = 'dword_B56D4'

# dps command output from Windbg goes here
# For example:
# dps poi(0xB56D4)
# where 00a2fb18 represents the pointer at 0xB56D4
function_pointer_table = """
00a2fb18  7551792b ADVAPI32!SetFileSecurityWStub
00a2fb1c  755240be ADVAPI32!AdjustTokenPrivilegesStub
00a2fb20  755618f9 ADVAPI32!SetEntriesInAclA
00a2fb24  75524016 ADVAPI32!AllocateAndInitializeSidStub
00a2fb28  7552405e ADVAPI32!FreeSidStub
00a2fb2c  7552483b ADVAPI32!RegOpenKeyExAStub
00a2fb30  75524823 ADVAPI32!RegQueryValueExAStub
00a2fb34  755245cd ADVAPI32!RegCloseKeyStub
00a2fb38  755418da ADVAPI32!ConvertSidToStringSidA
00a2fb3c  7551cc69 ADVAPI32!RegCreateKeyA
00a2fb40  755213e3 ADVAPI32!RegSetValueExAStub
00a2fb44  7555374f ADVAPI32!RegLoadKeyWStub
00a2fb48  7555376f ADVAPI32!RegUnLoadKeyWStub
00a2fb4c  7551c9cc ADVAPI32!OpenSCManagerWStub
00a2fb50  755370a4 ADVAPI32!CreateServiceWStub
00a2fb54  755178dc ADVAPI32!StartServiceWStub
00a2fb58  755370d4 ADVAPI32!DeleteServiceStub
00a2fb5c  755235cc ADVAPI32!CloseServiceHandleStub
00a2fb60  75519143 ADVAPI32!CryptAcquireContextAStub
00a2fb64  7551deb6 ADVAPI32!CryptCreateHashStub
00a2fb68  7551de9e ADVAPI32!CryptHashDataStub
00a2fb6c  755535a4 ADVAPI32!CryptVerifySignatureAStub
00a2fb70  7551e08c ADVAPI32!CryptReleaseContextStub
00a2fb74  7551c482 ADVAPI32!CryptDestroyKeyStub
00a2fb78  7551dece ADVAPI32!CryptDestroyHashStub
00a2fb7c  7552403b ADVAPI32!EqualSidStub
00a2fb80  755247a8 ADVAPI32!LookupAccountSidW
"""

LINES = function_pointer_table.splitlines()

import idautils
import idaapi
import ida_idp
import idc


def find_mov_dword(addr):
    while True:
        addr = idc.PrevHead(addr)
        if idc.GetMnem(addr) == "mov" and "eax" in idc.GetOpnd(addr, 0):
            #print("Found mov dword at %s" % idc.GetDisasm(addr))
            return idc.GetOpnd(addr, 1)

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

        # Step backward until we find the corresponding mov    eax, dword_xxxxxxxx
        mov_dword = find_mov_dword(ea)

        if mov_dword != function_pointer_dword:
            #print('Skipping dword ptr %s' % mov_dword)
            continue

        offset = idc.GetOperandValue(ea, 0)
        function_name = get_function(offset)
        print('Mapped %s to function %s' % (hex(offset), function_name))

        # Uncomment the code below only if the output you receive
        # from running the code above is correct, verifying with
        # dps poi(0xB56D4) + offset

        # Write comment containing function name at address of call instruction
        #idc.MakeComm(ea, function_name)
        #print('Commented call at 0x%08x as %s', (ea, function_name))
