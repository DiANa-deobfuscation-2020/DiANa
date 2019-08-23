# -*- coding: utf-8 -*-
from barf import BARF
import sys
from DeInsSubUtil import *
import barf.arch.arm.translator
import os


# if __name__ == '__main__':
def De_IS(filename, start):
    # sys.argv = ["test.py", "/Users/mark/Desktop/de_obfuscator/IS/New-test/total/inssub", "0x694"]
    # if len(sys.argv) != 3:
    #     print 'Usage: python DeInsSub.py filename function_address(hex)'
    #     exit(0)

    # filename = sys.argv[1]
    start = int(start, 16)
    filename = filename
    # start = int(start, 16)
    barf = BARF(filename)
    base_addr = barf.binary.entry_point >> 12 << 12

    cfg = barf.recover_cfg(start)
    blocks = cfg.basic_blocks

    print('The function has %d blocks. ' % len(blocks))

    origin = open(filename, 'rb')
    data = list(origin.read())

    for block in blocks:
        opposite = []
        #查找所用的MOV指令，然后记录所用寄存器值相反的对
        # for ins in block.instrs:
        #     if ins.mnemonic_full.startswith(u'mvn'):
        #         if ins.operands[0].name not in opposite:
        #             opposite[ins.operands[0].name] = ins.operands[1].name

        block_size = len(block.instrs)
        ADDHex, ADDnop = check_add(block, block_size)
        data = fix_substitution(data, ADDHex, ADDnop, base_addr)
        SUBHex, SUBnop = check_sub(block, block_size)
        data = fix_substitution(data, SUBHex, SUBnop, base_addr)
        XORHex, XORnop = check_xor(block, block_size)
        data = fix_substitution(data, XORHex, XORnop, base_addr)
        ANDHex, ANDnop = check_and(block, block_size)
        data = fix_substitution(data, ANDHex, ANDnop, base_addr)
        ORHex, ORnop  = check_or(block, block_size)
        data = fix_substitution(data, ORHex, ORnop, base_addr)

    origin.close()
    # recovery = open(filename + '_recovered', 'wb')
    path = sys.argv[3]
    if not os.path.exists(path + filename.split('/')[-2] + '/'):
        os.mkdir(path + filename.split('/')[-2] + '/')
    recovery = open(path + filename.split('/')[-2] + '/' + filename.split('/')[-1] + '_recovered', 'wb')

    recovery.write(''.join(data))
    recovery.close()
    print 'Successful! The recovered file: %s' % (filename + '_recovered')
