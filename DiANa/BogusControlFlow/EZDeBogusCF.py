# -*- coding: utf-8 -*-
import sys
from barf import BARF
from keystone import *
from DeBogudCFUtil import *


# # fix function
# def fix_instruction_substitution(data, hexlist, starts, base):
#     for start, x in zip(starts, hexlist):
#         flag = 0
#         hexx = x.split(',')[:-1]
#         for i in hexx:
#             data[start + flag - base] = ba.unhexlify(i[2:].zfill(2))
#             flag = flag + 1
#     return data
#
#
# # find compare blocks(cmp XXX, b** loc_XXX)
# def get_cmp_blocks(cfg):
#     cmp_blocks = {}
#
#     for block in cfg.basic_blocks:
#         size = len(block.instrs)
#         if size == 2:
#             opcodes = []
#             operand = []
#             opcodes.append(block.instrs[0].mnemonic)
#             opcodes.append(block.instrs[1].mnemonic_full)
#             operand.append(block.instrs[0].operands)
#
#             if opcodes[0] == u'cmp' and opcodes[1].startswith(u'b') and hasattr(operand[0][1], 'immediate'):
#                 if operand[0][1].immediate == 0:
#                     if opcodes[1] == u'beq':
#                         cmp_blocks[hex(block.address)] = 0
#                     elif opcodes[1] == u'bne':
#                         cmp_blocks[hex(block.address)] = 1
#     return cmp_blocks


# # find opaque predicate blocks(sub,mul,and(s))
# def get_predicate_blocks(cfg):
#     predicate_blocks = {}
#
#     for block in cfg.basic_blocks:
#         size = len(block.instrs)
#         if block.address == 2056:
#             print 'd'
#         if size > 2:
#             opcodes = []
#             operands = []
#             flag = 0
#             for x in block.instrs:
#                 opcodes.append(x.mnemonic)
#                 operands.append(x.operands)
#             for op, operand in zip(opcodes, operands):
#                 if flag + 2 <= size:
#                     if op == u'sub' and opcodes[flag + 1] == u'mul' and opcodes[flag + 2].startswith(u'and'):
#                         if operand[0] == operands[flag + 1][1] and operand[1] == operands[flag + 1][2] and \
#                                 hasattr(operand[2], 'immediate') and operands[flag + 1][0] == operands[flag + 2][1] \
#                                 and hasattr(operands[flag + 2][2], 'immediate'):
#                             if operand[2].immediate == 1 and operands[flag + 2][2].immediate == 1:
#                                 if block.instrs[-1].mnemonic_full == u'beq':
#                                     predicate_blocks[hex(block.address)] = 0
#                                 elif block.instrs[-1].mnemonic_full == u'bne':
#                                     predicate_blocks[hex(block.address)] = 1
#                                 elif block.instrs[-1].mnemonic_full == u'blt':
#                                     predicate_blocks[hex(block.address)] = 2
#
#                 if flag + 3 <= size:
#                     if op == u'sub' and opcodes[flag + 2] == u'mul' and opcodes[flag + 3].startswith(u'and'):
#                         if operand[0] == operands[flag + 2][1] and operand[1] == operands[flag + 2][2] and \
#                                 hasattr(operand[2], 'immediate') and operands[flag + 2][0] == operands[flag + 3][1] \
#                                 and hasattr(operands[flag + 3][2], 'immediate'):
#                             if operand[2].immediate == 1 and operands[flag + 3][2].immediate == 1:
#                                 if block.instrs[-1].mnemonic_full == u'beq':
#                                     predicate_blocks[hex(block.address)] = 0
#                                 elif block.instrs[-1].mnemonic_full == u'bne':
#                                     predicate_blocks[hex(block.address)] = 1
#                                 elif block.instrs[-1].mnemonic_full == u'blt':
#                                     predicate_blocks[hex(block.address)] = 2
#                     elif op == u'sub' and opcodes[flag + 1] == u'mul' and opcodes[flag + 3].startswith(u'and'):
#                         if operand[0] == operands[flag + 1][1] and operand[1] == operands[flag + 1][2] and \
#                                 hasattr(operand[2], 'immediate') and operands[flag + 1][0] == operands[flag + 3][1] \
#                                 and hasattr(operands[flag + 3][2], 'immediate'):
#                             if operand[2].immediate == 1 and operands[flag + 3][2].immediate == 1:
#                                 if block.instrs[-1].mnemonic_full == u'beq':
#                                     predicate_blocks[hex(block.address)] = 0
#                                 elif block.instrs[-1].mnemonic_full == u'bne':
#                                     predicate_blocks[hex(block.address)] = 1
#                                 elif block.instrs[-1].mnemonic_full == u'blt':
#                                     predicate_blocks[hex(block.address)] = 2
#
#                 if flag + 4 <= size:
#                     if op == u'sub' and opcodes[flag + 2] == u'mul' and opcodes[flag + 4].startswith(u'and'):
#                         if operand[0] == operands[flag + 2][1] and operand[1] == operands[flag + 2][2] and \
#                                 hasattr(operand[2], 'immediate') and operands[flag + 2][0] == operands[flag + 4][1] \
#                                 and hasattr(operands[flag + 4][2], 'immediate'):
#                             if operand[2].immediate == 1 and operands[flag + 4][2].immediate == 1:
#                                 if block.instrs[-1].mnemonic_full == u'beq':
#                                     predicate_blocks[hex(block.address)] = 0
#                                 elif block.instrs[-1].mnemonic_full == u'bne':
#                                     predicate_blocks[hex(block.address)] = 1
#                                 elif block.instrs[-1].mnemonic_full == u'blt':
#                                     predicate_blocks[hex(block.address)] = 2
#                 flag = flag + 1
#
#     return predicate_blocks


# if __name__ == '__main__':
def De_BCF(filename, start):
    # sys.argv = ["test.py", '/Users/mark/Desktop/de_obfuscator/benchmark/binary/pyramid-bcf-sub', "0x72c"]
    # start = int(sys.argv[2], 16)
    start = int(start, 16)
    # filename = sys.argv[1]
    filename = filename
    barf = BARF(filename)

    base_addr = barf.binary.entry_point >> 12 << 12
    cfg = barf.recover_cfg(start)
    cmp_blocks, opaque_predicate_blocks = get_predicate_blocks(cfg)
    print(cmp_blocks)
    print(opaque_predicate_blocks)


    blocks = cfg.basic_blocks
    fixhex = []
    fixaddr = []

    # for each block
    for block in blocks:
        command = ''
        # compare blocks(0 for beq(taken), 1 for bne(not-taken))
        if hex(block.address) in cmp_blocks:
            if cmp_blocks[hex(block.address)] == 0:
                for branch in block.branches:
                    if branch[1] == 'taken':
                        off_set = hex(branch[0]-block.instrs[-1].address)
                        command = 'b    #' + off_set

            elif cmp_blocks[hex(block.address)] == 1:
                for branch in block.branches:
                    if branch[1] == 'not-taken':
                        off_set = hex(branch[0] - block.instrs[-1].address)
                        command = 'b    #' + off_set

        # opaque predicate blocks(0 for beq(taken), 1,2 for bne(not-taken))
        if hex(block.address) in opaque_predicate_blocks:
            if opaque_predicate_blocks[hex(block.address)] == 0:
                for branch in block.branches:
                    if branch[1] == 'taken':
                        off_set = hex(branch[0] - block.instrs[-1].address)
                        command = 'b    #' + off_set

            elif opaque_predicate_blocks[hex(block.address)] == 1 or \
                    opaque_predicate_blocks[hex(block.address)] == 2:
                for branch in block.branches:
                    if branch[1] == 'not-taken':
                        off_set = hex(branch[0] - block.instrs[-1].address)
                        command = 'b    #' + off_set

        # change the conditional jump before opaque_predicate_blocks to unconditional jump
        # (force the flow through opaque_predicate_blocks)
        for branch in block.branches:
            if hex(branch[0]) in opaque_predicate_blocks and block.instrs[-1].mnemonic_full == u'blt':
                off_set = hex(branch[0] - block.instrs[-1].address)
                command = 'b    #' + off_set

        # if command.startswith('b'):
            # print command
        if command != '':
            bcommand = bytes(command)
            hexcommand = ''

            try:
                # Initialize engine in X86-32bit mode
                ks = Ks(KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN)
                encoding, count = ks.asm(bcommand)
                for i in encoding:
                    hexcommand = hexcommand + hex(int(i)) + ','
                fixaddr.append(block.instrs[-1].address)
                fixhex.append(hexcommand)
            except KsError as e:
                print("ERROR: %s" % e)
        # elif command.startswith('negative,'):
        #     hexcommand = ''
        #     off_set = command.split(',')[-1]
        #     x = int(off_set, 16) - 8
        #     x &= 0x3FFFFFF
        #     x >>= 2
        #     tmp = hex(0xEB000000 + x)
        #     for i in range(len(tmp), 2, -2):
        #         hexcommand = hexcommand + '0x' + tmp[i-2:i] + ','
        #     fixaddr.append(block.instrs[-1].address)
        #     fixhex.append(hexcommand)

    origin = open(filename, 'rb')
    data = list(origin.read())

    print fixaddr, fixhex
    data = fix_instruction_substitution(data, fixhex, fixaddr, base_addr)
    origin.close()
    path = sys.argv[3]
    recovery = open(path + filename.split('/')[-2] + '/' + filename.split('/')[-1] + '_recovered', 'wb')
    recovery.write(''.join(data))
    recovery.close()
    print 'Successful! The recovered file: %s' % (filename + '_recovered')


