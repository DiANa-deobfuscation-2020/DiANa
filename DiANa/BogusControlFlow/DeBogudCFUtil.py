# -*- coding:utf-8 -*-
import binascii as ba


# fix function
def fix_instruction_substitution(data, hexlist, starts, base):
    for start, x in zip(starts, hexlist):
        flag = 0
        hexx = x.split(',')[:-1]
        for i in hexx:
            data[start + flag - base] = ba.unhexlify(i[2:].zfill(2))
            flag = flag + 1
    return data


# find compare blocks(cmp XXX, b** loc_XXX)
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


# find opaque predicate blocks(sub,mul,and(s))
def get_predicate_blocks(cfg):
    global taint_reg
    predicate_blocks = {}
    cmp_blocks = {}
    taint_reg = ['r6']

    for block in cfg.basic_blocks:
        size = len(block.instrs)
        if size >= 2:
            opcodes = []
            operands = []
            flag = 0
            for x in block.instrs:
                opcodes.append(x.mnemonic)
                operands.append(x.operands)
            while flag < len(opcodes):
                # 三个指令是：opcodes[flag],opcodes[temp1],opcodes[temp2]
                # case1 sub mul and(s)
                temp1 = 0
                temp2 = 0
                if opcodes[flag] == u'sub':
                    temp1 = flag + 1
                    temp1flag = False
                    while temp1 < flag + 4 and temp1 < size:
                        if opcodes[temp1] == u'mul' and hasattr(operands[flag][0], 'name') and \
                                hasattr(operands[flag][1], 'name') and hasattr(operands[flag][2], 'immediate') and \
                                hasattr(operands[temp1][2], 'name') and hasattr(operands[temp1][1], 'name'):
                            if operands[flag][1] == operands[temp1][2] and operands[flag][0] == operands[temp1][1] and \
                                    operands[flag][2].immediate == 1:
                                temp1flag = True
                                break
                            else:
                                temp1 = temp1 + 1
                        else:
                            temp1 = temp1 + 1
                    #
                    # if temp1 + 1 == size:
                    #     flag = flag+1
                    #     continue

                    temp2 = temp1 + 1
                    while temp2 < temp1 + 4 and temp1flag and temp2 < size:
                        if opcodes[temp2].startswith(u'and') and hasattr(operands[temp1][0], 'name') and \
                                hasattr(operands[temp2][1], 'name') and hasattr(operands[temp2][2], 'immediate'):
                            if operands[temp1][0] == operands[temp2][1] and operands[temp2][2].immediate == 1:
                                # taint_reg.append(operands[temp2][0].name)
                                if block.instrs[-1].mnemonic_full == u'beq':
                                    predicate_blocks[hex(block.address)] = 0
                                elif block.instrs[-1].mnemonic_full == u'bne':
                                    predicate_blocks[hex(block.address)] = 1
                                elif block.instrs[-1].mnemonic_full == u'blt':
                                    predicate_blocks[hex(block.address)] = 2
                                break
                            else:
                                temp2 = temp2 + 1
                        elif opcodes[temp2] == u'tst' and hasattr(operands[temp1][0], 'name') and \
                                hasattr(operands[temp2][0], 'name') and hasattr(operands[temp2][1], 'immediate'):
                            if operands[temp1][0] == operands[temp2][0] and operands[temp2][1].immediate == 1:
                                # taint_reg.append(operands[temp2][0].name)
                                if block.instrs[-1].mnemonic_full == u'beq':
                                    predicate_blocks[hex(block.address)] = 1
                                elif block.instrs[-1].mnemonic_full == u'bne':
                                    predicate_blocks[hex(block.address)] = 0
                                elif block.instrs[-1].mnemonic_full == u'blt':
                                    predicate_blocks[hex(block.address)] = 2
                                break
                            else:
                                temp2 = temp2 + 1
                        else:
                            temp2 = temp2 + 1

                # case2 sub mul and(s)在前面，基本快都是直接cmp，taint_reg用来记录之前的sub mul and(s)操作
                if opcodes[flag] == u'cmp' and len(opcodes) < 3:
                    if hasattr(operands[flag][0], 'name') and hasattr(operands[flag][1], 'immediate'):
                        if operands[flag][0].name in taint_reg and operands[flag][1].immediate == 0:
                            if block.instrs[-1].mnemonic_full == u'beq':
                                cmp_blocks[hex(block.address)] = 1
                            elif block.instrs[-1].mnemonic_full == u'bne':
                                cmp_blocks[hex(block.address)] = 0

                # case3 指令替换模式下虚假控制流的特征块：orr eor cmp
                if opcodes[flag] == u'orr' and size < 6:
                    temp1flag = False
                    temp1 = flag + 1
                    while temp1 < flag + 3 and temp1 < size:
                        if opcodes[temp1] == u'eor' or opcodes[temp2] == u'eors':
                            if hasattr(operands[flag][0], 'name') and hasattr(operands[temp1][1], 'name') and \
                                    hasattr(operands[temp1][2], 'immediate'):
                                if operands[flag][0] == operands[temp1][1] and operands[temp1][2].immediate == 1:
                                    temp1flag = True
                                    break
                                else:
                                    temp1 = temp1 + 1
                            else:
                                temp1 = temp1 + 1
                        else:
                            temp1 = temp1 + 1

                    temp2 = temp1 + 1
                    while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                        if opcodes[temp2] == u'cmp' and hasattr(operands[temp1][0], 'name') and \
                                hasattr(operands[temp2][0], 'name') and hasattr(operands[temp2][1], 'immediate'):
                            if operands[temp1][0] == operands[temp2][0] and operands[temp2][1].immediate == 1:
                                # taint_reg.append(operands[temp2][0].name)
                                if block.instrs[-1].mnemonic_full == u'beq':
                                    predicate_blocks[hex(block.address)] = 0
                                elif block.instrs[-1].mnemonic_full == u'bne':
                                    predicate_blocks[hex(block.address)] = 1
                                elif block.instrs[-1].mnemonic_full == u'blt':
                                    predicate_blocks[hex(block.address)] = 2
                                break
                            else:
                                temp2 = temp2 + 1
                        else:
                            temp2 = temp2 + 1

                # case4 指令替换模式下虚假控制流的特征块：cmp movlt teq(tst)
                if opcodes[flag] == u'cmp' and hasattr(operands[flag][1], 'immediate'):
                    if operands[flag][1].immediate == 10:
                        temp1flag = False
                        temp1 = flag + 1

                        temp2 = temp1 + 1
                        temp2flag = False
                        while temp2 < temp1 + 3 and temp2 < size:
                            if block.instrs[temp2].mnemonic_full == u'movlt' and hasattr(operands[temp2][1],
                                                                                         'immediate'):
                                if operands[temp2][1].immediate == 1:
                                    temp2flag = True
                                    break
                                else:
                                    temp2 = temp2 + 1
                            else:
                                temp2 = temp2 + 1

                        temp3 = temp2 + 1
                        while temp3 < temp2 + 3 and temp2flag and temp3 < size:
                            if opcodes[temp3] == u'tst' and operands[temp2][0] == operands[temp3][0]:
                                if block.instrs[-1].mnemonic_full == u'beq':
                                    cmp_blocks[hex(block.address)] = 1
                                elif block.instrs[-1].mnemonic_full == u'bne':
                                    cmp_blocks[hex(block.address)] = 0
                                elif block.instrs[-1].mnemonic_full == u'blt':
                                    cmp_blocks[hex(block.address)] = 2
                                break
                            elif opcodes[temp3] == u'teq' and operands[temp2][0] == operands[temp3][0]:
                                if block.instrs[-1].mnemonic_full == u'beq':
                                    cmp_blocks[hex(block.address)] = 0
                                elif block.instrs[-1].mnemonic_full == u'bne':
                                    cmp_blocks[hex(block.address)] = 1
                                elif block.instrs[-1].mnemonic_full == u'blt':
                                    cmp_blocks[hex(block.address)] = 2
                                break
                            else:
                                temp3 = temp3 + 1

                flag = flag + 1

            # for op, operand in zip(opcodes, operands):
            #     if flag + 2 <= size:
            #         if op == u'sub' and opcodes[flag + 1] == u'mul' and opcodes[flag + 2].startswith(u'and'):
            #             if operand[0] == operands[flag + 1][1] and operand[1] == operands[flag + 1][2] and \
            #                     hasattr(operand[2], 'immediate') and operands[flag + 1][0] == operands[flag + 2][1] \
            #                     and hasattr(operands[flag + 2][2], 'immediate'):
            #                 if operand[2].immediate == 1 and operands[flag + 2][2].immediate == 1:
            #                     if block.instrs[-1].mnemonic_full == u'beq':
            #                         predicate_blocks[hex(block.address)] = 0
            #                     elif block.instrs[-1].mnemonic_full == u'bne':
            #                         predicate_blocks[hex(block.address)] = 1
            #                     elif block.instrs[-1].mnemonic_full == u'blt':
            #                         predicate_blocks[hex(block.address)] = 2
            #
            #     if flag + 3 <= size:
            #         if op == u'sub' and opcodes[flag + 2] == u'mul' and opcodes[flag + 3].startswith(u'and'):
            #             if operand[0] == operands[flag + 2][1] and operand[1] == operands[flag + 2][2] and \
            #                     hasattr(operand[2], 'immediate') and operands[flag + 2][0] == operands[flag + 3][1] \
            #                     and hasattr(operands[flag + 3][2], 'immediate'):
            #                 if operand[2].immediate == 1 and operands[flag + 3][2].immediate == 1:
            #                     if block.instrs[-1].mnemonic_full == u'beq':
            #                         predicate_blocks[hex(block.address)] = 0
            #                     elif block.instrs[-1].mnemonic_full == u'bne':
            #                         predicate_blocks[hex(block.address)] = 1
            #                     elif block.instrs[-1].mnemonic_full == u'blt':
            #                         predicate_blocks[hex(block.address)] = 2
            #         elif op == u'sub' and opcodes[flag + 1] == u'mul' and opcodes[flag + 3].startswith(u'and'):
            #             if operand[0] == operands[flag + 1][1] and operand[1] == operands[flag + 1][2] and \
            #                     hasattr(operand[2], 'immediate') and operands[flag + 1][0] == operands[flag + 3][1] \
            #                     and hasattr(operands[flag + 3][2], 'immediate'):
            #                 if operand[2].immediate == 1 and operands[flag + 3][2].immediate == 1:
            #                     if block.instrs[-1].mnemonic_full == u'beq':
            #                         predicate_blocks[hex(block.address)] = 0
            #                     elif block.instrs[-1].mnemonic_full == u'bne':
            #                         predicate_blocks[hex(block.address)] = 1
            #                     elif block.instrs[-1].mnemonic_full == u'blt':
            #                         predicate_blocks[hex(block.address)] = 2
            #
            #     if flag + 4 <= size:
            #         if op == u'sub' and opcodes[flag + 2] == u'mul' and opcodes[flag + 4].startswith(u'and'):
            #             if operand[0] == operands[flag + 2][1] and operand[1] == operands[flag + 2][2] and \
            #                     hasattr(operand[2], 'immediate') and operands[flag + 2][0] == operands[flag + 4][1] \
            #                     and hasattr(operands[flag + 4][2], 'immediate'):
            #                 if operand[2].immediate == 1 and operands[flag + 4][2].immediate == 1:
            #                     if block.instrs[-1].mnemonic_full == u'beq':
            #                         predicate_blocks[hex(block.address)] = 0
            #                     elif block.instrs[-1].mnemonic_full == u'bne':
            #                         predicate_blocks[hex(block.address)] = 1
            #                     elif block.instrs[-1].mnemonic_full == u'blt':
            #                         predicate_blocks[hex(block.address)] = 2
            #     flag = flag + 1

    return cmp_blocks, predicate_blocks
