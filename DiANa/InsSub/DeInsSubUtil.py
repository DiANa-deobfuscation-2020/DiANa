# -*- coding: utf-8 -*-
from keystone import *
import binascii as ba


def check_add(block, size):
    global taint_addr
    fixhex = {}
    fixnop = []
    taint_addr = []
    opcodes = []
    operands = []
    addresses = []
    # 存放改变区域操作的寄存器list
    flag = 0

    for x in block.instrs:
        opcodes.append(x.mnemonic)
        operands.append(x.operands)
        addresses.append(x.address)
    while flag < len(opcodes):
        if flag < size:
            if addresses[flag] in taint_addr:
                flag = flag+1
                continue
            # 三个指令是：op,opcodes[temp1],opcodes[temp2]
            # case1 sub add add
            key = 0
            temp1 = 0
            temp2 = 0
            if opcodes[flag] == u'sub':
                reg_env = {}
                temp1 = flag + 1
                temp1flag = False
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'add' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][1], 'name'):
                        if hasattr(operands[temp1][2], 'name'):
                            if operands[flag][0] == operands[temp1][1] or operands[flag][0] == operands[temp1][2]:
                                temp1flag = True
                                break
                            else:
                                temp1 = temp1 + 1
                        elif hasattr(operands[temp1][2], 'immediate'):
                            if operands[flag][0] == operands[temp1][1]:
                                temp1flag = True
                                break
                            else:
                                temp1 = temp1 + 1
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1
                #
                # if temp1 + 1 == size:
                #     flag = flag+1
                #     continue

                temp2 = temp1 + 1
                while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                    if opcodes[temp2] == u'add' and hasattr(operands[temp1][0], 'name') and \
                            hasattr(operands[temp2][1], 'name') and hasattr(operands[temp2][2], 'name') and \
                            hasattr(operands[flag][2], 'name'):
                        if (operands[temp1][0] == operands[temp2][1] or operands[temp1][0] == operands[temp2][2]) and \
                                (operands[flag][2] == operands[temp2][1] or operands[flag][2] == operands[temp2][2]):
                            key = 666
                            break
                        else:
                            temp2 = temp2 + 1
                    else:
                        temp2 = temp2 + 1

            # case2 add add sub
            if opcodes[flag] == u'add':
                reg_env = {}
                temp1flag = False
                temp1 = flag + 1
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'add' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][1], 'name'):
                        if operands[flag][0] == operands[temp1][1]:
                            temp1flag = True
                            break
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

                # if temp1 + 1 == size:
                    # flag = flag + 1
                    # continue

                temp2 = temp1 + 1
                while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                    if opcodes[temp2] == u'sub' and hasattr(operands[temp1][0], 'name') and \
                            hasattr(operands[temp2][1], 'name') and hasattr(operands[temp2][2], 'name') and \
                            hasattr(operands[flag][2], 'name'):
                        if operands[temp1][0] == operands[temp2][1] and \
                                operands[flag][2] == operands[temp2][2]: # or operands[flag][1] == operands[temp2][2]):
                            key = 666
                            break
                        else:
                            temp2 = temp2 + 1
                    else:
                        temp2 = temp2 + 1

            # case4 rsb sub rsb
            if opcodes[flag] == u'rsb':
                reg_env = {}
                temp1 = flag + 1
                temp1flag = False
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'sub' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][1], 'name') and hasattr(operands[flag][2], 'immediate'):
                        if operands[flag][0] == operands[temp1][1] and operands[flag][2].immediate == 0:
                            temp1flag = True
                            break
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

                # if temp1 + 1 == size:
                #     flag = flag + 1
                #     continue

                temp2 = temp1 + 1
                while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                    if opcodes[temp2] == u'rsb' and hasattr(operands[temp1][0], 'name') and \
                            hasattr(operands[temp2][1], 'name') and ((hasattr(operands[flag][2], 'immediate') and
                                                                      hasattr(operands[temp2][2], 'immediate')) or
                                                                     (hasattr(operands[flag][2], 'name') and
                                                                      hasattr(operands[temp2][2], 'name'))):
                        if operands[temp1][0] == operands[temp2][1] and operands[flag][2] == operands[temp2][2]:
                            key = 666
                            break
                        else:
                            temp2 = temp2 + 1
                    else:
                        temp2 = temp2 + 1

            # case3 rsb sub or rsb rsb
            if opcodes[flag] == u'rsb' and key != 666:
                reg_env = {}
                temp1 = flag + 1

                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'sub' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][2], 'name') and hasattr(operands[flag][2], 'immediate'):
                        if operands[flag][0] == operands[temp1][2] and operands[flag][2].immediate == 0:
                            key = 999
                            break
                        else:
                            reg_env[operands[temp1][0].name] = addresses[temp1]
                            temp1 = temp1 + 1

                    elif opcodes[temp1] == u'rsb' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[flag][2], 'immediate') and hasattr(operands[temp1][1], 'name'):
                        if operands[flag][0] == operands[temp1][1] and operands[flag][2].immediate == 0:
                            key = 999
                            break
                        else:
                            reg_env[operands[temp1][0].name] = addresses[temp1]
                            temp1 = temp1 + 1

                    elif opcodes[temp1] != u'sub' and opcodes[temp1] != u'rsb' and hasattr(operands[temp1][0], 'name'):
                        reg_env[operands[temp1][0].name] = addresses[temp1]
                        temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

            if key == 666 and (hasattr(operands[temp1][2], 'name') or hasattr(operands[temp1][2], 'immediate')):
                if hasattr(operands[temp1][2], 'name'):
                    command = 'add  ' + operands[temp2][0].name + ', ' + operands[flag][1].name + ', ' \
                              + operands[temp1][2].name
                elif hasattr(operands[temp1][2], 'immediate'):
                    command = 'add  ' + operands[temp2][0].name + ', ' + operands[flag][1].name + ', ' + '#' \
                              + str(operands[temp1][2].immediate)

                fixhex[addresses[temp2]] = fix_instruction_to_hex(command)
                fixnop.append(addresses[temp1])
                fixnop.append(addresses[flag])
                taint_addr.append(addresses[flag])
                taint_addr.append(addresses[temp1])
                taint_addr.append(addresses[temp2])
                flag = temp2 + 1

            elif key == 999:
                if hasattr(operands[temp1][2], 'immediate'):
                    command = 'add  ' + operands[temp1][0].name + ', ' + operands[flag][1].name + ', ' + '#' \
                              + str(operands[temp1][2].immediate)
                else:
                    command = 'add  ' + operands[temp1][0].name + ', ' + operands[flag][1].name + ', ' \
                              + operands[temp1][1].name

                if operands[flag][1].name in reg_env.keys():
                    fixhex[addresses[flag]] = fix_instruction_to_hex(command)
                    fixnop.append(addresses[temp1])
                    taint_addr.append(addresses[temp1])
                    taint_addr.append(addresses[flag])
                else:
                    fixhex[addresses[temp1]] = fix_instruction_to_hex(command)
                    fixnop.append(addresses[flag])
                    taint_addr.append(addresses[temp1])
                    taint_addr.append(addresses[flag])
                flag = temp1 + 1

            else:
                flag = flag + 1

    return fixhex, fixnop


def check_sub(block, size):
    global taint_addr
    reg_env={}
    fixhex = {}
    fixnop = []
    opcodes = []
    operands = []
    addresses = []
    flag = 0

    for x in block.instrs:
        opcodes.append(x.mnemonic)
        operands.append(x.operands)
        addresses.append(x.address)
    while flag < len(opcodes):
        if flag < size:
            if addresses[flag] in taint_addr:
                flag = flag+1
                continue
            # 三个指令是：op,opcodes[temp1],opcodes[temp2]
            # case1 add sub sub
            key = 0
            temp1 = 0
            temp2 = 0
            if opcodes[flag] == u'add':
                temp1flag = False
                temp1 = flag + 1
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'sub' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][1], 'name'):
                        if operands[flag][0] == operands[temp1][1]:
                            temp1flag = True
                            break
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

                if temp1 + 1 == size:
                    flag = flag + 1
                    continue

                temp2 = temp1 + 1
                while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                    if opcodes[temp2] == u'sub' and hasattr(operands[temp1][0], 'name') and \
                            hasattr(operands[temp2][1], 'name') and hasattr(operands[temp2][2], 'name') and \
                            hasattr(operands[flag][2], 'name'):
                        if operands[temp1][0] == operands[temp2][1] and operands[flag][2] == operands[temp2][2]:
                            key = 666
                            break
                        else:
                            temp2 = temp2 + 1
                    else:
                        temp2 = temp2 + 1

            # case2 sub sub add
            if opcodes[flag] == u'sub':
                temp1 = flag + 1
                temp1flag = False
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'sub' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][1], 'name'):
                        if operands[flag][0] == operands[temp1][1]:
                            temp1flag = True
                            break
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

                if temp1 + 1 == size:
                    flag = flag + 1
                    continue

                temp2 = temp1 + 1
                while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                    if opcodes[temp2] == u'add' and hasattr(operands[temp1][0], 'name') and \
                            hasattr(operands[temp2][1], 'name') and hasattr(operands[temp2][2], 'name') and \
                            hasattr(operands[flag][2], 'name'):
                        if (operands[temp1][0] == operands[temp2][1] and operands[flag][2] == operands[temp2][2]) or\
                                (operands[temp1][0] == operands[temp2][2] and operands[flag][2] == operands[temp2][1]):
                            key = 666
                            break
                        else:
                            temp2 = temp2 + 1
                    else:
                        temp2 = temp2 + 1

            # case3 rsb add
            if opcodes[flag] == u'rsb':

                temp1 = flag + 1
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'add' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][1], 'name') and hasattr(operands[temp1][2], 'name') and \
                            hasattr(operands[flag][2], 'immediate'):
                        if operands[flag][0] == operands[temp1][1] and operands[flag][2].immediate == 0:
                            key = 999
                            break
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

            # # case4 rsb add sub
            # if opcodes[flag] == u'rsb' and key != 999:
            #     temp1 = flag + 1
            #     while temp1+1 < size:
            #         if opcodes[temp1] == u'add' and hasattr(operands[flag][0], 'name') and \
            #                 hasattr(operands[temp1][1], 'name') and hasattr(operands[flag][2], 'immediate'):
            #             if operands[flag][0] == operands[temp1][1] and operands[flag][2].immediate == 0:
            #                 break
            #             else:
            #                 temp1 = temp1 + 1
            #         else:
            #             temp1 = temp1 + 1
            #
            #     temp2 = temp1 + 1
            #     while temp2+1 < size:
            #         if opcodes[temp2] == u'sub' and hasattr(operands[temp1][0], 'name') and \
            #                 hasattr(operands[temp2][1], 'name') and ((hasattr(operands[flag][2], 'immediate') and
            #                                                           hasattr(operands[temp2][2], 'immediate')) or
            #                                                          (hasattr(operands[flag][2], 'name') and
            #                                                           hasattr(operands[temp2][2], 'name'))):
            #             if operands[temp1][0] == operands[temp2][1] and operands[flag][2] == operands[temp2][2]:
            #                 key = 666
            #                 break
            #             else:
            #                 temp2 = temp2 + 1
            #         else:
            #             temp2 = temp2 + 1

            if key == 666:
                if hasattr(operands[temp1][2], 'name'):
                    command = 'sub  ' + operands[temp2][0].name + ', ' + operands[flag][1].name + ', ' \
                              + operands[temp1][2].name
                elif hasattr(operands[temp1][2], 'immediate'):
                    command = 'sub  ' + operands[temp2][0].name + ', ' + operands[flag][1].name + ', ' + '#' \
                              + str(operands[temp1][2].immediate)
                else:
                    print(addresses[flag] + "error!")
                fixhex[addresses[temp2]] = fix_instruction_to_hex(command)
                fixnop.append(addresses[temp1])
                fixnop.append(addresses[flag])
                taint_addr.append(addresses[flag])
                taint_addr.append(addresses[temp1])
                taint_addr.append(addresses[temp2])
                flag = temp2 + 1

            elif key == 999:
                if operands[flag][0] == operands[temp1][1]:
                    command = 'sub  ' + operands[temp1][0].name + ', ' + operands[temp1][1].name + ', ' \
                          + operands[flag][1].name
                else:
                    command = 'sub  ' + operands[temp1][0].name + ', ' + operands[temp1][1].name + ', ' \
                              + operands[temp1][1].name
                fixhex[addresses[temp1]] = fix_instruction_to_hex(command)
                fixnop.append(addresses[flag])
                taint_addr.append(addresses[flag])
                taint_addr.append(addresses[temp1])
                flag = temp1 + 1

            else:
                flag = flag + 1

    return fixhex, fixnop


def check_xor(block, size):
    global taint_addr
    reg_env = {}
    fixhex = {}
    fixnop = []
    opcodes = []
    operands = []
    addresses = []
    flag = 0

    for x in block.instrs:
        opcodes.append(x.mnemonic)
        operands.append(x.operands)
        addresses.append(x.address)

    while flag < len(opcodes):
        if flag < size:
            if addresses[flag] in taint_addr:
                flag = flag+1
                continue
            # 三个指令是：op,opcodes[temp1],opcodes[temp2]
            # case1 bic bic orr 两个寄存器之间的异或
            key = 0
            temp1 = 0
            temp2 = 0
            if opcodes[flag] == u'bic':
                reg_env = {}
                temp1flag = False
                temp1 = flag + 1
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'bic' and hasattr(operands[flag][1], 'name') and \
                            (hasattr(operands[flag][2], 'name') or hasattr(operands[flag][2], 'immediate')) and \
                            hasattr(operands[temp1][1], 'name') and hasattr(operands[temp1][2], 'name'):
                        if hasattr(operands[flag][2], 'name'):
                            if operands[flag][1] == operands[temp1][2] and operands[flag][2] == operands[temp1][1]:
                                temp1flag = True
                                break
                            else:
                                if hasattr(operands[temp1][0], 'name'):
                                    reg_env[operands[temp1][0].name] = addresses[temp1]
                                temp1 = temp1 + 1
                        else:
                            if operands[flag][1] == operands[temp1][2]:
                                for i in range(flag, max(flag-4, -1), -1):
                                    if opcodes[i] == u'mov' and hasattr(operands[i][1], 'immediate'):
                                        if operands[i][1].immediate == operands[flag][2].immediate and \
                                                operands[i][0].name == operands[temp1][1].name:
                                            temp1flag = True
                                            break
                                if not temp1flag:
                                    if hasattr(operands[temp1][0], 'name'):
                                        reg_env[operands[temp1][0].name] = addresses[temp1]
                                    temp1 = temp1 + 1
                                    continue
                                else:
                                    break

                            else:
                                if hasattr(operands[temp1][0], 'name'):
                                    reg_env[operands[temp1][0].name] = addresses[temp1]
                                temp1 = temp1 + 1

                    # elif opcodes[temp1] == u'bic' and hasattr(operands[flag][1], 'name') and \
                    #         hasattr(operands[flag][2], 'name') and hasattr(operands[temp1][1], 'name') or \
                    #         hasattr(operands[temp1][2], 'immediate'):
                    # 有些无法自动恢复的情况，考虑将其整理结果及地址输出，例如在大范围发现的指令替换，其对寄存器的操作可能无法孤立

                    else:
                        if hasattr(operands[temp1][0], 'name'):
                            reg_env[operands[temp1][0].name] = addresses[temp1]
                        temp1 = temp1 + 1

                temp2 = temp1 + 1
                while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                    if opcodes[temp2] == u'orr' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][0], 'name') and hasattr(operands[temp2][1], 'name') and \
                            hasattr(operands[temp2][2], 'name'):
                        if (operands[flag][0] == operands[temp2][1] and operands[temp1][0] == operands[temp2][2]) or \
                                (operands[flag][0] == operands[temp2][2] and operands[temp1][0] == operands[temp2][1]):
                            key = 666
                            break
                        else:
                            if hasattr(operands[temp2][0], 'name'):
                                reg_env[operands[temp2][0].name] = addresses[temp2]
                            temp2 = temp2 + 1
                    else:
                        if hasattr(operands[temp2][0], 'name'):
                            reg_env[operands[temp2][0].name] = addresses[temp2]
                        temp2 = temp2 + 1

            if key == 666:
                if hasattr(operands[flag][2], 'immediate'):
                    command = 'eor  ' + operands[temp2][0].name + ', ' + operands[temp1][2].name + ', ' + '#' \
                              + str(operands[flag][2].immediate)
                    if operands[temp1][1].name in reg_env.keys():
                        fixhex[addresses[flag]] = fix_instruction_to_hex(command)
                        fixnop.append(addresses[temp1])
                        fixnop.append(addresses[temp2])
                    else:
                        fixhex[addresses[temp2]] = fix_instruction_to_hex(command)
                        fixnop.append(addresses[flag])
                        fixnop.append(addresses[temp1])
                else:
                    command = 'eor  ' + operands[temp2][0].name + ', ' + operands[temp1][1].name + ', ' \
                                  + operands[temp1][2].name
                    if operands[temp1][1].name in reg_env.keys() or operands[temp1][2].name in reg_env.keys():
                        fixhex[addresses[flag]] = fix_instruction_to_hex(command)
                        fixnop.append(addresses[temp1])
                        fixnop.append(addresses[temp2])
                    else:
                        fixhex[addresses[temp2]] = fix_instruction_to_hex(command)
                        fixnop.append(addresses[flag])
                        fixnop.append(addresses[temp1])

                taint_addr.append(addresses[flag])
                taint_addr.append(addresses[temp1])
                taint_addr.append(addresses[temp2])
                flag = temp2 + 1
            else:
                flag = flag + 1

    return fixhex, fixnop


def check_or(block, size):
    global taint_addr
    fixhex = {}
    fixnop = []
    opcodes = []
    operands = []
    addresses = []
    flag = 0

    for x in block.instrs:
        opcodes.append(x.mnemonic)
        operands.append(x.operands)
        addresses.append(x.address)

    while flag < len(opcodes):
        if flag < size:
            if addresses[flag] in taint_addr:
                flag = flag + 1
                continue
            # 三个指令是：op,opcodes[temp1],opcodes[temp2]
            # case1 eor and orr
            key = 0
            temp1 = 0
            temp2 = 0
            if opcodes[flag] == u'eor':
                temp1flag = False
                temp1 = flag + 1
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'and' and hasattr(operands[flag][1], 'name') and \
                        hasattr(operands[temp1][1], 'name') and ((hasattr(operands[flag][2], 'name') and
                                                                  hasattr(operands[temp1][2], 'name')) or
                                                                 (hasattr(operands[flag][2], 'immediate') and
                                                                  hasattr(operands[temp1][2], 'immediate'))):
                        if operands[flag][1] == operands[temp1][1] and operands[flag][2] == operands[temp1][2]:
                            temp1flag = True
                            break
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

                    # elif opcodes[temp1] == u'bic' and hasattr(operands[flag][1], 'name') and \
                    #         hasattr(operands[flag][2], 'name') and hasattr(operands[temp1][1], 'name') or \
                    #         hasattr(operands[temp1][2], 'immediate'):
                    # 有些无法自动恢复的情况，考虑将其整理结果及地址输出，例如在大范围发现的指令替换，其对寄存器的操作可能无法孤立

                temp2 = temp1 + 1
                while temp2 < temp1 + 3 and temp1flag and temp2 < size:
                    if opcodes[temp2] == u'orr' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[temp1][0], 'name') and hasattr(operands[temp2][1], 'name') and \
                            hasattr(operands[temp2][2], 'name'):
                        if (operands[flag][0] == operands[temp2][1] and operands[temp1][0] == operands[temp2][2]) or \
                                (operands[flag][0] == operands[temp2][2] and operands[temp1][0] == operands[temp2][1]):
                            key = 666
                            break
                        else:
                            temp2 = temp2 + 1
                    else:
                        temp2 = temp2 + 1

            # # case2 orr eor and orr
            # if opcodes[flag] == u'orr':
            #     temp1flag = False
            #     temp1 = flag + 1
            #     while temp1 < flag + 3 and temp1 < size:
            #         if opcodes[temp1] == u'and' and hasattr(operands[flag][1], 'name') and \
            #             hasattr(operands[temp1][1], 'name') and ((hasattr(operands[flag][2], 'name') and
            #                                                       hasattr(operands[temp1][2], 'name')) or
            #                                                      (hasattr(operands[flag][2], 'immediate') and
            #                                                       hasattr(operands[temp1][2], 'immediate'))):
            #             if operands[flag][1] == operands[temp1][1] and operands[flag][2] == operands[temp1][2]:
            #                 temp1flag = True
            #                 break
            #             else:
            #                 temp1 = temp1 + 1
            #         else:
            #             temp1 = temp1 + 1
            #
            #         # elif opcodes[temp1] == u'bic' and hasattr(operands[flag][1], 'name') and \
            #         #         hasattr(operands[flag][2], 'name') and hasattr(operands[temp1][1], 'name') or \
            #         #         hasattr(operands[temp1][2], 'immediate'):
            #         # 有些无法自动恢复的情况，考虑将其整理结果及地址输出，例如在大范围发现的指令替换，其对寄存器的操作可能无法孤立
            #
            #     temp2 = temp1 + 1
            #     while temp2 < temp1 + 3 and temp1flag and temp2 < size:
            #         if opcodes[temp2] == u'orr' and hasattr(operands[flag][0], 'name') and \
            #                 hasattr(operands[temp1][0], 'name') and hasattr(operands[temp2][1], 'name') and \
            #                 hasattr(operands[temp2][2], 'name'):
            #             if (operands[flag][0] == operands[temp2][1] and operands[temp1][0] == operands[temp2][2]) or \
            #                     (operands[flag][0] == operands[temp2][2] and operands[temp1][0] == operands[temp2][1]):
            #                 key = 666
            #                 break
            #             else:
            #                 temp2 = temp2 + 1
            #         else:
            #             temp2 = temp2 + 1

            if key == 666:
                if hasattr(operands[temp1][2], 'immediate'):
                    command = 'orr  ' + operands[temp2][0].name + ', ' + operands[temp1][1].name + ', ' + '#' \
                              + str(operands[temp1][2].immediate)
                else:
                    command = 'orr  ' + operands[temp2][0].name + ', ' + operands[temp1][1].name + ', ' \
                              + operands[temp1][2].name

                fixhex[addresses[temp2]] = fix_instruction_to_hex(command)
                fixnop.append(addresses[temp1])
                fixnop.append(addresses[flag])
                taint_addr.append(addresses[flag])
                taint_addr.append(addresses[temp1])
                taint_addr.append(addresses[temp2])
                flag = temp2 + 1
            else:
                flag = flag + 1

    return fixhex, fixnop


def check_and(block, size):
    global taint_addr
    fixhex = {}
    fixnop = []
    taint_reg = []
    opcodes = []
    operands = []
    addresses = []
    flag = 0
    case1flag = False

    for x in block.instrs:
        opcodes.append(x.mnemonic)
        operands.append(x.operands)
        addresses.append(x.address)

    while flag < len(opcodes):
        case1flag = False
        if flag < size:
            if addresses[flag] in taint_addr:
                flag = flag + 1
                continue
            # 三个指令是：opcodes[temp1],op,opcodes[temp2]
            # case1 (mov or mvn) eor and
            key = 0
            temp1 = 0
            temp2 = 0
            if opcodes[flag] == u'eor' and hasattr(operands[flag][2], 'name'):
                temp1flag = False
                for i in range(flag-1, 0, -1):
                    if opcodes[i] == u'mov' or opcodes[i] == u'mvn' and hasattr(operands[i][0], 'name'):
                        if operands[flag][2] == operands[i][0] and operands[i][0].name not in taint_reg:
                            temp1 = i
                            temp1flag = True
                            break
                    else:
                        if hasattr(operands[i][0], 'name'):
                            taint_reg.append(operands[i][0].name)

                temp2 = flag + 1
                while temp2 < flag + 3 and temp2 < size and temp1flag:
                    if opcodes[temp2] == u'and' and hasattr(operands[flag][0], 'name') and \
                            hasattr(operands[flag][1], 'name') and hasattr(operands[temp2][2], 'name') and \
                            hasattr(operands[temp2][1], 'name'):
                        if operands[flag][0] == operands[temp2][1] and operands[flag][1] == operands[temp2][2]:
                            key = 666
                            case1flag = True
                            break
                        else:
                            temp2 = temp2 + 1
                    else:
                        temp2 = temp2 + 1

            # case2 eor bic
            if opcodes[flag] == u'eor' and not case1flag:
                temp1 = flag + 1
                while temp1 < flag + 3 and temp1 < size:
                    if opcodes[temp1] == u'bic' and hasattr(operands[flag][0], 'name') and \
                        hasattr(operands[flag][1], 'name') and hasattr(operands[temp1][1], 'name') and \
                                hasattr(operands[temp1][2], 'name'):
                        if operands[flag][0] == operands[temp1][2] and operands[flag][1] == operands[temp1][1]:
                            key =999
                            break
                        else:
                            temp1 = temp1 + 1
                    else:
                        temp1 = temp1 + 1

            if key == 666:
                if hasattr(operands[temp1][1], 'immediate'):
                    if opcodes[temp1] == u'mov':
                        command = 'and  ' + operands[temp2][0].name + ', ' + operands[temp2][2].name + ', ' + '#' \
                                  + str(~operands[temp1][1].immediate)
                    else:
                        command = 'and  ' + operands[temp2][0].name + ', ' + operands[temp2][2].name + ', ' + '#' \
                                  + str(operands[temp1][1].immediate)
                else:
                    command = 'and  ' + operands[temp2][0].name + ', ' + operands[temp2][2].name + ', ' \
                              + operands[temp1][1].name

                fixhex[addresses[temp2]] = fix_instruction_to_hex(command)
                fixnop.append(addresses[flag])
                taint_addr.append(addresses[flag])
                taint_addr.append(addresses[temp2])
                flag = temp2 + 1
            elif key == 999:
                command = 'and  ' + operands[temp1][0].name + ', ' + operands[flag][1].name + ', ' \
                          + operands[flag][2].name
                fixhex[addresses[flag]] = fix_instruction_to_hex(command)
                fixnop.append(addresses[temp1])
                taint_addr.append(addresses[flag])
                taint_addr.append(addresses[temp1])
                flag = temp1 + 1
            else:
                flag = flag + 1

    return fixhex, fixnop


def fix_instruction_to_hex(command):
    bcommand = bytes(command)
    hexcommand = ''

    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN)
        encoding, count = ks.asm(bcommand)
        for i in encoding:
            hexcommand = hexcommand + hex(int(i)) + ','
        return hexcommand
    except KsError as e:
        print("ERROR: %s" % e)


def fix_substitution(data, hexlist, nop, base):
    for k, v in hexlist.items():
        flag = 0

        hexx = v.split(',')[:-1]
        for i in hexx:
            data[k + flag - base] = ba.unhexlify(i[2:].zfill(2))
            flag = flag + 1

    for i in nop:
        data[i - base] = '\x00'
        data[i + 1 - base] = '\xf0'
        data[i + 2 - base] = '\x20'
        data[i + 3 - base] = '\xe3'

    return data


# fix function
# def fix_instruction_substitution(data, hexlist, starts, ends, base):
#     for start, end, x in zip(starts, ends, hexlist):
#         flag = 0
#         hexx = x.split(',')[:-1]
#         for i in hexx:
#             data[start + flag - base] = ba.unhexlify(i[2:].zfill(2))
#             flag = flag + 1
#         while end - start - flag > 0:
#             data[start + flag - base] = '\x00'
#             data[start + flag + 1 - base] = '\xf0'
#             data[start + flag + 2 - base] = '\x20'
#             data[start + flag + 3 - base] = '\xe3'
#             flag = flag + 4
#
#     return data