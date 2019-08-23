# -*- coding: utf-8 -*-
from barf.barf import BARF
import angr
import simuvex
import claripy
import pyvex
import networkx as nx
import sys
import barf.arch.arm.disassembler as dis
import os


def usage():
    print("Usage: " + sys.argv[0] + "obfuscated_file_path " + "obfuscated_function_address " + "check_loop(default=3) "
          + "origin_file_path " + "origin_function_address ")
    exit()


def fix_nop(data, start, end):
    for i in range(start, end + 1):
        data[i] = '\xff'

    return data


def findFlattenBlocks(cfg):
    cmp_blocks = []
    flatten_flags = {}
    blocks_income = {}

    for block in cfg.basic_blocks:
        # 32位老师给的so库的情况：
        # 1、四条指令：
        for branch in block.branches:
            if branch[0] not in blocks_income:
                blocks_income[branch[0]] = 0
            blocks_income[branch[0]] = blocks_income[branch[0]] + 1

        size = len(block.instrs)
        if size <= 6:

            if size == 2:
                opcodes = []
                operand = []
                opcodes.append(block.instrs[0].mnemonic)
                opcodes.append(block.instrs[1].mnemonic_full)
                operand.append(block.instrs[0].operands)

                if opcodes[0] == u'cmp' and opcodes[1].startswith(u'b') \
                        and hasattr(operand[0][0], 'name') and hasattr(operand[0][1], 'name'):
                    if operand[0][0].name.startswith('r') and operand[0][1].name.startswith('r'):
                        cmp_blocks.append(block.address)

            # 64位mac的情况：
            if size > 2:
                opcodes = []
                operands = []
                for x in block.instrs:
                    opcodes.append(x.mnemonic)
                    operands.append(x.operands)
                flag = 0
                if block.address == 0x6cc:
                    print('block.address')
                while flag < len(opcodes):
                    # 三个指令是：op,opcodes[temp1],opcodes[temp2]
                    # case1 sub add add
                    key = 0
                    temp1 = 0
                    temp2 = 0
                    if opcodes[flag] == u'ldr' and hasattr(operands[flag][1], 'displacement') and hasattr(
                            operands[flag][1].displacement, 'immediate'):
                        if operands[flag][1].displacement.immediate != 0 and operands[flag][1].base_reg.name == u'r15':
                            temp1 = flag + 1
                            temp1flag = False
                            while temp1 < flag + 4 and temp1 < size:
                                if opcodes[temp1] == u'cmp' and hasattr(operands[temp1][0], 'name') and \
                                        hasattr(operands[temp1][1], 'name'):
                                    if operands[temp1][0].name.startswith('r') and operands[temp1][1].name.startswith(
                                            'r'):
                                        temp1flag = True
                                        break
                                    else:
                                        temp1 = temp1 + 1
                                else:
                                    temp1 = temp1 + 1
                            movXX_flag = True
                            for key in range(temp1 + 1, len(opcodes)):
                                if block.instrs[key].mnemonic_full.startswith(u'mov') and block.instrs[
                                    key].mnemonic_full != u'moval':
                                    movXX_flag = False

                            if movXX_flag and temp1flag and opcodes[-1].startswith('b') or opcodes[-1].startswith('p') \
                                    or (opcodes[-1].startswith('l') and size < 4):
                                cmp_blocks.append(block.address)
                                flatten_flags[block.address] = []
                                temp = operands[flag][1].displacement.immediate + block.instrs[0].address + 8
                                flatten_flags[block.address].append(temp)
                            break

                        else:
                            flag = flag + 1

                    elif (opcodes[flag] == u'movw' or opcodes[flag] == u'movt') and hasattr(operands[flag][1],
                                                                                            'immediate'):
                        temp1 = flag + 1
                        temp1flag = False
                        while temp1 < flag + 3 and temp1 < size:
                            if opcodes[flag] == u'movt' and opcodes[temp1] == u'movw' and \
                                    hasattr(operands[temp1][1], 'immediate') and operands[flag][0] == operands[temp1][
                                0]:
                                temp1flag = True
                                break
                            elif opcodes[flag] == u'movw' and opcodes[temp1] == u'movt' and \
                                    hasattr(operands[temp1][1], 'immediate') and operands[flag][0] == operands[temp1][
                                0]:
                                temp1flag = True
                                break
                            elif size == 3:
                                temp1flag = True
                                temp1 = temp1 - 1
                                break
                            else:
                                temp1 = temp1 + 1

                        temp2 = temp1 + 1
                        temp2flag = False

                        while temp1flag and temp2 < temp1 + 3 and temp2 < size:
                            if opcodes[temp2] == u'cmp' and operands[temp2][0].name.startswith('r') and \
                                    operands[temp2][1].name.startswith('r') and opcodes[-1].startswith('b'):
                                cmp_blocks.append(block.address)
                                flatten_flags[block.address] = []
                                if opcodes[flag] == u'movt' and size > 3:
                                    temp = operands[flag][1].immediate * 0x1000 + operands[temp1][1].immediate
                                elif opcodes[flag] == u'movw' and size > 3:
                                    temp = operands[temp1][1].immediate * 0x1000 + operands[flag][1].immediate
                                elif opcodes[flag] == u'movw' and size == 3:
                                    temp = operands[flag][1].immediate
                                else:
                                    temp = operands[flag][1].immediate * 0x1000
                                flatten_flags[block.address].append(temp)
                                temp2flag = True
                                break
                            else:
                                temp2 = temp2 + 1
                        if temp2flag:
                            flag = flag + 1
                            break
                        else:
                            flag = flag + 1
                    else:
                        flag = flag + 1

    return blocks_income, cmp_blocks, flatten_flags


# 超难想这个程序逻辑
def find_cmp_dispatcher(graph, involved_blocks, flatten_blocks):
    # 对每个参与块而言
    delete_blocks = []
    for i in involved_blocks:
        # 寻找他们的父块
        for k, v in zip(graph.keys(), graph.values()):
            # 如果父块不是混淆块
            if i in v and k not in flatten_blocks:
                # 加入参与块
                involved_blocks.append(k)
    return involved_blocks


# 超难想这个程序逻辑
def findUndirectInvlovedBlocks(cfg, graph, involved_blocks, flatten_blocks):
    # 对每个参与块而言
    delete_blocks = []
    temp = list(involved_blocks)
    for i in temp:
        # 寻找他们的父块
        for k, v in zip(graph.keys(), graph.values()):
            # 如果父块不是混淆块
            if i in v and k not in flatten_blocks:
                # 加入参与块
                involved_blocks.append(k)
                if len(cfg.find_basic_block(k).instrs) > 1:
                    delete_blocks.append(i)

    delete_blocks = list(set(delete_blocks))
    for i in delete_blocks:
        if i in involved_blocks:
            involved_blocks.remove(i)
    involved_blocks = list(set(involved_blocks))

    return involved_blocks, delete_blocks


def check_branches(cfg, flatten_flags, involved_blocks):
    has_branches = []
    # involved_cmp_dispatcher = []
    for i in involved_blocks:

        block = cfg.find_basic_block(i)
        for ins in block.instrs:
            if ins.mnemonic == u'ldr' and hasattr(ins.operands[1], 'displacement'):
                for v in flatten_flags.values():
                    if hasattr(ins.operands[1].displacement, 'immediate'):
                        temp = ins.operands[1].displacement.immediate + ins.address + 8
                        if temp in v and block.address not in has_branches:
                            has_branches.append(block.address)
    return has_branches


def init_symbolic_execution(start_addr, pre_dispatcher, hook_addr, loop=5):
    global b, modify_value, relevants
    if hook_addr:
        for hook in hook_addr:
            b.hook(hook, retn_procedure, length=4)

    state = b.factory.blank_state(addr=start_addr, remove_options={simuvex.o.LAZY_SOLVES})

    p = b.factory.path(state)
    succ = p.step()
    addr = 0
    loop_flag = 0
    loop = len(pre_dispatcher) * loop
    while len(succ.successors) and loop_flag < loop and addr == 0:
        if succ.successors[0].addr not in relevants:
            if succ.successors[0].addr in pre_dispatcher:
                loop_flag = loop_flag + 1
            succ = succ.successors[0].step()
        else:
            addr = succ.successors[0].addr
            break

    state = succ.successors[0].state

    return state


# False 代表一条
def symbolic_execution(start_addr, state, hook_addr=None, relevants=None, loop=3, modify=None, inspect=False):
    global b, modify_value, graph, prologue, pre_dispatcher
    if hook_addr != None:
        for hook in hook_addr:
            if hook!= 13664:
                b.hook(hook, retn_procedure, length=4)
            else:
                b.hook(hook, retn_procedure, length=8)
    if modify != None:
        modify_value = modify

    # 在序言执行后的状态基础上进行当前块的执行，来自angr官方人员的建议

    if start_addr == prologue:
        state = b.factory.blank_state(addr=start_addr, remove_options={simuvex.o.LAZY_SOLVES})
    else:
        state = state
        state.regs.ip = start_addr

    if inspect:
        state.inspect.b('statement', when=simuvex.BP_BEFORE, action=statement_inspect)
    p = b.factory.path(state)
    succ = p.step()
    addr = 0
    loop_flag = 0
    loop = len(pre_dispatcher) * loop
    while len(succ.successors) and loop_flag != loop:
        if succ.successors[0].addr not in relevants and succ.successors[0].addr != addr:
            if succ.successors[0].addr in pre_dispatcher:
                loop_flag = loop_flag + 1
            addr = succ.successors[0].addr
            succ = succ.successors[0].step()
        else:
            addr = succ.successors[0].addr
            state = succ.successors[0].state
            break
    if loop_flag == loop:
        print('skiped %s' % start_addr)
        addr = 0

    return addr, state


def statement_inspect(state):
    global modify_value
    expressions = state.scratch.irsb.statements[state.inspect.statement].expressions
    if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
        state.scratch.temps[expressions[0].cond.tmp] = modify_value
        state.inspect._breakpoints['statement'] = []


def retn_procedure(state):
    global b
    ip = state.se.eval(state.regs.ip)
    b.unhook(ip)
    return


# class CapstoneOperandNotSupported(Exception):
#     """AError---exception"""
#     print('AError')


# 思路：无论如何先找基本块
# if __name__ == '__main__':
def De_CFF(CFF_file_path, CFF_start, loop, output):
# def De_CFF(CFF_file_path, CFF_start, loop, end):
    global b, modify_value, graph, prologue, pre_dispatcher, relevants
    # sys.argv = ["test.py", '/Users/mark/Desktop/djbhash-obfuscated', "0x690", 5]
    # de_obfuscator/benchmark/binary/binarysearch-cff
    # reverse-cff是特殊情况
    # if len(sys.argv) != 6:
    #     usage()
    # functionname = 'send_magicmsg'
    # filename = sys.argv[1]
    filename = CFF_file_path
    # end = int(sys.argv[4], 16)
    # start = int(sys.argv[2], 16)
    # end = int(end, 16)
    start = int(CFF_start, 16)
    barf = BARF(filename)
    # base_addr = barf.binary.entry_point >> 12 << 12
    b = angr.Project(filename, load_options={'auto_load_libs': False, 'main_opts': {'custom_base_addr': 0}})

    # irsb = irsb.next
    # print(irsb.next)
    try:
        cfg = barf.recover_cfg(start=start)
    except dis.CapstoneOperandNotSupported:
        # return -1
        print('ccccccc')
        # exit()
    # blocks = cfg.basic_blocks
    # prologue序言，即初始的块
    prologue = start

    cfg_path = output

    if len(cfg.basic_blocks) > 3:
        # print ('start %s' % functionname)
        loop = sys.argv[3]
        # loop = loop
        hook_addr = []
        jump_end_block = []
        # NDK编译后的程序的序言后面接的有可能是main_dispatcher，也有可能是pre_dispatcher，
        # 逻辑上，先找cmp块，在cmp块中找出pre_dispatcher，
        # 其中，第一块是prologue，其他的都认为是组成main_dispatcher的
        # 找出cmp块(flatten特征块)vvv
        income, cmp_blocks, flatten_flags = findFlattenBlocks(cfg)
        prologue_block = cfg.find_basic_block(prologue)
        flatten_flags[prologue] = []
        for ins in prologue_block.instrs:
            if ins.mnemonic == u'ldr' and len(ins.operands) == 2:
                if hasattr(ins.operands[1], 'displacement'):
                    if ins.operands[1].base_reg.name == u'r15' and hasattr(ins.operands[1].displacement, 'immediate'):
                        temp = ins.operands[1].displacement.immediate + ins.address + 8
                        flatten_flags[prologue].append(temp)
        flatten_flags[prologue] = list(set(flatten_flags[prologue]))

        pre_dispatcher = []
        for i in cmp_blocks:
            if income[i] >= 2:
                # !!!!!!!!!!!!!!!!!!!!!!!!
                pre_dispatcher.append(i)

        print 'flatten_blocks:', [hex(addr) for addr in cmp_blocks]
        # 找出pre_dispatcher(有很多个入口的cmp块)
        main_dispatcher = []
        temp_block = 0
        if cfg.find_basic_block(prologue).direct_branch:
            temp_block = cfg.find_basic_block(prologue).direct_branch
        else:
            for branch in cfg.find_basic_block(prologue).branches:
                if branch[0] in cmp_blocks:
                    temp_block = branch[0]
                else:
                    main_dispatcher.append(branch[0])
            if temp_block == 0:
                temp_block = cfg.find_basic_block(prologue).branches[0][0]

        while True:
            # if temp_block in cmp_dispatcher and temp_block == max(blocks_income, key=income.get):
            if temp_block in cmp_blocks:
                break
            else:
                main_dispatcher.append(temp_block)
                if cfg.find_basic_block(temp_block).direct_branch:
                    temp_block = cfg.find_basic_block(temp_block).direct_branch
                else:
                    for branch in cfg.find_basic_block(temp_block).branches:
                        if branch[0] != temp_block:
                            temp_block = branch[0]
        main_dispatcher = set(list(main_dispatcher))
        # 找出直接与pre_dispatcher相连的参与块:
        part_involved_blocks = []
        origin_has_branches = []
        retn = []
        graph = {}
        # 计算得到一个简单的cfg_dict:
        block_range = {}
        obfuscated_opcodes = {}
        for block in cfg.basic_blocks:
            # if block.address <= end:
                # if block.address == 0x7f8:
                #     print('ca')
                if block.address not in graph:
                    graph[block.address] = []
                for i in block.branches:
                    graph[block.address].append(i[0])
                # if block.address == 0x950:
                # print('xsa')
                obfuscated_opcodes[block.address] = []

                for i in block.instrs:
                    obfuscated_opcodes[block.address].append(i.mnemonic)
                    # if i.mnemonic_full == u'blal' or i.mnemonic_full == u'blxal':
                    #     hook_addr.append(block.address)

                if len(block.branches) == 0:
                    retn.append(block.address)
                elif len(block.branches) == 1:
                    # !!!!!!!!!!!!!!!!!!!!!!!!删除指向自身的基本块
                    if (block.branches[0][0] in pre_dispatcher or block.branches[0][0] in main_dispatcher) and \
                            block.address != prologue and block.address not in main_dispatcher and \
                            block.address not in cmp_blocks and block.branches[0][0] != block.address:
                        if len(block.instrs) > 1:
                            part_involved_blocks.append(block.address)
                elif len(block.branches) == 2:
                    for j in range(0, 2):
                        if (block.branches[j][0] in pre_dispatcher or block.branches[j][0] in main_dispatcher) and \
                                block.address != prologue and block.address not in main_dispatcher and block.address not in \
                                cmp_blocks and block.branches[j][0] != block.address:
                            part_involved_blocks.append(block.address)
                            origin_has_branches.append(block.address)
        # if not retn:
        # print filename + functionname
        # return -1
        print 'part_involved_blocks:', [hex(addr) for addr in part_involved_blocks]
        # 找出未与flatten特征块相连的参与块：
        involved_blocks, involved_control_blocks = findUndirectInvlovedBlocks(cfg, graph, part_involved_blocks,
                                                                              cmp_blocks)
        rest_part = list(graph.keys())
        for i in graph.keys():
            # if i == 1888:
            #     print('vew')
            if i == prologue or i in cmp_blocks or i in involved_blocks or i in involved_control_blocks or i in retn:
                rest_part.remove(i)
            if len(graph[i]) == 1 and graph[i][0] == i and i in rest_part:
                rest_part.remove(i)
                # for j in rest_part:
                #     if len(graph[j]) == 1 and graph[j][0] == i:
                #         rest_part.remove(j)

        temp_part = []
        if len(rest_part) > 0:
            for i in rest_part:
                for k, v in zip(graph.keys(), graph.values()):
                    # 如果父块是混淆块
                    if i in v and k in cmp_blocks and len(graph[i]) == 1 and graph[i][0] not in cmp_blocks and \
                            len(cfg.find_basic_block(i).instrs) > 1:
                        # 加入参与块
                        print hex(i)
                        temp_part.append(i)
            for j in temp_part:
                involved_blocks.append(j)
                if j in rest_part:
                    rest_part.remove(j)

            for p in rest_part:
                if graph[p][0] not in cmp_blocks and len(cfg.find_basic_block(p).instrs) > 1:
                    involved_control_blocks.append(p)

        # 去掉main_dispatcher
        for i in main_dispatcher:
            if i in involved_blocks:
                involved_blocks.remove(i)
            if i in involved_control_blocks:
                involved_control_blocks.remove(i)

        print '--------------------------involved_blocks--------------------------'
        print 'prologue:%#x' % start
        print 'main_dispatcher', [hex(addr) for addr in main_dispatcher]
        print 'pre_dispatcher: ', [hex(addr) for addr in pre_dispatcher]
        print 'retn: ', [hex(addr) for addr in retn]
        print 'involved_blocks:', [hex(addr) for addr in involved_blocks]
        print 'flatten_blocks:', [hex(addr) for addr in cmp_blocks]
        print 'flatten_flags:', flatten_flags

        # 找出存在分支的参与块
        has_branches = check_branches(cfg, flatten_flags, involved_blocks)
        if prologue not in has_branches:
            has_branches.append(prologue)
        for i in origin_has_branches:
            has_branches.append(i)
        has_branches = list(set(has_branches))

        for block in cfg.basic_blocks:
            if block.instrs[0].mnemonic_full == u'blxal' or block.instrs[0].mnemonic_full == u'blal' and block.address \
                    not in involved_control_blocks:
                jump_end_block.append(block.address)
                hook_addr.append(block.address)

        print '-------------------------check_branch_block-------------------------'
        print 'has_branches_blocks:', [hex(addr) for addr in has_branches]
        print 'involved_control_blocks:', [hex(addr) for addr in involved_control_blocks]

        print '-------------------------symbolic_execution-------------------------'

        relevants = list(involved_blocks)
        if prologue in relevants:
            relevants.remove(prologue)
        relevants_without_retn = list(relevants)
        for i in retn:
            relevants.append(i)

        for i in jump_end_block:
            relevants.append(i)
        # 初始化control flow的dict
        flow = {}
        for parent in relevants:
            flow[parent] = []
        flow[prologue] = []

        modify_value = None
        prologue_block = cfg.find_basic_block(prologue)
        hook = []
        hook = hook + hook_addr
        for ins in prologue_block.instrs:
            if ins.mnemonic_full == u'blal' or ins.mnemonic_full == u'blxal':
                hook.append(ins.address)

        # 初始化的符号执行，将pre_dispatcher部分的工作先完成，并保存状态
        init_state = init_symbolic_execution(start, pre_dispatcher, hook, loop)
        print '-----------------------------dse %#x-------------------------------' % prologue

        addr1, state1 = symbolic_execution(prologue, None, hook, relevants, loop, claripy.BVV(1, 1), True)
        addr2, state2 = symbolic_execution(prologue, None, hook, relevants, loop, claripy.BVV(0, 1), True)

        statedict = {}
        already = 0
        if addr1 != addr2:
            statedict[addr1] = state1
            statedict[addr2] = state2
            flow[prologue].append(addr1)
            flow[prologue].append(addr2)
            if addr1 in relevants_without_retn:
                index = relevants_without_retn.index(addr1)
                temp = relevants_without_retn[already]
                relevants_without_retn[index] = temp
                relevants_without_retn[already] = addr1
                already = already + 1
            if addr2 in relevants_without_retn:
                index = relevants_without_retn.index(addr2)
                temp = relevants_without_retn[already]
                relevants_without_retn[index] = temp
                relevants_without_retn[already] = addr2
                already = already + 1
        else:
            statedict[addr1] = state1
            flow[prologue].append(addr1)
            if addr1 in relevants_without_retn:
                index = relevants_without_retn.index(addr1)
                temp = relevants_without_retn[already]
                relevants_without_retn[index] = temp
                relevants_without_retn[already] = addr1
                already = already + 1
        a = list(set(relevants_without_retn))

        # if 0x1db8 in relevants_without_retn:
        #     print 'cdcedvwe'
        size = len(relevants_without_retn)
        for ind in range(0, size):
            relevant = relevants_without_retn[ind]
            # if relevant == 0x1cb4:
            #     print ind
            print '-----------------------------dse %#x-------------------------------' % relevant
            block = cfg.find_basic_block(relevant)
            branches = False
            hook = []
            hook = hook + hook_addr

            if relevant in has_branches:
                branches = True
            back_flag = True
            back = relevant
            while back_flag:
                for i, ins in enumerate(block.instrs):
                    if ins.mnemonic_full == u'blal' or ins.mnemonic_full == u'blxal':
                        hook.append(ins.address)

                if graph[back][0] in involved_control_blocks:
                    back = graph[back][0]
                    block = cfg.find_basic_block(back)
                    # count = count + 1
                else:
                    back_flag = False

            if branches:
                if relevant in statedict.keys():
                    state = statedict[relevant]
                else:
                    state = init_state
                address, state = symbolic_execution(relevant, state, hook, relevants, loop, claripy.BVV(1, 1), True)
                flow[relevant].append(address)
                statedict[address] = state
                if address in relevants_without_retn:

                    index = relevants_without_retn.index(address)
                    # if address == 0x1cb4:
                    #     print already
                    if index >= already:
                        temp = relevants_without_retn[already]
                        relevants_without_retn[index] = temp
                        relevants_without_retn[already] = address
                        already = already + 1
                elif address not in relevants_without_retn and address not in retn:
                    print('x2')

                address, state = symbolic_execution(relevant, state, hook, relevants, loop, claripy.BVV(0, 1), True)
                flow[relevant].append(address)
                statedict[address] = state

                if address in relevants_without_retn:
                    index = relevants_without_retn.index(address)
                    # if address == 0x1cb4:
                    #     print already
                    if index >= already:
                        temp = relevants_without_retn[already]
                        relevants_without_retn[index] = temp
                        relevants_without_retn[already] = address
                        already = already + 1
                elif address not in relevants_without_retn and address not in retn:
                    print('x2')
                already = already + 1

            else:
                if relevant in statedict.keys():
                    state = statedict[relevant]
                else:
                    state = init_state
                address, state = symbolic_execution(relevant, state, hook, relevants, loop)
                flow[relevant].append(address)
                statedict[address] = state

                if address in relevants_without_retn:
                    index = relevants_without_retn.index(address)
                    # if address == 0x1cb4:
                    #     print already
                    if index >= already:
                        temp = relevants_without_retn[already]
                        relevants_without_retn[index] = temp
                        relevants_without_retn[already] = address
                        already = already + 1

                elif address not in relevants_without_retn and address not in retn:
                    print('x3')
                already = already + 1

        # 该部分确认初始块是否有分支
        # 逻辑：prologue -> 保存state —> 第1个relevant块 —> 保存state -> 第2个relevant块
        #              |->是否有分支？—> 保存state -> 第2个relevant块
        # statedict = {}
        # if addr1 != addr2:
        #     statedict[addr1] = state1
        #     statedict[addr2] = state2
        #     flow[prologue].append(addr1)
        #     flow[prologue].append(addr2)
        # else:
        #     statedict[addr1] = state1
        #     flow[prologue].append(addr1)
        #
        # relevants_without_retn.sort()
        # for relevant in relevants_without_retn:
        #     print '-----------------------------dse %#x-------------------------------' % relevant
        #     block = cfg.find_basic_block(relevant)
        #     branches = False
        #     if block.address == 0x8c0:
        #         print('xsxs')
        #     hook = []
        #     hook = hook + hook_addr
        #     # if relevant == 0x9dc:
        #     #     print('x')
        #     if relevant in has_branches:
        #         branches = True
        #     back_flag = True
        #     back = relevant
        #     while back_flag:
        #         for i, ins in enumerate(block.instrs):
        #             if ins.mnemonic_full == u'blal' or ins.mnemonic_full == u'blxal':
        #                 hook.append(ins.address)
        #
        #         if graph[back][0] in involved_control_blocks:
        #             back = graph[back][0]
        #             block = cfg.find_basic_block(back)
        #             # count = count + 1
        #         else:
        #             back_flag = False
        #
        #     if branches:
        #         if relevant in statedict.keys():
        #             state = statedict[relevant]
        #         else:
        #             state = init_state
        #         address, state = symbolic_execution(relevant, state, hook, relevants, loop, claripy.BVV(1, 1),
        #                                             True)
        #         flow[relevant].append(address)
        #         statedict[address] = state
        #         address, state = symbolic_execution(relevant, state, hook, relevants, loop, claripy.BVV(0, 1),
        #                                             True)
        #         flow[relevant].append(address)
        #         statedict[address] = state
        #     else:
        #         if relevant in statedict.keys():
        #             state = statedict[relevant]
        #         else:
        #             state = init_state
        #         address, state = symbolic_execution(relevant, state, hook, relevants, loop)
        #         flow[relevant].append(address)
        #         statedict[address] = state

        print '-----------------------------flow-------------------------------'
        flow1 = dict(flow)
        for (k, v) in flow1.items():
            flow1[k] = list(set(flow1[k]))
            print '%#x:' % k, [hex(child) for child in set(v)]

        print '-----------------------------GET CFG-------------------------------'

        # origin_filename = "/Users/mark/Desktop/djbhash-origin"
        # origin_start = 0x628
        # G_origin = nx.DiGraph()
        # origin_flow = {}
        # origin = BARF(origin_filename)
        # origin_cfg = origin.recover_cfg(start=origin_start)
        # for block in origin_cfg.basic_blocks:
        #     if hex(block.address) not in origin_flow:
        #         origin_flow[hex(block.address)] = []
        #     for i in block.branches:
        #         origin_flow[hex(block.address)].append(hex(i[0]))
        #
        # for i, j in origin_flow.items():
        #     origin_flow[i] = []
        #     for k in j:
        #         origin_flow[i].append(k)
        #
        # # G_obfuscated.add_nodes_from(obfuscated_flow.keys())
        # ori = angr.Project(origin_filename, load_options={'auto_load_libs': False, 'main_opts': {'custom_base_addr': 0}})
        # for i in origin_flow.keys():
        #     block = origin_cfg.find_basic_block(int(i, 16))
        #     irsb = ori.factory.block(int(i, 16)).vex
        #     ir = irsb.__str__()
        #     size = len(block.instrs)
        #     while size>0:
        #         if irsb.instructions < size and irsb.jumpkind == "Ijk_Boring":
        #             b_next = int(irsb.next.con.value) + 4
        #             irsb = b.factory.block(b_next).vex
        #             ir = ir + irsb.__str__()
        #             size = size - irsb.instructions
        #         elif irsb.instructions < size and irsb.jumpkind == "Ijk_Call":
        #             b_next = int(irsb.next.con.value) + 4
        #             irsb = b.factory.block(b_next).vex
        #             ir = ir + irsb.__str__()
        #             size = size - irsb.instructions
        #         else:
        #             break
        #     G_origin.add_node(i, opcode=ir)
        # for parent in origin_flow.keys():
        #     origin_flow[parent] = list(set(origin_flow[parent]))
        #     for child in origin_flow[parent]:
        #         G_origin.add_edge(parent, child)
        # path = cfg_path + str(origin_start) + "_origin.dot"
        # nx.drawing.nx_agraph.write_dot(G_origin, path)

        G_obfuscated = nx.DiGraph()
        obfuscated_flow = {}
        obfuscated = BARF(filename)
        obfuscated_cfg = obfuscated.recover_cfg(start=start)
        for block in obfuscated_cfg.basic_blocks:
            if hex(block.address) not in obfuscated_flow:
                obfuscated_flow[hex(block.address)] = []
            for i in block.branches:
                obfuscated_flow[hex(block.address)].append(hex(i[0]))

        for i, j in obfuscated_flow.items():
            obfuscated_flow[i] = []
            for k in j:
                obfuscated_flow[i].append(k)

        # G_obfuscated.add_nodes_from(obfuscated_flow.keys())
        for i in obfuscated_flow.keys():
            # irsb = b.factory.block(int(i)).vex
            G_obfuscated.add_node(i, opcode=obfuscated_opcodes[int(i, 16)])
        for parent in obfuscated_flow.keys():
            obfuscated_flow[parent] = list(set(obfuscated_flow[parent]))
            for child in obfuscated_flow[parent]:
                G_obfuscated.add_edge(parent, child)
        path = cfg_path + str(start) + "_obfuscated.dot"
        nx.drawing.nx_agraph.write_dot(G_obfuscated, path)

        G_recover = nx.DiGraph()
        flow_hex = {}
        for i, j in flow.items():
            flow_hex[hex(i)] = []
            for k in j:
                flow_hex[hex(i)].append(hex(k))
        for i in flow_hex.keys():
            block = obfuscated_cfg.find_basic_block(int(i, 16))
            size = len(block.instrs)
            irsb = b.factory.block(int(i, 16)).vex
            ir = irsb.__str__()
            while size > 0:
                if irsb.instructions < size and irsb.jumpkind == "Ijk_Boring":
                    b_next = int(irsb.next.con.value) + 4
                    irsb = b.factory.block(b_next).vex
                    ir = ir + irsb.__str__()
                    size = size - irsb.instructions
                elif irsb.instructions < size and irsb.jumpkind == "Ijk_Call":
                    b_next = int(irsb.next.con.value) + 4
                    irsb = b.factory.block(b_next).vex
                    ir = ir + irsb.__str__()
                    size = size - irsb.instructions
                else:
                    break
            # if irsb.instructions < size and irsb.jumpkind == "Ijk_Boring":
            #     b_next = irsb.next + 4
            #     irsb = b.factory.block(b_next).vex
            #     irsb.pp()
            #     size = size - irsb.instructions
            # if irsb.instructions < size and irsb.jumpkind == "Ijk_Call":
            #     b_next = int(irsb.next) + 4
            #     irsb = b.factory.block(b_next).vex
            #     irsb.pp()
            #     size = size - irsb.instructions
            # if irsb.instructions < size and irsb.jumpkind == "Ijk_Call":
            #     b_next = int(irsb.next) + 4
            #     irsb = b.factory.block(b_next).vex
            #     irsb.pp()
            #     size = size - irsb.instructions

            G_recover.add_node(i, opcode=ir)
        # G_recover.add_nodes_from(flow_hex.keys())
        for parent in flow_hex.keys():
            flow_hex[parent] = list(set(flow_hex[parent]))
            for child in flow_hex[parent]:
                if child.endswith('L'):
                    child = child.replace('L', '')
                if child in G_recover.nodes:
                    G_recover.add_edge(parent, child)
                else:
                    if len(retn) >= 1:
                        G_recover.add_edge(parent, hex(retn[0]))
                    else:
                        G_recover.add_node(child, opcode=obfuscated_opcodes[int(child, 16)])
                        G_recover.add_edge(parent, child)
        path = cfg_path + str(start) + "_recovered.dot"
        nx.drawing.nx_agraph.write_dot(G_recover, path)

    else:
        print('skip %s' % filename.split('/')[-2])
