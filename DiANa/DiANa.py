import logging, sys, getopt
from InsSub.DeInsSub import De_IS
from BogusControlFlow.EZDeBogusCF import De_BCF
from ControlFlowFlatten.De_CFF import De_CFF


def usage():
    print(
        '''
        usage: python DiANa.py -i|--input <FILEPATH> -t|--type <DEOBFUS_TYPE> -a|--address <FUNC_ADDR> 
        -o|--output <OUTPUT_PATH> -l|--loop <CHECK_LOOP>
        
        '''
    )


def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'i:t:a:o:l:', ['input', 'type', 'address', 'output', 'loop'])
    except getopt.GetoptError:
        usage()
        sys.exit()

    deob_type = 'all'
    for opt, arg in opts:
        if opt in ['-i', '--input']:
            file_name = arg
        elif opt in ['-t', '--type']:
            deob_type = arg
        elif opt in ['-a', '--address']:
            address = arg
        elif opt in ['-o', '--output']:
            output_file = arg
        elif opt in ['-l', '--loop']:
            loop = arg
        else:
            print("Error: invalid parameters")
            usage()
            sys.exit()

    print("Deobfuscator start!")
    print(file_name, deob_type, address, loop)
    if '3' in deob_type or 'all' in deob_type:
        De_CFF(file_name, address, loop, output_file)
    else:
        if '2' not in deob_type and '1' in deob_type:
            De_IS(file_name, address)
        elif '1' not in deob_type and '2' in deob_type:
            De_BCF(file_name, address)
        elif '1' in deob_type and '2' in deob_type:
            De_IS(file_name, address)
            De_BCF(file_name + '_recovered', address)
        else:
            print("please choose a valid mode!!")
    
    print("")


if __name__ == '__main__':
    main(sys.argv)