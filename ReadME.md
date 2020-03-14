# DiANa

DiANa is a binary-level deobfuscator for Android native code, which is based on [Angr](https://github.com/angr/angr) and [Barf](https://github.com/programa-stic/barf-project) project. 


## Description

Currently, DiANa supports the deobfuscation for all three types of obfuscation from [O-LLVM](https://github.com/obfuscator-llvm/obfuscator): **Instructions Substitution**, **Bogus Control Flow** and **Control Flow Flattening**. 

We are now working on making DiANa into a general-purpose deobfuscator.

## Run DiANa

### Dependencies

- install [Angr](https://github.com/angr/angr) and [Barf](https://github.com/programa-stic/barf-project) project.


### Deobfuscate your executable file

In your terminal, 
```
python DiANa.py -i|--input <FILEPATH> -t|--type <DEOBFUS_TYPE> -a|--address <FUNC_ADDR> -o|--output <OUTPUT_PATH> -l|--loop <CHECK_LOOP>
```
- ``<FILEPATH>`` is the path of the obfuscated binary file. 

- ``<DEOBFUS_TYPE>`` can be any combination of `1`, `2` and `3`. `1` means the **Instructions Substitution** deobfuscation, `2` means the **Bogus Control Flow** deobfuscation and `3` means the **Control Flow Flattening** deobfuscation. If the ``type`` flag is empty, DiANa would deobfuscate the input binary from the all three obfuscating approaches.

- ``<FUNC_ADDR>`` is the entry point of the obfuscated function, which could be extracted from some disassembler (e.g IDA).

- ``<OUTPUT_PATH>`` suggests the output file path.

- ``<CHECK_LOOP>`` is the loops of the deobfuscating process. The deflaut value is 5.

For example, you can run the following command to analyze Function_A (0x1234) from the file ``"Users/example/example.so"``:
```
 python DiANa.py -i "Users/example/example.so" -t 123 -a 0x1234 -o "Users/example/output/" -l 3
 ```

Currently, DiANa could only recover a binary obfuscated by Control Flow Flattening to a control flow graph level.

After deobfuscation of Control Flow Flattening, a file named ``XXX_recovered.dot`` will be generated in the output directory. You can use [vscode](https://github.com/microsoft/vscode) to view the generated CFG.

## Other Content Included in This Repository

- ``./CFG-optimization`` [directory](https://github.com/EVulHunter/EVulHunter/tree/master/Assistant): A python sript used to optimize the recovered CFG. The optimization rules could be found in the original paper.

- ``./Evaluation/`` [directory](https://github.com/EVulHunter/EVulHunter/tree/master/myhelper): The deobfuscation result of the evaluation part. 

- ``./requirments.txt`` [file](https://github.com/EVulHunter/EVulHunter/tree/master/myhelper): The required components that the DiANa project relies on. You should install these components before running DiANa on your computer. 
``` 
pip install -r requriements.txt 
```

## Acknowledgement
The implementation of symbol execution in DiANa (CFF part) inspried by the deflat script of the GitHub user [liumengdeqq](https://github.com/liumengdeqq/deflat) on x86 platform. 
