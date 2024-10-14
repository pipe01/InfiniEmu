from os import listdir, environ
from os.path import isfile, join
from pathlib import Path
import subprocess

from dataclasses import dataclass
from typing import List, Dict

import yaml
import re

GCC_BIN = environ["ARM_TOOLCHAIN_PATH"] + "/bin"
AS = f"{GCC_BIN}/arm-none-eabi-as"
OBJCOPY = f"{GCC_BIN}/arm-none-eabi-objcopy"

AUTOGEN_HEADER = "/* AUTOGENERATED FILE, DO NOT EDIT */\n"

tests_dir = "./suites"

test_files = [join(tests_dir, f) for f in listdir(tests_dir) if isfile(join(tests_dir, f)) and f.endswith(".yaml")]

@dataclass
class Memory:
    start: int
    size: int
    value: List[int]

@dataclass
class Registers:
    core: Dict[int, int]

@dataclass
class Flags:
    negative: bool | None = None
    carry: bool | None = None
    overflow: bool | None = None
    zero: bool | None = None

@dataclass
class CPUState:
    memory: List[Memory]
    registers: Registers | None = None
    flags: Flags | None = None

def cpustate_from_spec(spec: any, setupState: CPUState | None) -> CPUState:
    state = CPUState([])

    for key, value in spec.items():
        if key == "memory":
            memory_spec = value

            for addr_spec in memory_spec:
                fill_spec = memory_spec[addr_spec]

                if isinstance(fill_spec, int):
                    fill = [fill_spec]
                elif isinstance(fill_spec, list):
                    if not all(isinstance(i, int) for i in fill_spec):
                        raise ValueError("Invalid memory fill value")
                    fill = fill_spec
                elif isinstance(fill_spec, str):
                    fill = list(bytes(fill_spec, "ascii"))
                else:
                    raise ValueError("Invalid memory fill value")

                if isinstance(addr_spec, str):
                    addr_spec = addr_spec.replace("_", "")
                    if "-" in addr_spec:
                        start, end = addr_spec.split("-")
                        start = int(start, 0)
                        end = int(end, 0)
                        size = end - start
                    else:
                        start = int(addr_spec, 0)
                        size = len(fill)
                elif isinstance(addr_spec, int):
                    start = addr_spec
                    size = len(fill)
                else:
                    raise ValueError("Invalid memory address")

                state.memory.append(Memory(start, size, fill))

        elif key == "registers":
            registers_spec = value

            core = {}

            for reg_name, value in registers_spec.items():
                if reg_name[0] == "r":
                    reg = int(reg_name[1:])
                elif reg_name == "sp":
                    reg = 13
                elif reg_name == "lr":
                    reg = 14
                elif reg_name == "pc":
                    reg = 15
                else:
                    raise ValueError("Invalid register name")

                if value == "==" and setupState is not None:
                    value = setupState.registers.core[reg]
                elif not isinstance(value, int):
                    raise ValueError("Invalid register value")
                
                core[reg] = value

            state.registers = Registers(core)

        elif len(key) <= 4 and isinstance(value, str) and len(key) == len(value):
            state.flags = Flags()

            for i in range(len(key)):
                c = key[i]
                
                if value[i] == "0":
                    on = False
                elif value[i] == "1":
                    on = True
                elif value[i] == "x":
                    on = None
                else:
                    raise ValueError(f"Invalid flag value {value[i]}")

                if c == "n":
                    state.flags.negative = on
                elif c == "c":
                    state.flags.carry = on
                elif c == "v":
                    state.flags.overflow = on
                elif c == "z":
                    state.flags.zero = on
                else:
                    raise ValueError(f"Invalid flag {c}")

        else:
            raise ValueError(f"Invalid key {key}")
    
    return state

@dataclass
class TestCase:
    name: str
    setup: CPUState
    code: List[str]
    steps: int
    expect: CPUState

    def func_name(self) -> str:
        return "test_" + re.sub(r'[^a-zA-Z0-9_]', '_', self.name)

@dataclass
class TestSuite:
    name: str
    cases: List[TestCase]

def compile(code: str) -> bytes:
    elf_path = "/tmp/test.elf"
    bin_path = "/tmp/test.bin"

    subprocess.run([AS, "-mcpu=cortex-m4", "-march=armv7-m", "-o", elf_path, "-"], input=code.encode("utf8"), check=True)
    subprocess.run([OBJCOPY, "-O", "binary", elf_path, bin_path], check=True)

    with open(bin_path, "rb") as f:
        return f.read()

def core_register_enum(n: int) -> str:
    return f"ARM_REG_R{n}"

def core_register_name(n: int) -> str:
    if n <= 12:
        return f"R{n}"
    elif n == 13:
        return "SP"
    elif n == 14:
        return "LR"
    elif n == 15:
        return "PC"
    return "UNKNOWN"

suites: List[TestSuite] = list()

for test_file in test_files:
    suite = TestSuite(Path(test_file).stem, [])

    with (open(test_file, 'r')) as f:
        spec = yaml.load(f, Loader=yaml.FullLoader)

        for group_name, group_spec in spec.items():
            test_num = 1
            
            for test_spec in group_spec:
                name = test_spec["name"] if "name" in test_spec else f"#{test_num}"

                test = TestCase(f"{group_name} {name}", CPUState([], None), test_spec["execute"], 0, CPUState([], None))
                test_num += 1

                if "steps" in test_spec and test_spec["steps"] is int:
                    test.steps = test_spec["steps"]
                else:
                    test.steps = len(test.code)

                if "setup" in test_spec:
                    setup_spec = test_spec["setup"]
                    test.setup = cpustate_from_spec(setup_spec, None)

                if "expect" in test_spec:
                    expect_spec = test_spec["expect"]
                    test.expect = cpustate_from_spec(expect_spec, test.setup)

                suite.cases.append(test)

    suites.append(suite)

suites.sort(key=lambda s: s.name)

with open("main.c", "w") as main:
    main.write(AUTOGEN_HEADER)
    main.write("""#include <stdio.h>
#include <stdint.h>
               
#include "arm.h"
#include "cpu.h"

""")

    for suite in suites:
        for test in suite.cases:
            program = compile(".syntax unified\n" + "\n".join(test.code) + "\n")

            test_name = f"{suite.name}/{test.name}"
        
            main.write(f"void {test.func_name()}() {{\n")

            main.write("uint8_t program[] = {")
            main.write(", ".join([str(i) for i in program]))
            main.write("};\n")

            main.write("memreg_t *mem_first = NULL;\n")
            if len(test.setup.memory) > 0:
                main.write("memreg_t *mem_last = NULL;\n")

            memcounter = 0
            for mem in test.setup.memory:
                main.write(f"uint8_t memory{memcounter}[{mem.size}] = {{")
                main.write(", ".join([str(i) for i in mem.value])) #TODO: Repeat values if necessary to fill array
                main.write("};\n")

                reg = f"memreg_new_simple({mem.start}, memory{memcounter}, sizeof(memory{memcounter}))"
                if memcounter == 0:
                    main.write(f"mem_first = mem_last = {reg};\n")
                else:
                    main.write(f"mem_last = memreg_set_next(mem_last, {reg});\n")

                memcounter += 1

            main.write("cpu_t *cpu = cpu_new(program, sizeof(program), mem_first, 512, 3);\n")

            if test.setup.registers is not None:
                for reg in test.setup.registers.core:
                    main.write(f"cpu_reg_write(cpu, {core_register_enum(reg)}, {test.setup.registers.core[reg]});\n")

            main.write(f"for (size_t i = 0; i < {test.steps}; i++) {{\n")
            main.write("cpu_step(cpu);\n")
            main.write("}\n")

            if test.expect.registers is not None:
                main.write("uint32_t value;\n")

                for reg in test.expect.registers.core:
                    main.write(f"value = cpu_reg_read(cpu, {core_register_enum(reg)}); \n")
                    main.write(f"if (value != (uint32_t)({test.expect.registers.core[reg]}))\n")
                    main.write(f'\tprintf("    [!] Register {core_register_name(reg)}: expected {test.expect.registers.core[reg]}, got %d\\n", value);\n')

            if len(test.expect.memory) > 0:
                for mem in test.expect.memory:
                    for i in range(len(mem.value)):
                        addr = mem.start + i
                        main.write(f"if ((memory_map_read(mem_first, {addr}) & 0xFF) != {mem.value[i]})\n")
                        main.write(f'\tprintf("    [!] Memory at 0x{addr:08X}: expected {mem.value[i]}, got %d\\n", memory_map_read(mem_first, {addr}) & 0xFF);\n')

            def test_flag(expected: bool | None, flag_const: str):
                if expected is not None:
                    main.write(f"flag_value = (cpu_sysreg_read(cpu, ARM_SYSREG_XPSR) & (1 << {flag_const})) != 0;\n")
                    main.write(f"if (flag_value != {'true' if expected else 'false'})\n")
                    main.write(f'\tprintf("    [!] Flag {flag_const}: expected {1 if expected else 0}, got %d\\n", flag_value);\n')
                pass

            if test.expect.flags != None:
                main.write("uint32_t flag_value;\n")
                test_flag(test.expect.flags.negative, "APSR_N")
                test_flag(test.expect.flags.carry, "APSR_C")
                test_flag(test.expect.flags.overflow, "APSR_V")
                test_flag(test.expect.flags.zero, "APSR_Z")

            main.write("cpu_free(cpu);\n")
            main.write("memreg_free(mem_first);\n")

            main.write("}\n")
            main.write("\n")

    main.write("\n")

    main.write("int main() {\n")
    for suite in suites:
        main.write(f'printf("Running tests for {suite.name}\\n");\n')

        for test in suite.cases:
            main.write(f'printf("  [*] {test.name}\\n");\n')

            main.write(f"{test.func_name()}();\n")

        main.write('printf("\\n");\n')
    main.write("}\n")