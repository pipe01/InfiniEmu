from os import listdir
from os.path import isfile, join
from pathlib import Path
import subprocess

from dataclasses import dataclass
from typing import List, Dict

import yaml
import re

GCC_BIN = "/opt/gcc-arm-none-eabi-10.3-2021.10/bin"
AS = f"{GCC_BIN}/arm-none-eabi-as"
OBJCOPY = f"{GCC_BIN}/arm-none-eabi-objcopy"

AUTOGEN_HEADER = "/* AUTOGENERATED FILE, DO NOT EDIT */\n"

tests_dir = "."

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
class CPUState:
    memory: List[Memory]
    registers: Registers | None

def cpustate_from_spec(spec: any) -> CPUState:
    state = CPUState([], None)
    
    if "memory" in spec:
        memory_spec = spec["memory"]

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

    if "registers" in spec:
        registers_spec = spec["registers"]

        core = {}

        if "core" in registers_spec:
            core_spec = registers_spec["core"]

            for reg_spec in core_spec:
                value_spec = core_spec[reg_spec]

                if reg_spec == "sp":
                    reg = 13
                elif reg_spec == "lr":
                    reg = 14
                elif reg_spec == "pc":
                    reg = 15
                elif isinstance(reg_spec, int):
                    reg = reg_spec
                else:
                    raise ValueError("Invalid register key")
                
                if not isinstance(value_spec, int):
                    raise ValueError("Invalid register value")

                core[reg] = value_spec

        state.registers = Registers(core)
    
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
                test = TestCase(f"{group_name} #{test_num}", CPUState([], None), test_spec["execute"], 0, CPUState([], None))
                test_num += 1

                if "steps" in test_spec and test_spec["steps"] is int:
                    test.steps = test_spec["steps"]
                else:
                    test.steps = len(test.code)

                if "setup" in test_spec:
                    setup_spec = test_spec["setup"]
                    test.setup = cpustate_from_spec(setup_spec)

                if "expect" in test_spec:
                    expect_spec = test_spec["expect"]
                    test.expect = cpustate_from_spec(expect_spec)

                suite.cases.append(test)

    suites.append(suite)


with open("main.c", "w") as main:
    main.write(AUTOGEN_HEADER)
    main.write("#include <stdio.h>\n\n")
    main.write("typedef void (*test_t)();\n\n")

    for suite in suites:
        with open(f"{suite.name}.c", "w") as c:
            c.write(AUTOGEN_HEADER)

            c.write('#include "./common.h"\n\n')

            for test in suite.cases:
                main.write(f"void {test.func_name()}();\n")

                program = compile("\n".join(test.code) + "\n")

                test_name = f"{suite.name}/{test.name}"
            
                c.write(f"void {test.func_name()}() {{\n")
                c.write(f'#define TEST_NAME "{test.name}"\n')

                c.write("uint8_t program[] = {")
                c.write(", ".join([str(i) for i in program]))
                c.write("};\n")

                c.write("memreg_t *mem_first = NULL;\n")
                if len(test.setup.memory) > 0:
                    c.write("memreg_t *mem_last = NULL;\n")

                memcounter = 0
                for mem in test.setup.memory:
                    c.write(f"uint8_t memory{memcounter}[{mem.size}] = {{")
                    c.write(", ".join([str(i) for i in mem.value]))
                    c.write("};\n")
                    c.write(f"ADD_MEM_SIMPLE({mem.start}, memory{memcounter});\n")

                    memcounter += 1

                c.write("cpu_t *cpu = cpu_new(program, sizeof(program), mem_first);\n")

                if test.setup.registers is not None:
                    for reg in test.setup.registers.core:
                        c.write(f"cpu_reg_write(cpu, {core_register_enum(reg)}, {test.setup.registers.core[reg]});\n")

                c.write(f"for (size_t i = 0; i < {test.steps}; i++) {{\n")
                c.write("cpu_step(cpu);\n")
                c.write("}\n")

                if test.expect.registers is not None:
                    c.write("uint32_t value;\n")

                    for reg in test.expect.registers.core:
                        c.write(f"value = cpu_reg_read(cpu, {core_register_enum(reg)}); \n")
                        c.write(f"if (value != {test.expect.registers.core[reg]})\n")
                        c.write(f'\tprintf("Register {core_register_name(reg)}: expected {reg}, got %d\\n", value);\n')

                c.write("#undef TEST_NAME\n")
                c.write("}\n")
                c.write("\n")

    main.write("\n")

    main.write("int main() {\n")
    for suite in suites:
        main.write(f'printf("Running tests for {suite.name}\\n");\n')
        
        for test in suite.cases:
            main.write(f'printf("  [*] {test.name}\\n");\n')

            main.write(f"{test.func_name()}();\n")
    main.write("}\n")