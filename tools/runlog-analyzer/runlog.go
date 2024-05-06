package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// #cgo LDFLAGS: -lcapstone
// #include <capstone/capstone.h>
import "C"

const (
	RUNLOG_EV_RESET = iota + 1
	RUNLOG_EV_LOAD_PROGRAM
	RUNLOG_EV_FETCH_INST
	RUNLOG_EV_EXECUTE_INST
	RUNLOG_EV_MEMORY_WRITE
)

const (
	RUNLOG_REG_R0 = iota
	RUNLOG_REG_R1
	RUNLOG_REG_R2
	RUNLOG_REG_R3
	RUNLOG_REG_R4
	RUNLOG_REG_R5
	RUNLOG_REG_R6
	RUNLOG_REG_R7
	RUNLOG_REG_R8
	RUNLOG_REG_R9
	RUNLOG_REG_R10
	RUNLOG_REG_R11
	RUNLOG_REG_R12
	RUNLOG_REG_SP
	RUNLOG_REG_LR
	RUNLOG_REG_PC
	RUNLOG_REG_XPSR
	RUNLOG_REG_MSP
	RUNLOG_REG_PSP

	RUNLOG_REG_MAX = iota - 1
)

type Instruction struct {
	Address  uint32
	Mnemonic string
}

type Registers [RUNLOG_REG_MAX + 1]uint32

type Frame struct {
	Registers       Registers
	NextInstruction Instruction
}

func readRegs(br *bufio.Reader, regs *Registers) error {
	val := make([]byte, 4)

	for {
		reg, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("failed to read register number: %v", err)
		}
		if reg == 0xFF {
			break
		}

		if _, err := io.ReadFull(br, val); err != nil {
			return fmt.Errorf("failed to read register value: %v", err)
		}

		regs[reg] = binary.LittleEndian.Uint32(val)
	}

	return nil
}

func ReadFrames(r io.Reader) ([]Frame, error) {
	var regs Registers
	var program []byte
	var currentInst Instruction

	frames := make([]Frame, 0)

	br := bufio.NewReader(r)

	var cs C.ulong
	if C.cs_open(C.CS_ARCH_ARM, C.CS_MODE_THUMB+C.CS_MODE_MCLASS, &cs) != C.CS_ERR_OK {
		return nil, fmt.Errorf("failed to initialize capstone")
	}
	defer C.cs_close(&cs)

	for {
		evType, err := br.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, fmt.Errorf("read event type: %v", err)
		}

		switch evType {
		case RUNLOG_EV_LOAD_PROGRAM:
			var size uint32
			if err := binary.Read(br, binary.LittleEndian, &size); err != nil {
				return nil, fmt.Errorf("read program size: %v", err)
			}

			program = make([]byte, size)
			if _, err := io.ReadFull(br, program); err != nil {
				return nil, fmt.Errorf("read program data: %v", err)
			}

		case RUNLOG_EV_RESET:
			err = readRegs(br, &regs)
			if err != nil {
				return nil, fmt.Errorf("read registers: %v", err)
			}

		case RUNLOG_EV_FETCH_INST:
			binary.Read(br, binary.LittleEndian, &pc)

			var insn *C.cs_insn

			addr := pc & 0xFFFF_FFFE
			if C.cs_disasm(cs, (*C.uchar)(&program[addr]), C.size_t(len(program)-int(addr)), C.uint64_t(addr), 1, &insn) == 0 {
				return nil, fmt.Errorf("failed to disassemble instruction")
			}

			currentInst = Instruction{
				Address:  addr,
				Mnemonic: C.GoString(&insn.mnemonic[0]) + " " + C.GoString(&insn.op_str[0]),
			}

			C.cs_free(insn, 1)

		case RUNLOG_EV_EXECUTE_INST:
			err = readRegs(br, &regs)
			if err != nil {
				return nil, fmt.Errorf("read registers: %v", err)
			}

			frames = append(frames, Frame{
				Registers:       regs,
				NextInstruction: currentInst,
			})

		default:
			panic("unknown event type")
		}
	}

	return frames, nil
}
