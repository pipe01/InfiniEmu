package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// #cgo LDFLAGS: -lcapstone
// #include <capstone/capstone.h>
import "C"

type RunlogEventType byte

const (
	RUNLOG_EV_RESET RunlogEventType = iota + 1
	RUNLOG_EV_LOAD_PROGRAM
	RUNLOG_EV_FETCH_INST
	RUNLOG_EV_EXECUTE_INST
	RUNLOG_EV_MEMORY_LOAD
	RUNLOG_EV_MEMORY_STORE
	RUNLOG_EV_EXCEPTION_ENTER
	RUNLOG_EV_EXCEPTION_EXIT
)

type RunlogRegister byte

const (
	RUNLOG_REG_R0 RunlogRegister = iota
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

	RUNLOG_REG_MAX RunlogRegister = iota - 1
)

func (r RunlogRegister) String() string {
	switch r {
	case RUNLOG_REG_R0:
		return "r0"
	case RUNLOG_REG_R1:
		return "r1"
	case RUNLOG_REG_R2:
		return "r2"
	case RUNLOG_REG_R3:
		return "r3"
	case RUNLOG_REG_R4:
		return "r4"
	case RUNLOG_REG_R5:
		return "r5"
	case RUNLOG_REG_R6:
		return "r6"
	case RUNLOG_REG_R7:
		return "r7"
	case RUNLOG_REG_R8:
		return "r8"
	case RUNLOG_REG_R9:
		return "r9"
	case RUNLOG_REG_R10:
		return "r10"
	case RUNLOG_REG_R11:
		return "r11"
	case RUNLOG_REG_R12:
		return "r12"
	case RUNLOG_REG_SP:
		return "sp"
	case RUNLOG_REG_LR:
		return "lr"
	case RUNLOG_REG_PC:
		return "pc"
	case RUNLOG_REG_XPSR:
		return "xpsr"
	case RUNLOG_REG_MSP:
		return "msp"
	case RUNLOG_REG_PSP:
		return "psp"
	}

	return "unknown"
}

type MemoryAccess struct {
	IsWrite   bool
	Address   uint32
	Value     uint32
	Register  RunlogRegister
	SizeBytes int
}

type Instruction struct {
	Address  uint32
	Mnemonic string
}

type Registers [RUNLOG_REG_MAX + 1]uint32

type Frame struct {
	Program         []byte
	Registers       Registers
	NextInstruction Instruction
	MemoryAccesses  []MemoryAccess
}

type Frames []*Frame

func (f Frames) Last() *Frame {
	return f[len(f)-1]
}

func (f Frames) ReadMemoryAt(addr uint32) (uint32, error) {
	var value uint32

	if addr < 0x8_0000-4 {
		value = binary.LittleEndian.Uint32(f.Last().Program[addr:])
	} else if addr >= 0x2000_0000 && addr < 0x2001_0000-4 {
		for _, frame := range f {
			for _, access := range frame.MemoryAccesses {
				if access.Address == addr && access.IsWrite {
					switch access.SizeBytes {
					case 1:
						value |= access.Value & 0xFF
					case 2:
						value |= access.Value & 0xFFFF
					case 4:
						value = access.Value
					}
				}
			}
		}
	} else {
		return 0, errors.New("memory address outside readable ranges")
	}

	return value, nil
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

func ReadFrames(r io.Reader) (Frames, error) {
	var regs Registers
	var program []byte
	var currentInst Instruction

	var currentFrame *Frame
	frames := make([]*Frame, 0)

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

		switch RunlogEventType(evType) {
		case RUNLOG_EV_RESET:
			err = readRegs(br, &regs)
			if err != nil {
				return nil, fmt.Errorf("read registers: %v", err)
			}

		case RUNLOG_EV_LOAD_PROGRAM:
			var size uint32
			if err := binary.Read(br, binary.LittleEndian, &size); err != nil {
				return nil, fmt.Errorf("read program size: %v", err)
			}

			program = make([]byte, size)
			if _, err := io.ReadFull(br, program); err != nil {
				return nil, fmt.Errorf("read program data: %v", err)
			}

		case RUNLOG_EV_FETCH_INST:
			var pc uint32
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

			currentFrame = &Frame{
				Program:         program,
				Registers:       regs,
				NextInstruction: currentInst,
			}
			frames = append(frames, currentFrame)

		case RUNLOG_EV_EXECUTE_INST:
			err = readRegs(br, &regs)
			if err != nil {
				return nil, fmt.Errorf("read registers: %v", err)
			}

		case RUNLOG_EV_MEMORY_LOAD:
			{
				var addr uint32
				var value uint32
				var dstReg RunlogRegister
				var size byte

				binary.Read(br, binary.LittleEndian, &addr)
				binary.Read(br, binary.LittleEndian, &value)
				binary.Read(br, binary.LittleEndian, &dstReg)
				binary.Read(br, binary.LittleEndian, &size)

				currentFrame.MemoryAccesses = append(currentFrame.MemoryAccesses, MemoryAccess{
					IsWrite:   false,
					Address:   addr,
					Value:     value,
					Register:  dstReg,
					SizeBytes: int(size),
				})
			}

		case RUNLOG_EV_MEMORY_STORE:
			{
				var srcReg RunlogRegister
				var value uint32
				var addr uint32
				var size byte

				binary.Read(br, binary.LittleEndian, &srcReg)
				binary.Read(br, binary.LittleEndian, &value)
				binary.Read(br, binary.LittleEndian, &addr)
				binary.Read(br, binary.LittleEndian, &size)

				currentFrame.MemoryAccesses = append(currentFrame.MemoryAccesses, MemoryAccess{
					IsWrite:   true,
					Address:   addr,
					Value:     value,
					Register:  srcReg,
					SizeBytes: int(size),
				})
			}

		case RUNLOG_EV_EXCEPTION_ENTER, RUNLOG_EV_EXCEPTION_EXIT:
			{
				var exceptionType uint16

				binary.Read(br, binary.LittleEndian, &exceptionType)

				//TODO: Implement
			}

		default:
			panic("unknown event type")
		}
	}

	return frames, nil
}
