package main

// #cgo LDFLAGS: -lcapstone
// #include <capstone/capstone.h>
import "C"
import (
	"fmt"
)

type Disassembler struct {
	cs C.ulong
}

type Instruction struct {
	Address  uint32
	Mnemonic string
	Bytes    []byte
	Size     uint
}

func NewDisassembler() (*Disassembler, error) {
	var cs C.ulong
	if C.cs_open(C.CS_ARCH_ARM, C.CS_MODE_THUMB+C.CS_MODE_MCLASS, &cs) != C.CS_ERR_OK {
		return nil, fmt.Errorf("failed to initialize capstone")
	}

	return &Disassembler{cs}, nil
}

func (d *Disassembler) Close() {
	C.cs_close(&d.cs)
}

func (d *Disassembler) Disassemble(code []byte, addr uint32) (*Instruction, error) {
	var insn *C.cs_insn
	count := C.cs_disasm(d.cs, (*C.uchar)(&code[0]), C.size_t(len(code)), C.uint64_t(addr), 1, &insn)
	if count != 1 {
		err := C.cs_errno(d.cs)

		return nil, fmt.Errorf("disassemble instruction: %d", err)
	}
	defer C.cs_free(insn, 1)

	b := make([]byte, insn.size)
	for i := 0; i < int(insn.size); i++ {
		b[i] = byte(insn.bytes[i])
	}

	return &Instruction{
		Address:  uint32(insn.address),
		Mnemonic: C.GoString(&insn.mnemonic[0]) + " " + C.GoString(&insn.op_str[0]),
		Bytes:    b,
		Size:     uint(insn.size),
	}, nil
}
