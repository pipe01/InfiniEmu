package asm

import (
	"fmt"
	"math/rand"
	"strings"
)

type Register uint8

const (
	RegisterR0 Register = iota
	RegisterR1
	RegisterR2
	RegisterR3
	RegisterR4
	RegisterR5
	RegisterR6
	RegisterR7
	RegisterR8
	RegisterR9
	RegisterR10
	RegisterR11
	RegisterR12
	RegisterSP
	RegisterLR
	RegisterPC
)

func (r Register) String() string {
	if r <= 12 {
		return fmt.Sprintf("r%d", r)
	}

	switch r {
	case RegisterSP:
		return "sp"
	case RegisterLR:
		return "lr"
	case RegisterPC:
		return "pc"
	default:
		return "unknown"
	}
}

type ShiftType uint8

const (
	ShiftLSL ShiftType = iota
	ShiftLSR
	ShiftASR
	ShiftROR
	ShiftRRX
)

func (s ShiftType) String() string {
	switch s {
	case ShiftLSL:
		return "lsl"
	case ShiftLSR:
		return "lsr"
	case ShiftASR:
		return "asr"
	case ShiftROR:
		return "ror"
	case ShiftRRX:
		return "rrx"
	default:
		panic("invalid shift type")
	}
}

type RegisterShift struct {
	Type   ShiftType
	Amount uint
}

func (r RegisterShift) IsEmpty() bool {
	return r.Type != ShiftRRX && r.Amount == 0
}

func (r RegisterShift) String() string {
	if r.Type == ShiftRRX {
		return r.Type.String()
	}
	if r.Amount == 0 {
		return ""
	}

	return fmt.Sprintf("%s #%d", r.Type, r.Amount)
}

type RandASM struct {
	*rand.Rand
}

func (r RandASM) maybe() bool {
	return r.Int63()%2 == 0
}

func (r RandASM) RandIntBits(n int) uint32 {
	return uint32(r.Int63()) & (1<<n - 1)
}

func (r RandASM) RandRegister() Register {
	return Register(r.Intn(16))
}

func (r RandASM) RandLowRegister() Register {
	return Register(r.Intn(13))
}

func (r RandASM) RandRegisterN(n int) Register {
	return Register(r.Intn(n))
}

func (r RandASM) RandThumbImm() uint32 {
	imm8 := r.RandIntBits(8)

	if r.maybe() {
		// Simple value

		switch r.Int63() % 4 {
		case 0:
			return imm8
		case 1:
			return imm8 | (imm8 << 16)
		case 2:
			return (imm8 << 8) | (imm8 << 24)
		case 3:
			return imm8 | (imm8 << 8) | (imm8 << 16) | (imm8 << 24)
		default:
			panic("unreachable")
		}
	} else {
		// Rotated value

		lsl := (r.Int63() % 24) + 1
		imm8 |= 1 << 7

		return imm8 << lsl
	}
}

func (r RandASM) RandUpdateFlags(insName string, ops string, a ...any) string {
	if r.maybe() {
		insName += "s"
	}

	return fmt.Sprintf("%s "+ops, append([]any{insName}, a...)...)
}

func (r RandASM) RandShift() RegisterShift {
	if r.maybe() {
		return RegisterShift{
			Type:   ShiftType(r.Intn(5)),
			Amount: uint(r.Intn(32)),
		}
	}

	return RegisterShift{}
}

func (r RandASM) inst(name string, canUpdateFlags bool, ops ...any) string {
	if canUpdateFlags && r.maybe() {
		if strings.HasSuffix(name, ".w") {
			name = name[:len(name)-2] + "s.w"
		} else {
			name += "s"
		}
	}

	opStrings := make([]string, 0, len(ops))

	for _, op := range ops {
		switch op := op.(type) {
		case Register:
			opStrings = append(opStrings, op.String())
		case uint32:
			opStrings = append(opStrings, fmt.Sprintf("#%d", op))
		case RegisterShift:
			if !op.IsEmpty() {
				opStrings = append(opStrings, op.String())
			}
		default:
			panic("invalid operand type")
		}
	}

	return fmt.Sprintf("%s %s", name, strings.Join(opStrings, ", "))
}

type Generator func(r RandASM) string

var Instructions = []Generator{
	// ADC (immediate)
	func(r RandASM) string {
		return r.inst("adc", true, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},
	// ADC (register) T1
	func(r RandASM) string {
		return r.inst("adc", true, r.RandLowRegister(), r.RandLowRegister())
	},
	// ADC (register) T2
	func(r RandASM) string {
		return r.inst("adc", true, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// ADD (immediate) T1
	func(r RandASM) string {
		return r.inst("add", false, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(3))
	},
	// ADD (immediate) T2
	func(r RandASM) string {
		return r.inst("add", false, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(8))
	},
	// ADD (immediate) T3
	func(r RandASM) string {
		return r.inst("add.w", true, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},
	// ADD (immediate) T4
	func(r RandASM) string {
		return r.inst("add.w", false, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(12))
	},

	// ADD (register) T1
	func(r RandASM) string {
		return r.inst("add", false, r.RandRegisterN(8), r.RandRegisterN(8), r.RandRegisterN(8))
	},
	// ADD (register) T2
	func(r RandASM) string {
		return r.inst("add", false, r.RandLowRegister(), r.RandLowRegister())
	},
	// ADD (register) T3
	func(r RandASM) string {
		return r.inst("add", true, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// ADD (SP plus immediate) T1
	func(r RandASM) string {
		return r.inst("add", false, r.RandRegisterN(8), RegisterSP, r.RandIntBits(8))
	},
	// ADD (SP plus immediate) T2
	func(r RandASM) string {
		return r.inst("add", false, RegisterSP, RegisterSP, r.RandIntBits(7)<<2)
	},
}
