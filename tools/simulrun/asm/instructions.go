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
	RegisterXPSR
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

func (r Register) withMax(max uint32) FuzzedRegister {
	return FuzzedRegister{
		Register: r,
		Maximum:  max,
	}
}

type FuzzedRegister struct {
	Register Register
	Minimum  uint32
	Maximum  uint32
}

type XPSR uint32

func (x XPSR) N() bool {
	return x&(1<<31) != 0
}

func (x XPSR) Z() bool {
	return x&(1<<30) != 0
}

func (x XPSR) C() bool {
	return x&(1<<29) != 0
}

func (x XPSR) V() bool {
	return x&(1<<28) != 0
}

type ShiftType uint8

const (
	ShiftNone ShiftType = iota
	ShiftLSL
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
	return r.Type == ShiftNone || (r.Type != ShiftRRX && r.Amount == 0)
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

type Instruction struct {
	Name     string
	Flags    InstructionFlags
	Operands []any
}

func (i Instruction) String() string {
	name := i.Name

	if i.Flags.Has(FlagUpdateFlags) {
		name += "s"
	}
	if i.Flags.Has(FlagWide) {
		name += ".w"
	}

	opStrings := make([]string, 0, len(i.Operands))

	for _, op := range i.Operands {
		switch op := op.(type) {
		case Register:
			opStrings = append(opStrings, op.String())
		case FuzzedRegister:
			opStrings = append(opStrings, op.Register.String())
		case uint32, int32:
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

type InstructionFlags uint32

const (
	FlagNone        InstructionFlags = 0
	FlagUpdateFlags InstructionFlags = 1 << iota
	FlagMaybeUpdateFlags
	FlagWide
)

func (f InstructionFlags) Has(flag InstructionFlags) bool {
	return f&flag != 0
}

type RandASM struct {
	*rand.Rand
}

func (r RandASM) maybe() bool {
	return r.Int63()%2 == 0
}

func (r RandASM) MaybeNegative(n uint32) int32 {
	if r.maybe() {
		return -int32(n)
	}

	return int32(n)
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

func (r RandASM) RandRegisterBits(n int) Register {
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

func (r RandASM) RandShift(shiftType ...ShiftType) RegisterShift {
	if r.maybe() {
		var t ShiftType
		if len(shiftType) == 0 {
			t = ShiftType(r.Intn(5))
		} else {
			t = shiftType[r.Intn(len(shiftType))]
		}

		return RegisterShift{
			Type:   t,
			Amount: uint(r.Intn(32)),
		}
	}

	return RegisterShift{}
}

func (r *RandASM) RandROR8() RegisterShift {
	shift := r.RandShift(ShiftROR)
	if shift.Type != ShiftNone {
		shift.Amount = uint(r.Intn(4) * 8)
	}

	return shift
}

func (r RandASM) inst(name string, flags InstructionFlags, ops ...any) Instruction {
	if flags.Has(FlagMaybeUpdateFlags) && r.maybe() {
		flags |= FlagUpdateFlags
	}

	return Instruction{
		Name:     name,
		Flags:    flags,
		Operands: ops,
	}
}

type Generator func(r RandASM) Instruction

var Instructions = []Generator{
	// ADC (immediate)
	func(r RandASM) Instruction {
		return r.inst("adc", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},
	// ADC (register) T1
	func(r RandASM) Instruction {
		return r.inst("adc", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister())
	},
	// ADC (register) T2
	func(r RandASM) Instruction {
		return r.inst("adc", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// ADD (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("add", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(3))
	},
	// ADD (immediate) T2
	func(r RandASM) Instruction {
		return r.inst("add", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(8))
	},
	// ADD (immediate) T3
	func(r RandASM) Instruction {
		return r.inst("add", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},
	// ADD (immediate) T4
	func(r RandASM) Instruction {
		return r.inst("add", FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(12))
	},

	// ADD (register) T1
	func(r RandASM) Instruction {
		return r.inst("add", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3), r.RandRegisterBits(3))
	},
	// ADD (register) T2
	func(r RandASM) Instruction {
		return r.inst("add", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},
	// ADD (register) T3
	func(r RandASM) Instruction {
		return r.inst("add", FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// ADD (SP plus immediate) T1
	func(r RandASM) Instruction {
		return r.inst("add", FlagNone, r.RandRegisterBits(3), RegisterSP, r.RandIntBits(8))
	},
	// ADD (SP plus immediate) T2
	func(r RandASM) Instruction {
		return r.inst("add", FlagNone, RegisterSP, RegisterSP, r.RandIntBits(7)<<2)
	},
	// ADD (SP plus immediate) T3
	func(r RandASM) Instruction {
		return r.inst("add", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), RegisterSP, r.RandThumbImm())
	},
	// ADD (SP plus immediate) T4
	func(r RandASM) Instruction {
		return r.inst("add", FlagWide, r.RandLowRegister(), RegisterSP, r.RandIntBits(12))
	},

	// ADD (SP plus register) T1
	func(r RandASM) Instruction {
		reg := r.RandLowRegister()
		return r.inst("add", FlagNone, reg, RegisterSP, reg)
	},
	// ADD (SP plus register) T2
	func(r RandASM) Instruction {
		return r.inst("add", FlagNone, RegisterSP, r.RandLowRegister())
	},
	// ADD (SP plus register) T3
	func(r RandASM) Instruction {
		return r.inst("add", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), RegisterSP, r.RandLowRegister(), r.RandShift())
	},

	// These seem to emit SUB instructions instead of ADR
	// ADR T1
	func(r RandASM) Instruction {
		return r.inst("adr", FlagNone, r.RandLowRegister(), r.RandIntBits(8)<<2)
	},
	// ADR T2, T3
	func(r RandASM) Instruction {
		return r.inst("adr", FlagWide, r.RandLowRegister(), r.MaybeNegative(r.RandIntBits(12)))
	},

	// AND (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("and", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},

	// AND (register) T1
	func(r RandASM) Instruction {
		return r.inst("and", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister())
	},
	// AND (register) T2
	func(r RandASM) Instruction {
		return r.inst("and", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// ASR (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("asr", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3), r.RandIntBits(5))
	},
	// ASR (immediate) T2
	func(r RandASM) Instruction {
		return r.inst("asr", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(5))
	},

	// ASR (register) T1
	func(r RandASM) Instruction {
		return r.inst("asr", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3))
	},
	// ASR (register) T2
	func(r RandASM) Instruction {
		return r.inst("asr", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// BFC
	func(r RandASM) Instruction {
		lsb := r.RandIntBits(5)
		width := uint32(1)
		if lsb < 31 {
			width = uint32(r.Rand.Intn(31-int(lsb)) + 1)
		}

		return r.inst("bfc", FlagNone, r.RandLowRegister(), lsb, width)
	},

	// BFI
	func(r RandASM) Instruction {
		lsb := r.RandIntBits(5)
		width := uint32(1)
		if lsb < 31 {
			width = uint32(r.Rand.Intn(31-int(lsb)) + 1)
		}

		return r.inst("bfi", FlagNone, r.RandLowRegister(), r.RandLowRegister(), lsb, width)
	},

	// BIC (immediate)
	func(r RandASM) Instruction {
		return r.inst("bic", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},

	// BIC (register) T1
	func(r RandASM) Instruction {
		return r.inst("bic", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},
	// BIC (register) T2
	func(r RandASM) Instruction {
		return r.inst("bic", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// CLZ
	func(r RandASM) Instruction {
		return r.inst("clz", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},

	// CMN (immediate)
	func(r RandASM) Instruction {
		return r.inst("cmn", FlagNone, r.RandLowRegister(), r.RandThumbImm())
	},

	// CMN (register) T1
	func(r RandASM) Instruction {
		return r.inst("cmn", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},
	// CMN (register) T2
	func(r RandASM) Instruction {
		return r.inst("cmn", FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// CMP (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("cmp", FlagNone, r.RandLowRegister(), r.RandIntBits(8))
	},
	// CMP (immediate) T2
	func(r RandASM) Instruction {
		return r.inst("cmp", FlagWide, r.RandLowRegister(), r.RandThumbImm())
	},

	// CMP (register) T1, T2
	func(r RandASM) Instruction {
		return r.inst("cmp", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},
	// CMP (register) T3
	func(r RandASM) Instruction {
		return r.inst("cmp", FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// EOR (immediate)
	func(r RandASM) Instruction {
		return r.inst("eor", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},

	// EOR (register) T1
	func(r RandASM) Instruction {
		return r.inst("eor", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3))
	},
	// EOR (register) T2
	func(r RandASM) Instruction {
		return r.inst("eor", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// LSL (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("lsl", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3), r.RandIntBits(5))
	},
	// LSL (immediate) T2
	func(r RandASM) Instruction {
		return r.inst("lsl", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(5))
	},

	// LSL (register) T1
	func(r RandASM) Instruction {
		return r.inst("lsl", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3).withMax(32))
	},
	// LSL (register) T2
	func(r RandASM) Instruction {
		return r.inst("lsl", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister().withMax(32))
	},

	// LSR (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("lsr", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3), r.RandIntBits(5))
	},
	// LSR (immediate) T2
	func(r RandASM) Instruction {
		return r.inst("lsr", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(5))
	},

	// LSR (register) T1
	func(r RandASM) Instruction {
		return r.inst("lsr", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3).withMax(32))
	},
	// LSR (register) T2
	func(r RandASM) Instruction {
		return r.inst("lsr", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister().withMax(32))
	},

	// MLA
	func(r RandASM) Instruction {
		return r.inst("mla", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// MLS
	func(r RandASM) Instruction {
		return r.inst("mls", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// MUL
	func(r RandASM) Instruction {
		return r.inst("mul", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// MVN (immediate)
	func(r RandASM) Instruction {
		return r.inst("mvn", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandThumbImm())
	},

	// MVN (register) T1
	func(r RandASM) Instruction {
		return r.inst("mvn", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3))
	},
	// MVN (register) T2
	func(r RandASM) Instruction {
		return r.inst("mvn", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// ORN (immediate)
	func(r RandASM) Instruction {
		return r.inst("orn", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},

	// ORN (register)
	func(r RandASM) Instruction {
		return r.inst("orn", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// ORR (immediate)
	func(r RandASM) Instruction {
		return r.inst("orr", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},

	// ORR (register)
	func(r RandASM) Instruction {
		return r.inst("orr", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// PKHBT
	func(r RandASM) Instruction {
		return r.inst("pkhbt", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift(ShiftLSL))
	},

	// PKHTB
	func(r RandASM) Instruction {
		return r.inst("pkhtb", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift(ShiftASR))
	},

	// RBIT
	func(r RandASM) Instruction {
		return r.inst("rbit", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},

	// REV
	func(r RandASM) Instruction {
		return r.inst("rev", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},

	// REV16
	func(r RandASM) Instruction {
		return r.inst("rev16", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},

	// REVSH
	func(r RandASM) Instruction {
		return r.inst("revsh", FlagNone, r.RandLowRegister(), r.RandLowRegister())
	},

	// ROR (immediate)
	func(r RandASM) Instruction {
		return r.inst("ror", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(5))
	},

	// ROR (register) T1
	func(r RandASM) Instruction {
		return r.inst("ror", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3))
	},
	// ROR (register) T2
	func(r RandASM) Instruction {
		return r.inst("ror", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// RRX
	func(r RandASM) Instruction {
		return r.inst("rrx", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister())
	},

	// RSB (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("rsb", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3), uint32(0))
	},
	// RSB (immediate) T2
	func(r RandASM) Instruction {
		return r.inst("rsb", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},

	// RSB (register)
	func(r RandASM) Instruction {
		return r.inst("rsb", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// SADD16
	func(r RandASM) Instruction {
		return r.inst("sadd16", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// SADD8
	func(r RandASM) Instruction {
		return r.inst("sadd8", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// SASX
	func(r RandASM) Instruction {
		return r.inst("sasx", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// SBC (immediate)
	func(r RandASM) Instruction {
		return r.inst("sbc", FlagMaybeUpdateFlags, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},

	// SBC (register) T1
	func(r RandASM) Instruction {
		return r.inst("sbc", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3))
	},
	// SBC (register) T2
	func(r RandASM) Instruction {
		return r.inst("sbc", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// SBFX
	func(r RandASM) Instruction {
		lsb := r.RandIntBits(5)
		width := uint32(1)
		if lsb < 31 {
			width = uint32(r.Rand.Intn(31-int(lsb)) + 1)
		}

		return r.inst("sbfx", FlagNone, r.RandLowRegister(), r.RandLowRegister(), lsb, width)
	},

	// SDIV
	func(r RandASM) Instruction {
		return r.inst("sdiv", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// SEL
	func(r RandASM) Instruction {
		return r.inst("sel", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// SMULL
	func(r RandASM) Instruction {
		rdlo := r.RandLowRegister()

		rdhi := r.RandLowRegister()
		for rdlo == rdhi {
			rdlo = r.RandLowRegister()
		}

		return r.inst("smull", FlagNone, rdlo, rdhi, r.RandLowRegister(), r.RandLowRegister())
	},

	// SUB (immediate) T1
	func(r RandASM) Instruction {
		return r.inst("sub", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(3))
	},
	// SUB (immediate) T2
	func(r RandASM) Instruction {
		return r.inst("sub", FlagNone, r.RandLowRegister(), r.RandIntBits(8))
	},
	// SUB (immediate) T3
	func(r RandASM) Instruction {
		return r.inst("sub", FlagMaybeUpdateFlags|FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandThumbImm())
	},
	// SUB (immediate) T4
	func(r RandASM) Instruction {
		return r.inst("sub", FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandIntBits(12))
	},

	// SXTAB
	func(r RandASM) Instruction {
		return r.inst("sxtab", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},

	// SXTAH
	func(r RandASM) Instruction {
		return r.inst("sxtah", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},

	// SXTB
	func(r RandASM) Instruction {
		return r.inst("sxtb", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},

	// SXTH
	func(r RandASM) Instruction {
		return r.inst("sxth", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},

	// TEQ (immediate)
	func(r RandASM) Instruction {
		return r.inst("teq", FlagNone, r.RandLowRegister(), r.RandThumbImm())
	},

	// TEQ (register)
	func(r RandASM) Instruction {
		return r.inst("teq", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// TST (immediate)
	func(r RandASM) Instruction {
		return r.inst("tst", FlagNone, r.RandLowRegister(), r.RandThumbImm())
	},

	// TST (register) T1
	func(r RandASM) Instruction {
		return r.inst("tst", FlagNone, r.RandRegisterBits(3), r.RandRegisterBits(3))
	},

	// TST (register) T2
	func(r RandASM) Instruction {
		return r.inst("tst", FlagWide, r.RandLowRegister(), r.RandLowRegister(), r.RandShift())
	},

	// UADD8
	func(r RandASM) Instruction {
		return r.inst("uadd8", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister())
	},

	// UBFX
	func(r RandASM) Instruction {
		lsb := r.RandIntBits(5)
		width := uint32(1)
		if lsb < 31 {
			width = uint32(r.Rand.Intn(31-int(lsb)) + 1)
		}

		return r.inst("ubfx", FlagNone, r.RandLowRegister(), r.RandLowRegister(), lsb, width)
	},

	// UMLAL
	func(r RandASM) Instruction {
		rdlo := r.RandLowRegister()

		rdhi := r.RandLowRegister()
		for rdlo == rdhi {
			rdlo = r.RandLowRegister()
		}

		return r.inst("umlal", FlagNone, rdlo, rdhi, r.RandLowRegister(), r.RandLowRegister())
	},

	// UMULL
	func(r RandASM) Instruction {
		rdlo := r.RandLowRegister()

		rdhi := r.RandLowRegister()
		for rdlo == rdhi {
			rdlo = r.RandLowRegister()
		}

		return r.inst("umull", FlagNone, rdlo, rdhi, r.RandLowRegister(), r.RandLowRegister())
	},

	// USAT
	func(r RandASM) Instruction {
		return r.inst("usat", FlagNone, r.RandLowRegister(), r.RandIntBits(5), r.RandLowRegister(), r.RandShift(ShiftLSL, ShiftASR))
	},

	// UXTB
	func(r RandASM) Instruction {
		return r.inst("uxtb", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},

	// UXTH
	func(r RandASM) Instruction {
		return r.inst("uxth", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},

	// UXTAH
	func(r RandASM) Instruction {
		return r.inst("uxtah", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},

	// UXTAB
	func(r RandASM) Instruction {
		return r.inst("uxtab", FlagNone, r.RandLowRegister(), r.RandLowRegister(), r.RandLowRegister(), r.RandROR8())
	},
}
