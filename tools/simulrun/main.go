package main

import (
	"encoding/hex"
	"flag"
	"log"
	"math/rand"
	"simulrun/asm"
	"sync/atomic"
	"time"
)

// const startAt = 0x4d70 // <main>
const startAt = 0x572e // <vPortSetupTimerInterrupt>

var randomInstructions bool

type Instruction struct {
	Instruction asm.Instruction
	Data        []byte
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func generateInstructions(ch chan<- Instruction, workers int) {
	var instCounter atomic.Uint64

	for i := 0; i < workers; i++ {
		r := rand.New(rand.NewSource(time.Now().UnixMicro() + int64(i)))

		go func() {
			var n uint64

			for {
				if randomInstructions {
					n = r.Uint64()
				} else {
					n = instCounter.Add(1)
				}

				gen := asm.Instructions[n%uint64(len(asm.Instructions))]
				inst := gen(asm.RandASM{Rand: r})

				b, err := asm.Assemble(inst.String(), asm.ToolPaths{
					As:      "toolchain/bin/arm-none-eabi-as",
					Objcopy: "toolchain/bin/arm-none-eabi-objcopy",
				})
				if err != nil {
					log.Fatal(err)
				}

				ch <- Instruction{
					Instruction: inst,
					Data:        b,
				}
			}
		}()
	}
}

func printRegisters(regs1, regs2 *[RegisterCount]uint32, mismatched map[asm.Register]struct{}) {
	for i := asm.RegisterR0; i < RegisterCount; i++ {
		marker := ""
		if _, ok := mismatched[i]; ok {
			marker = " !!"
		}

		log.Printf("  %s: 0x%08X 0x%08X%s", RegisterNames[i], regs1[i], regs2[i], marker)
	}
}

func checkRegisterMismatches(regs1, regs2 *[RegisterCount]uint32) bool {
	mismatch := false
	mismatched := map[asm.Register]struct{}{}

	for i := asm.RegisterR0; i < RegisterCount; i++ {
		if regs1[i] != regs2[i] {
			mismatch = true
			mismatched[i] = struct{}{}
		}
	}

	if mismatch {
		log.Printf("registers mismatch")
		printRegisters(regs1, regs2, mismatched)

		if _, ok := mismatched[asm.RegisterXPSR]; ok {
			xpsr1 := asm.XPSR(regs1[asm.RegisterXPSR])
			xpsr2 := asm.XPSR(regs2[asm.RegisterXPSR])

			if xpsr1.N() != xpsr2.N() {
				log.Printf("  N flag: %v %v", xpsr1.N(), xpsr2.N())
			}
			if xpsr1.Z() != xpsr2.Z() {
				log.Printf("  Z flag: %v %v", xpsr1.Z(), xpsr2.Z())
			}
			if xpsr1.C() != xpsr2.C() {
				log.Printf("  C flag: %v %v", xpsr1.C(), xpsr2.C())
			}
			if xpsr1.V() != xpsr2.V() {
				log.Printf("  V flag: %v %v", xpsr1.V(), xpsr2.V())
			}
		}

		return true
	}

	return false
}

func main() {
	fuzzCount := flag.Int("fuzz", 0, "run fuzzer for this amount of instructions, -1 to run indefinitely")
	flag.BoolVar(&randomInstructions, "random", false, "choose random instructions when fuzzing instead of round-robin")
	flag.Parse()

	if flag.NArg() != 2 {
		log.Fatalf("expected 2 arguments: <gdb1> <gdb2>")
	}

	gdb1, err := DialGDB(flag.Arg(0))
	if err != nil {
		log.Fatalf("failed to dial gdb1: %v", err)
	}
	gdb2, err := DialGDB(flag.Arg(1))
	if err != nil {
		log.Fatalf("failed to dial gdb2: %v", err)
	}

	if *fuzzCount != 0 {
		doFuzz(gdb1, gdb2, *fuzzCount)
	} else {
		doSimulrun(gdb1, gdb2)
	}
}

func doSimulrun(gdb1, gdb2 *GDBClient) {
	must(gdb1.Reset())
	must(gdb2.Reset())

	must(gdb1.AddBreakpoint(startAt))
	must(gdb2.AddBreakpoint(startAt))

	must(gdb1.Continue())
	must(gdb2.Continue())

	must(gdb1.RemoveBreakpoint(startAt))
	must(gdb2.RemoveBreakpoint(startAt))

	instCounter := 0

	go func() {
		lastCount := 0

		for range time.Tick(time.Second) {
			log.Printf("%d instructions per second, %d total", instCounter-lastCount, instCounter)
			lastCount = instCounter
		}
	}()

	for {
		instCounter++

		err := gdb1.Step()
		if err != nil {
			panic(err)
		}
		err = gdb2.Step()
		if err != nil {
			panic(err)
		}

		err = gdb1.ReadRegisters()
		if err != nil {
			panic(err)
		}
		err = gdb2.ReadRegisters()
		if err != nil {
			panic(err)
		}

		regs1 := gdb1.Registers()
		regs2 := gdb2.Registers()

		if checkRegisterMismatches(regs1, regs2) {
			break
		}
	}
}

func doFuzz(gdb1, gdb2 *GDBClient, count int) {
	r := rand.New(rand.NewSource(time.Now().UnixMicro()))

	ch := make(chan Instruction)
	generateInstructions(ch, 1)

	must(gdb1.Reset())
	must(gdb2.Reset())

	lastUpdate := time.Now()

	const updateInterval = 100

	for i := 0; count < 0 || i < count; i++ {
		if i != 0 && i%updateInterval == 0 {
			instPerSecond := float64(updateInterval) / (time.Now().Sub(lastUpdate).Seconds())
			lastUpdate = time.Now()

			log.Printf("%d instructions, %.0f per second", i, instPerSecond)
		}

		inst := <-ch

		must(gdb1.WriteMemory(0x2000_0000, inst.Data))
		must(gdb2.WriteMemory(0x2000_0000, inst.Data))

		must(gdb1.ReadRegisters())
		must(gdb2.ReadRegisters())

		// Seed registers with random values
		for i := 0; i < 12; i++ {
			val := r.Uint32()

			gdb1.Registers()[i] = val
			gdb2.Registers()[i] = val
		}

		gdb1.Registers()[asm.RegisterPC] = 0x2000_0000
		gdb2.Registers()[asm.RegisterPC] = 0x2000_0000

		must(gdb1.WriteRegisters())
		must(gdb2.WriteRegisters())

		must(gdb1.Step())
		must(gdb2.Step())

		must(gdb1.ReadRegisters())
		must(gdb2.ReadRegisters())

		regs1 := gdb1.Registers()
		regs2 := gdb2.Registers()

		if checkRegisterMismatches(regs1, regs2) {
			log.Printf("when running instruction %s (%s)", inst.Instruction, hex.EncodeToString(inst.Data))

			break
		}
	}
}
