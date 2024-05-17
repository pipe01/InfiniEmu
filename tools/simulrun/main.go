package main

import (
	"flag"
	"log"
	"math/rand"
	"simulrun/asm"
	"time"
)

// const startAt = 0x4d70 // <main>
const startAt = 0x572e // <vPortSetupTimerInterrupt>

type Instruction struct {
	Mnemonic string
	Data     []byte
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func generateInstructions(ch chan<- Instruction, workers int) {
	for i := 0; i < workers; i++ {
		r := rand.New(rand.NewSource(time.Now().UnixMicro() + int64(i)))

		go func() {
			for {
				gen := asm.Instructions[r.Intn(len(asm.Instructions))]
				inst := gen(asm.RandASM{Rand: r})

				b, err := asm.Assemble(inst, asm.ToolPaths{
					As:      "toolchain/bin/arm-none-eabi-as",
					Objcopy: "toolchain/bin/arm-none-eabi-objcopy",
				})
				if err != nil {
					log.Fatal(err)
				}

				ch <- Instruction{
					Mnemonic: inst,
					Data:     b,
				}
			}
		}()
	}
}

func printRegisters(regs1, regs2 *[RegisterCount]uint32, mismatched map[int]struct{}) {
	for i := 0; i < RegisterCount; i++ {
		marker := ""
		if _, ok := mismatched[i]; ok {
			marker = " !!"
		}

		log.Printf("  %s: 0x%08X 0x%08X%s", RegisterNames[i], regs1[i], regs2[i], marker)
	}
}

func checkRegisterMismatches(regs1, regs2 *[RegisterCount]uint32) bool {
	mismatch := false
	mismatched := map[int]struct{}{}

	for i := 0; i < RegisterCount; i++ {
		if regs1[i] != regs2[i] {
			mismatch = true
			mismatched[i] = struct{}{}
		}
	}

	if mismatch {
		log.Printf("registers mismatch")
		printRegisters(regs1, regs2, mismatched)

		return true
	}

	return false
}

func main() {
	fuzzCount := flag.Int("fuzz", 0, "run fuzzer for this amount of instructions, -1 to run indefinitely")
	flag.Parse()

	gdb1, err := DialGDB("localhost:3333")
	if err != nil {
		log.Fatalf("failed to dial gdb1: %v", err)
	}
	gdb2, err := DialGDB("localhost:3334")
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
	generateInstructions(ch, 4)

	must(gdb1.Reset())
	must(gdb2.Reset())

	for i := 0; count < 0 || i < count; i++ {
		if i%100 == 0 {
			log.Printf("%d instructions", i)
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

		gdb1.Registers()[15] = 0x2000_0000
		gdb2.Registers()[15] = 0x2000_0000

		must(gdb1.WriteRegisters())
		must(gdb2.WriteRegisters())

		must(gdb1.Step())
		must(gdb2.Step())

		must(gdb1.ReadRegisters())
		must(gdb2.ReadRegisters())

		regs1 := gdb1.Registers()
		regs2 := gdb2.Registers()

		if checkRegisterMismatches(regs1, regs2) {
			log.Printf("when running instruction %s", inst.Mnemonic)

			break
		}
	}
}
