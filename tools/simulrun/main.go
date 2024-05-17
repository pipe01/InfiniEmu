package main

import (
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
				inst := gen(asm.RandASM{r})
				inst = "adds r0, r1, r2"

				b, err := asm.Assemble(".syntax unified\n"+inst+"\n", asm.ToolPaths{
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

func main() {
	gdb1, err := DialGDB("localhost:3333")
	if err != nil {
		log.Fatalf("failed to dial gdb1: %v", err)
	}
	gdb2, err := DialGDB("localhost:3335")
	if err != nil {
		log.Fatalf("failed to dial gdb2: %v", err)
	}

	doFuzz(gdb1, gdb2)
	// doSimulrun(gdb1, gdb2)
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

		mismatch := false
		mismatched := map[int]struct{}{}

		for i := 0; i < RegisterCount; i++ {
			a := regs1[i]
			b := regs2[i]

			if i == 16 { // xPSR, ignore IT/ICI bits
				a &^= 0x600FC00
				b &^= 0x600FC00
			}

			if a != b {
				mismatch = true
				mismatched[i] = struct{}{}
			}
		}

		if mismatch {
			log.Printf("registers mismatch")

			for i := 0; i < RegisterCount; i++ {
				marker := ""
				if _, ok := mismatched[i]; ok {
					marker = " !!"
				}

				log.Printf("  %s: 0x%08X 0x%08X%s", RegisterNames[i], regs1[i], regs2[i], marker)
			}

			break
		}
	}
}

func doFuzz(gdb1, gdb2 *GDBClient) {
	r := rand.New(rand.NewSource(1))

	ch := make(chan Instruction)
	generateInstructions(ch, 1)

	must(gdb1.Reset())
	must(gdb2.Reset())

	for inst := range ch {
		println(inst.Mnemonic)

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

			for i := 0; i < RegisterCount; i++ {
				marker := ""
				if _, ok := mismatched[i]; ok {
					marker = " !!"
				}

				log.Printf("  %s: 0x%08X 0x%08X%s", RegisterNames[i], regs1[i], regs2[i], marker)
			}

			return
		}
	}
}
