package main

import (
	"log"
	"time"
)

// const startAt = 0x4d70 // <main>
const startAt = 0x572e // <vPortSetupTimerInterrupt>

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	gdb1, err := DialGDB("localhost:3333")
	if err != nil {
		log.Fatalf("failed to dial gdb1: %v", err)
	}
	gdb2, err := DialGDB("localhost:3334")
	if err != nil {
		log.Fatalf("failed to dial gdb2: %v", err)
	}

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

		err = gdb1.Step()
		if err != nil {
			panic(err)
		}
		err = gdb2.Step()
		if err != nil {
			panic(err)
		}

		err = gdb1.UpdateRegisters()
		if err != nil {
			panic(err)
		}
		err = gdb2.UpdateRegisters()
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
