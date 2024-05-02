package main

import (
	"log"
	"time"
)

func main() {
	gdb1, err := DialGDB("localhost:3333")
	if err != nil {
		log.Fatalf("failed to dial gdb: %v", err)
	}
	gdb2, err := DialGDB("localhost:3334")
	if err != nil {
		log.Fatalf("failed to dial gdb: %v", err)
	}

	gdb1.Reset()
	gdb2.Reset()

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
		// println(string(r))

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

		if regs1 != regs2 {
			log.Printf("registers aren't equal at PC=0x%08X", regs1[15])

			for i := 0; i < RegisterCount; i++ {
				marker := ""
				if regs1[i] != regs2[i] {
					marker = "!!"
				}

				log.Printf("  R%d: 0x%08X 0x%08X %s", i, regs1[i], regs2[i], marker)
			}

			return
		}

		// fmt.Printf("PC: 0x%x\n", gdb1.Registers()[15])
	}
}
