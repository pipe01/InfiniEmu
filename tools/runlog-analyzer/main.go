package main

import (
	"flag"
	"log"
	"os"
)

var regs [RUNLOG_REG_MAX + 1]uint32
var pc uint32

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatalf("usage: %s <runlog path>", os.Args[0])
	}

	runlogPath := flag.Arg(0)

	f, err := os.Open(runlogPath)
	if err != nil {
		log.Fatalf("failed to open runlog: %v", err)
	}
	defer f.Close()

	frames, err := ReadFrames(f)
	if err != nil {
		log.Fatalf("failed to read frames: %v", err)
	}

	for i, frame := range frames {
		log.Printf("Frame %d:", i)
		log.Printf("  PC: 0x%08X", frame.NextInstruction.Address)
		log.Printf("  Mnemonic: %s", frame.NextInstruction.Mnemonic)
		log.Printf("  Registers:")
		for reg, val := range frame.Registers {
			log.Printf("    reg[%d] = 0x%08X", reg, val)
		}
	}
}
