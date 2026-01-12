package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/pipe01/InfiniEmu/frontend/desktop/emulator"
	"github.com/pipe01/InfiniEmu/frontend/desktop/gui"
)

func main() {
	runGDB := flag.Bool("gdb", false, "")
	analyzeHeap := flag.Bool("heap", false, "")
	emitRunlog := flag.Bool("runlog", false, "")
	noScheduler := flag.Bool("no-sched", false, "")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Usage: infiniemu [options] <firmware.bin>")
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	program, err := emulator.LoadProgram(f)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Loaded %d symbols and %d functions\n", len(program.Symbols), len(program.Functions))

	e := emulator.NewEmulator(program, true)

	if f, err := os.OpenFile("spiflash.bin", os.O_RDWR, 0); err == nil {
		go func() {
			defer f.Close()

			t := time.Tick(1 * time.Second)

			for {
				f.Seek(0, io.SeekStart)

				data, _ := io.ReadAll(f)
				e.SetSPIFlash(data)

				<-t
			}
		}()
	}

	if *emitRunlog {
		e.RecordRunlog("runlog.bin")
		defer e.CloseRunlog()
	}

	if *analyzeHeap {
		e.EnableHeapTracker()
	}

	err = gui.RunGUI(e, *analyzeHeap, *runGDB, *noScheduler)
	if err != nil {
		log.Fatal(err)
	}
}
