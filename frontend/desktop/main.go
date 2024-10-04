package main

import (
	"flag"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"log"
	"os"
	"strings"

	"github.com/pipe01/InfiniEmu/frontend/desktop/emulator"
	"github.com/pipe01/InfiniEmu/frontend/desktop/gui"
	"github.com/pipe01/InfiniEmu/frontend/desktop/script"
)

func loadFlash(filePath string) (*emulator.Program, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var program *emulator.Program

	program, err = emulator.LoadELF(f, true)
	if err != nil {
		if strings.Contains(err.Error(), "bad magic number") {
			f.Seek(0, 0)

			program, err = emulator.LoadBinary(f)
			if err != nil {
				return nil, fmt.Errorf("load binary file: %w", err)
			}
		} else {
			return nil, fmt.Errorf("load elf file: %w", err)
		}
	}

	fmt.Printf("Loaded %d symbols and %d functions\n", len(program.Symbols), len(program.Functions))

	return program, nil
}

func main() {
	runGDB := flag.Bool("gdb", false, "")
	analyzeHeap := flag.Bool("heap", false, "")
	emitRunlog := flag.Bool("runlog", false, "")
	noScheduler := flag.Bool("no-sched", false, "")
	scriptPath := flag.String("script", "", "")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Usage: infiniemu [options] <firmware.bin>")
	}

	program, err := loadFlash(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	var extflashInit []byte
	if v, err := os.ReadFile("spiflash.bin"); err == nil {
		extflashInit = v
	}

	e := emulator.NewEmulator(program, extflashInit, true)

	if *emitRunlog {
		e.RecordRunlog("runlog.bin")
		defer e.CloseRunlog()
	}

	if *analyzeHeap {
		e.EnableHeapTracker()
	}

	if *scriptPath != "" {
		scriptBytes, err := os.ReadFile(*scriptPath)
		if err != nil {
			log.Fatal(err)
		}

		screenshots, err := script.Execute(e, scriptBytes)
		if err != nil {
			log.Fatal(err)
		}

		if len(screenshots) > 0 {
			combined := combineImages(screenshots)

			f, err := os.Create("screenshot.png")
			if err != nil {
				log.Fatal(err)
			}

			err = png.Encode(f, combined)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else {
		err = gui.RunGUI(e, *analyzeHeap, *runGDB, *noScheduler)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func combineImages(images []image.Image) image.Image {
	const separation = 5

	width := 0
	height := 0

	for i, img := range images {
		if img.Bounds().Dy() > height {
			height = img.Bounds().Dy()
		}

		width += img.Bounds().Dx()

		if i > 0 {
			width += separation
		}
	}

	dst := image.NewRGBA(image.Rect(0, 0, width, height))

	x := 0
	for _, img := range images {
		rect := img.Bounds()

		draw.Draw(dst, image.Rect(x, 0, x+rect.Dx(), rect.Dy()), img, image.Point{0, 0}, draw.Src)

		x += rect.Dx() + separation
	}

	return dst
}
