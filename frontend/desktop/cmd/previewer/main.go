package main

import (
	"flag"
	"image"
	"image/draw"
	"image/png"
	"log"
	"os"

	"github.com/pipe01/InfiniEmu/frontend/desktop/emulator"
	"github.com/pipe01/InfiniEmu/frontend/desktop/script"
)

func main() {
	screenshotPath := flag.String("screenshot", "screenshot.png", "Path to save screenshot")
	flag.Parse()

	if flag.NArg() != 2 {
		log.Fatal("Usage: previewer [options] <firmware.bin> <script.txt>")
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

	scriptBytes, err := os.ReadFile(flag.Arg(1))
	if err != nil {
		log.Fatal(err)
	}

	e := emulator.NewEmulator(program, nil, true)

	screenshots, err := script.Execute(e, scriptBytes)
	if err != nil {
		log.Fatal(err)
	}

	if len(screenshots) > 0 {
		combined := combineImages(screenshots)

		f, err := os.Create(*screenshotPath)
		if err != nil {
			log.Fatal(err)
		}

		err = png.Encode(f, combined)
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
