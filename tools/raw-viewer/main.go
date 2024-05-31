package main

import (
	"encoding/binary"
	"flag"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"strings"
	"time"

	g "github.com/AllenDang/giu"
	"github.com/AllenDang/imgui-go"
)

// #include "pinetime.h"
// #cgo CFLAGS: -I../../include
// #cgo LDFLAGS: -L. -linfiniemu
/*
void loop(pinetime_t *pt)
{
	for (;;)
	{
		pinetime_step(pt);
	}
}
*/
import "C"

const (
	displayWidth         = C.DISPLAY_WIDTH
	displayHeight        = C.DISPLAY_HEIGHT
	displayBytesPerPixel = C.BYTES_PER_PIXEL
)

func convertImage(raw []byte) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, displayWidth, displayHeight))

	for x := 0; x < displayWidth; x++ {
		for y := 0; y < displayHeight; y++ {
			pixelIndex := (y*displayWidth + x) * 2
			pixel16 := binary.BigEndian.Uint16(raw[pixelIndex:])

			r := (pixel16 >> 11) & 0x1f
			g := (pixel16 >> 5) & 0x3f
			b := pixel16 & 0x1f

			img.Set(x, y, color.RGBA{uint8((r*527 + 23) >> 6), uint8((g*259 + 33) >> 6), uint8((b*527 + 23) >> 6), 0xff})
		}
	}

	return img
}

var lastImage image.Image

func convert(inPath, outPath string) {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		log.Fatal(err)
	}

	img := convertImage(raw)

	if strings.HasSuffix(inPath, "_60.raw") {
		lastImage = img
	}

	f, err := os.Create(outPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := png.Encode(f, img); err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()

	program, err := os.ReadFile("../../infinitime.bin")
	if err != nil {
		log.Fatal(err)
	}

	pt := C.pinetime_new((*C.uchar)(&program[0]), C.ulong(len(program)), true)
	C.pinetime_reset(pt)

	go C.loop(pt)

	lcd := C.pinetime_get_st7789(pt)

	screen := make([]byte, displayWidth*displayHeight*displayBytesPerPixel)

	var texid imgui.TextureID

	go func() {
		time.Sleep(200 * time.Millisecond) // TODO: Find a better way to wait for the window to be created

		for range time.Tick(20 * time.Millisecond) {
			g.Update()
		}
	}()

	wnd := g.NewMasterWindow("InfiniEmu", 500, 500, g.MasterWindowFlagsNotResizable)
	wnd.Run(func() {
		C.st7789_read_screen(lcd, (*C.uchar)(&screen[0]))

		img := convertImage(screen)

		g.Context.GetRenderer().ReleaseImage(texid)
		texid, err = g.Context.GetRenderer().LoadImage(img)
		if err != nil {
			log.Fatal(err)
		}

		tex := g.ToTexture(texid)

		g.Window("Screen").
			Flags(g.WindowFlagsNoResize).
			Layout(
				g.Image(tex).Size(displayWidth, displayHeight),
			)

		g.Window("Inputs").Layout(
			g.Button("Side button").OnClick(func() {
				C.pins_set(C.nrf52832_get_pins(C.pinetime_get_nrf52832(pt)), 13)
				time.Sleep(200 * time.Millisecond)
				C.pins_clear(C.nrf52832_get_pins(C.pinetime_get_nrf52832(pt)), 13)
			}),
		)
	})
}
