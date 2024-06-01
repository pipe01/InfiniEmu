package main

import (
	"encoding/binary"
	"image"
	"image/color"
	"log"
	"os"
	"time"

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
	displayWidth         = 240
	displayHeight        = 240
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

func main() {
	program, err := os.ReadFile("../../infinitime.bin")
	if err != nil {
		log.Fatal(err)
	}

	pt := C.pinetime_new((*C.uchar)(&program[0]), C.ulong(len(program)), true)
	C.pinetime_reset(pt)

	go C.loop(pt)

	lcd := C.pinetime_get_st7789(pt)
	pins := C.nrf52832_get_pins(C.pinetime_get_nrf52832(pt))

	screen := make([]byte, displayWidth*displayHeight*displayBytesPerPixel)

	var texid imgui.TextureID

	context := imgui.CreateContext(nil)
	defer context.Destroy()

	io := imgui.CurrentIO()
	io.Fonts().AddFontDefault()

	p, err := imgui.NewGLFW(io, "InfiniEmu", 500, 500, imgui.GLFWWindowFlagsNotResizable)
	if err != nil {
		panic(err)
	}
	defer p.Dispose()

	r, err := imgui.NewOpenGL3(io, 1.0)
	if err != nil {
		panic(err)
	}
	defer r.Dispose()

	r.SetFontTexture(io.Fonts().TextureDataRGBA32())

	clearColor := [4]float32{0.7, 0.7, 0.7, 1.0}

	sideButton := false

	imgui.StyleColorsDark()

	t := time.Tick(time.Second / 60)

	for !p.ShouldStop() {
		<-t

		p.ProcessEvents()

		p.NewFrame()
		imgui.NewFrame()

		C.st7789_read_screen(lcd, (*C.uchar)(&screen[0]), displayWidth, displayHeight)
		img := convertImage(screen)

		r.ReleaseImage(texid)
		texid, err = r.LoadImage(img)
		if err != nil {
			log.Fatal(err)
		}

		imgui.Begin("Display")
		{
			imgui.Image(texid, imgui.Vec2{displayWidth, displayHeight})
		}
		imgui.End()

		imgui.Begin("Inputs")
		{
			if imgui.Checkbox("Side button pressed", &sideButton) {
				if sideButton {
					C.pins_set(pins, 13)
				} else {
					C.pins_clear(pins, 13)
				}
			}
		}
		imgui.End()

		imgui.Render() // This call only creates the draw data list. Actual rendering to framebuffer is done below.

		r.PreRender(clearColor)
		r.Render(p.DisplaySize(), p.FramebufferSize(), imgui.RenderedDrawData())
		p.PostRender()
	}
}
