package main

import (
	"encoding/binary"
	"flag"
	"image"
	"image/color"
	"log"
	"os"
	"time"

	"github.com/AllenDang/imgui-go"
)

// #include "gdb.h"
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
	runGDB := flag.Bool("gdb", false, "")
	flag.Parse()

	program, err := os.ReadFile("../../infinitime.bin")
	if err != nil {
		log.Fatal(err)
	}

	pt := C.pinetime_new((*C.uchar)(&program[0]), C.ulong(len(program)), true)
	C.pinetime_reset(pt)

	if *runGDB {
		gdb := C.gdb_new(pt, true)
		go C.gdb_start(gdb)
	} else {
		go C.loop(pt)
	}

	lcd := C.pinetime_get_st7789(pt)
	touchScreen := C.pinetime_get_cst816s(pt)
	pins := C.nrf52832_get_pins(C.pinetime_get_nrf52832(pt))

	screen := make([]byte, displayWidth*displayHeight*displayBytesPerPixel)

	var texid imgui.TextureID

	context := imgui.CreateContext(nil)
	defer context.Destroy()

	io := imgui.CurrentIO()
	io.Fonts().AddFontDefault()

	p, err := imgui.NewGLFW(io, "InfiniEmu", 600, 600, 0)
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

	imgui.StyleColorsDark()

	t := time.Tick(time.Second / 60)

	var doAction func()
	var doActionTime time.Time

	sideButtonDown := false

	for !p.ShouldStop() {
		<-t

		if doAction != nil && time.Now().After(doActionTime) {
			doAction()
			doAction = nil
		}

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

		imgui.BeginV("Display", nil, imgui.WindowFlagsNoResize)
		{
			imgui.Image(texid, imgui.Vec2{X: displayWidth, Y: displayHeight})

			if imgui.IsItemHovered() && imgui.IsMouseClicked(0) {
				pos := imgui.MousePos().Minus(imgui.GetItemRectMin())

				C.cst816s_do_touch(touchScreen, C.GESTURE_SINGLETAP, C.ushort(pos.X), C.ushort(pos.Y))
				doAction = func() { C.cst816s_release_touch(touchScreen) }
				doActionTime = time.Now().Add(200 * time.Millisecond)
			}
		}
		imgui.End()

		imgui.Begin("Inputs")
		{
			imgui.Button("Side button")
			if imgui.IsItemHovered() {
				if imgui.IsMouseDown(0) && !sideButtonDown {
					sideButtonDown = true
					C.pins_set(pins, 13)
				} else if !imgui.IsMouseDown(0) && sideButtonDown {
					sideButtonDown = false
					C.pins_clear(pins, 13)
				}
			}

			imgui.BeginTable("Slide", 3, 0, imgui.Vec2{}, 0)
			{
				imgui.TableNextRow(0, 0)
				imgui.TableSetColumnIndex(1)
				if imgui.Button("Slide up") {
					C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDEUP, displayWidth/2, displayHeight/2)
					doAction = func() { C.cst816s_release_touch(touchScreen) }
					doActionTime = time.Now().Add(200 * time.Millisecond)
				}

				imgui.TableNextRow(0, 0)
				imgui.TableSetColumnIndex(0)
				if imgui.Button("Slide left") {
					C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDELEFT, displayWidth/2, displayHeight/2)
					doAction = func() { C.cst816s_release_touch(touchScreen) }
					doActionTime = time.Now().Add(200 * time.Millisecond)
				}
				imgui.TableSetColumnIndex(2)
				if imgui.Button("Slide right") {
					C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDERIGHT, displayWidth/2, displayHeight/2)
					doAction = func() { C.cst816s_release_touch(touchScreen) }
					doActionTime = time.Now().Add(200 * time.Millisecond)
				}

				imgui.TableNextRow(0, 0)
				imgui.TableSetColumnIndex(1)
				if imgui.Button("Slide down") {
					C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDEDOWN, displayWidth/2, displayHeight/2)
					doAction = func() { C.cst816s_release_touch(touchScreen) }
					doActionTime = time.Now().Add(200 * time.Millisecond)
				}
			}
			imgui.EndTable()
		}
		imgui.End()

		imgui.Render() // This call only creates the draw data list. Actual rendering to framebuffer is done below.

		r.PreRender(clearColor)
		r.Render(p.DisplaySize(), p.FramebufferSize(), imgui.RenderedDrawData())
		p.PostRender()
	}
}
