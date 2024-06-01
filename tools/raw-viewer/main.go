package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"time"

	"github.com/AllenDang/imgui-go"
)

/*
#cgo CFLAGS: -I../../include
#cgo LDFLAGS: -L. -linfiniemu

#include "gdb.h"
#include "pinetime.h"

volatile unsigned long inst_counter = 0;

void loop(pinetime_t *pt)
{
	for (;;)
	{
		pinetime_step(pt);
		inst_counter++;
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

type RTCTracker struct {
	rtc *C.RTC_t

	ticksPerSecond       uint32
	targetTicksPerSecond uint32

	lastTicks     uint32
	lastCheckTime time.Time
}

func NewRTCTracker(rtc *C.RTC_t) *RTCTracker {
	return &RTCTracker{
		rtc: rtc,
	}
}

func (r *RTCTracker) Update() {
	ticks := uint32(C.rtc_get_counter(r.rtc))

	interval := time.Duration(C.rtc_get_tick_interval_us(r.rtc)) * time.Microsecond
	if interval == 0 {
		return
	}

	r.targetTicksPerSecond = 1e6 / uint32(interval.Microseconds())

	now := time.Now()
	elapsed := now.Sub(r.lastCheckTime)

	r.ticksPerSecond = (1e6 * (ticks - r.lastTicks)) / uint32(elapsed.Microseconds())

	r.lastTicks = ticks
	r.lastCheckTime = now
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
	rtcs := []*RTCTracker{
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC0))),
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC1))),
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC2))),
	}

	var instPerSecond uint64
	go func() {
		for range time.Tick(time.Second) {
			for _, rtc := range rtcs {
				rtc.Update()
			}

			instPerSecond = uint64(C.inst_counter)
			C.inst_counter = 0
		}
	}()

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

	mouseWasDown := false
	mouseIsDown := false

	for !p.ShouldStop() {
		<-t

		mouseIsDown = imgui.IsMouseDown(0)

		if doAction != nil && time.Now().After(doActionTime) {
			doAction()
			doAction = nil
		}

		p.ProcessEvents()

		p.NewFrame()
		imgui.NewFrame()

		imgui.BeginV("Display", nil, imgui.WindowFlagsNoResize)
		{
			if C.st7789_is_sleeping(lcd) {
				imgui.Text("Display is off")
			} else {
				C.st7789_read_screen(lcd, (*C.uchar)(&screen[0]), displayWidth, displayHeight)
				img := convertImage(screen)

				r.ReleaseImage(texid)
				texid, err = r.LoadImage(img)
				if err != nil {
					log.Fatal(err)
				}

				imgui.Image(texid, imgui.Vec2{X: displayWidth, Y: displayHeight})

				if imgui.IsItemHovered() {
					if mouseIsDown && !mouseWasDown {
						pos := imgui.MousePos().Minus(imgui.GetItemRectMin())

						C.cst816s_do_touch(touchScreen, C.GESTURE_SINGLETAP, C.ushort(pos.X), C.ushort(pos.Y))
					} else if !mouseIsDown && mouseWasDown {
						C.cst816s_release_touch(touchScreen)
					}
				}
			}
		}
		imgui.End()

		imgui.Begin("Inputs")
		{
			imgui.Button("Side button")
			if imgui.IsItemHovered() {
				if mouseIsDown && !mouseWasDown {
					C.pins_set(pins, 13)
				} else if !mouseIsDown && mouseWasDown {
					C.pins_clear(pins, 13)
				}
			}

			imgui.Separator()

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

		imgui.BeginV("Performance", nil, imgui.WindowFlagsAlwaysAutoResize)
		{
			for i, rtc := range rtcs {
				imgui.Text(fmt.Sprintf("RTC%d", i))
				imgui.Text(fmt.Sprintf("Ticks per second: %d", rtc.ticksPerSecond))
				imgui.Text(fmt.Sprintf("Target ticks per second: %d", rtc.targetTicksPerSecond))

				imgui.Separator()
			}

			imgui.Text(fmt.Sprintf("Instructions per second: %d", instPerSecond))
		}
		imgui.End()

		imgui.Render() // This call only creates the draw data list. Actual rendering to framebuffer is done below.

		r.PreRender(clearColor)
		r.Render(p.DisplaySize(), p.FramebufferSize(), imgui.RenderedDrawData())
		p.PostRender()

		mouseWasDown = mouseIsDown
	}
}
