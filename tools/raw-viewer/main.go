package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/AllenDang/imgui-go"
)

/*
#cgo CFLAGS: -I../../include
#cgo LDFLAGS: libinfiniemu.o -lcapstone

#include "gdb.h"
#include "pinetime.h"
#include "scheduler.h"

volatile unsigned long inst_counter = 0;
volatile bool stop_loop = false;

void loop(pinetime_t *pt)
{
	stop_loop = false;

	while (!stop_loop)
	{
		pinetime_step(pt);
		inst_counter++;
	}
}

scheduler_t *create_sched(pinetime_t *pt, size_t freq)
{
	return scheduler_new((scheduler_cb_t)pinetime_step, pt, freq);
}
*/
import "C"

const (
	displayWidth         = 240
	displayHeight        = 240
	displayBytesPerPixel = C.BYTES_PER_PIXEL
)

const (
	pinCharging           = 12
	pinCst816sReset       = 10
	pinButton             = 13
	pinButtonEnable       = 15
	pinCst816sIrq         = 28
	pinPowerPresent       = 19
	pinBma421Irq          = 8
	pinMotor              = 16
	pinLcdBacklightLow    = 14
	pinLcdBacklightMedium = 22
	pinLcdBacklightHigh   = 23
	pinSpiSck             = 2
	pinSpiMosi            = 3
	pinSpiMiso            = 4
	pinSpiFlashCsn        = 5
	pinSpiLcdCsn          = 25
	pinLcdDataCommand     = 18
	pinLcdReset           = 26
	pinTwiScl             = 7
	pinTwiSda             = 6
)

type Brightness int

const (
	BrightnessOff Brightness = iota
	BrightnessLow
	BrightnessMedium
	BrightnessHigh
)

func (b Brightness) String() string {
	switch b {
	case BrightnessOff:
		return "off"
	case BrightnessLow:
		return "low"
	case BrightnessMedium:
		return "medium"
	case BrightnessHigh:
		return "high"
	default:
		return "unknown"
	}
}

const baseFrequencyHZ = 18_000_000

const touchDuration = 200 * time.Millisecond

var blackScreenImage *image.RGBA

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

	TicksPerSecond       uint32
	TargetTicksPerSecond uint32
	Running              bool

	lastTicks uint32
} //

func NewRTCTracker(rtc *C.RTC_t) *RTCTracker {
	return &RTCTracker{
		rtc: rtc,
	}
}

func (r *RTCTracker) Update(updateInterval time.Duration) {
	r.Running = C.rtc_is_running(r.rtc) != 0
	if !r.Running {
		return
	}

	ticks := uint32(C.rtc_get_counter(r.rtc))

	interval := time.Duration(C.rtc_get_tick_interval_us(r.rtc)) * time.Microsecond
	if interval == 0 {
		return
	}

	r.TargetTicksPerSecond = 1e6 / uint32(interval.Microseconds())
	r.TicksPerSecond = (1e6 * (ticks - r.lastTicks)) / uint32(updateInterval.Microseconds())

	r.lastTicks = ticks
}

type CPUVariable struct {
	mem *C.memreg_t
	sym *Symbol
}

func NewCPUVariable(pt *C.pinetime_t, program *Program, name string) *CPUVariable {
	return &CPUVariable{
		mem: C.cpu_mem(C.nrf52832_get_cpu(C.pinetime_get_nrf52832(pt))),
		sym: program.FindSymbol(name),
	}
}

func (v *CPUVariable) Read() uint32 {
	if v.sym == nil {
		return 0
	}

	return uint32(C.memreg_read(v.mem, C.uint(v.sym.Start)))
}

func constCheckbox(id string, state bool) {
	imgui.Checkbox(id, &state)
}

func pinCheckbox(id string, pins *C.pins_t, pin int32) {
	state := bool(C.pins_is_set(pins, C.int(pin)))

	if imgui.Checkbox(id, &state) {
		if state {
			C.pins_set(pins, C.int(pin))
		} else {
			C.pins_clear(pins, C.int(pin))
		}
	}
}

func loadFlash(filePath string) (*Program, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var program *Program

	program, err = LoadELF(f, true)
	if err != nil {
		if strings.Contains(err.Error(), "bad magic number") {
			f.Seek(0, 0)

			program, err = LoadBinary(f)
			if err != nil {
				return nil, fmt.Errorf("load binary file: %w", err)
			}
		} else {
			return nil, fmt.Errorf("load elf file: %w", err)
		}
	}

	fmt.Printf("Loaded %d symbols\n", len(program.Symbols))

	return program, nil
}

func main() {
	var noScheduler bool

	runGDB := flag.Bool("gdb", false, "")
	flag.BoolVar(&noScheduler, "no-sched", false, "")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Usage: infiniemu [options] <firmware.bin>")
	}

	blackScreenImage = image.NewRGBA(image.Rect(0, 0, displayWidth, displayHeight))

	program, err := loadFlash(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	flash := program.Flatten()

	var pinner runtime.Pinner
	pinner.Pin(&program)

	pt := C.pinetime_new((*C.uchar)(&flash[0]), C.ulong(len(flash)), true)
	C.pinetime_reset(pt)

	pinner.Unpin()

	sched := C.create_sched(pt, baseFrequencyHZ)

	if *runGDB {
		gdb := C.gdb_new(pt, true)
		go C.gdb_start(gdb)
	} else if noScheduler {
		go C.loop(pt)
	} else {
		go C.scheduler_run(sched)
	}

	lcd := C.pinetime_get_st7789(pt)
	touchScreen := C.pinetime_get_cst816s(pt)
	pins := C.nrf52832_get_pins(C.pinetime_get_nrf52832(pt))
	rtcs := []*RTCTracker{
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC0))),
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC1))),
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC2))),
	}

	freertosFreeBytesRemaining := NewCPUVariable(pt, program, "xFreeBytesRemaining")

	// Active low pins with pull ups
	C.pins_set(pins, pinCharging)
	C.pins_set(pins, pinPowerPresent)

	var instPerSecond uint64
	go func() {
		interval := 500 * time.Millisecond

		var lastCounter uint64

		for range time.Tick(interval) {
			for _, rtc := range rtcs {
				rtc.Update(interval)
			}

			var instCounter uint64
			if noScheduler {
				instCounter = uint64(C.inst_counter)
			} else {
				instCounter = uint64(C.scheduler_get_counter(sched))
			}

			instPerSecond = (1e6 * (instCounter - lastCounter)) / uint64(interval.Microseconds())
			lastCounter = instCounter
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

	var releaseTouchTime time.Time

	mouseWasDown := false
	mouseIsDown := false
	brightness := BrightnessOff

	var speed float32 = 1

	for !p.ShouldStop() {
		<-t

		mouseIsDown = imgui.IsMouseDown(0)

		if !releaseTouchTime.IsZero() && time.Now().After(releaseTouchTime) {
			releaseTouchTime = time.Time{}
			C.cst816s_release_touch(touchScreen)
		}

		p.ProcessEvents()

		p.NewFrame()
		imgui.NewFrame()

		lcdLow := bool(C.pins_is_set(pins, pinLcdBacklightLow))
		lcdMedium := bool(C.pins_is_set(pins, pinLcdBacklightMedium))
		lcdHigh := bool(C.pins_is_set(pins, pinLcdBacklightHigh))

		if !lcdLow && lcdMedium && lcdHigh {
			brightness = BrightnessLow
		} else if !lcdLow && !lcdMedium && lcdHigh {
			brightness = BrightnessMedium
		} else if !lcdLow && !lcdMedium && !lcdHigh {
			brightness = BrightnessHigh
		} else {
			brightness = BrightnessOff
		}

		if imgui.BeginV("Display", nil, imgui.WindowFlagsNoResize|imgui.WindowFlagsAlwaysAutoResize) {
			r.ReleaseImage(texid)
			var img *image.RGBA

			if C.st7789_is_sleeping(lcd) || brightness == BrightnessOff {
				img = blackScreenImage
			} else {
				C.st7789_read_screen(lcd, (*C.uchar)(&screen[0]), displayWidth, displayHeight)
				img = convertImage(screen)
			}

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

			imgui.Separator()

			imgui.Text(fmt.Sprintf("Brightness: %s", brightness.String()))
		}
		imgui.End()

		if imgui.Begin("Inputs") {
			imgui.Button("Side button")
			if imgui.IsItemHovered() {
				if mouseIsDown && !mouseWasDown {
					C.pins_set(pins, pinButton)
				} else if !mouseIsDown && mouseWasDown {
					C.pins_clear(pins, pinButton)
				}
			}

			imgui.Separator()

			imgui.BeginTable("Slide", 3, 0, imgui.Vec2{}, 0)
			{
				imgui.BeginDisabled(!releaseTouchTime.IsZero())
				{
					imgui.TableNextRow(0, 0)
					imgui.TableSetColumnIndex(1)
					if imgui.Button("Slide up") {
						C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDEUP, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}

					imgui.TableNextRow(0, 0)
					imgui.TableSetColumnIndex(0)
					if imgui.Button("Slide left") {
						C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDELEFT, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}
					imgui.TableSetColumnIndex(2)
					if imgui.Button("Slide right") {
						C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDERIGHT, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}

					imgui.TableNextRow(0, 0)
					imgui.TableSetColumnIndex(1)
					if imgui.Button("Slide down") {
						C.cst816s_do_touch(touchScreen, C.GESTURE_SLIDEDOWN, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}
				}
				imgui.EndDisabled()
			}
			imgui.EndTable()

			imgui.Separator()

			pinCheckbox("Charging (active low)", pins, pinCharging)
			pinCheckbox("Power present (active low)", pins, pinPowerPresent)
		}
		imgui.End()

		if imgui.BeginV("Performance", nil, imgui.WindowFlagsAlwaysAutoResize) {
			for i, rtc := range rtcs {
				status := "off"
				if rtc.Running {
					status = "running"
				}

				imgui.Text(fmt.Sprintf("RTC%d (%s)", i, status))
				imgui.Text(fmt.Sprintf("Ticks per second: %d", rtc.TicksPerSecond))
				imgui.Text(fmt.Sprintf("Target ticks per second: %d", rtc.TargetTicksPerSecond))

				imgui.Separator()
			}

			imgui.Text(fmt.Sprintf("Instructions per second: %d", instPerSecond))

			imgui.BeginDisabled(*runGDB)
			{
				if imgui.Checkbox("Disable scheduler", &noScheduler) {
					if noScheduler {
						C.scheduler_stop(sched)

						//TODO: Wait for scheduler to stop
						time.Sleep(100 * time.Millisecond)

						go C.loop(pt)
					} else {
						C.stop_loop = true

						//TODO: Wait for loop to stop
						time.Sleep(100 * time.Millisecond)

						go C.scheduler_run(sched)
					}
				}

				imgui.BeginDisabled(noScheduler)
				{
					if imgui.SliderFloat("Speed", &speed, 0, 2) {
						C.scheduler_set_frequency(sched, C.ulong(speed*baseFrequencyHZ))
					}
				}
				imgui.EndDisabled()
			}
			imgui.EndDisabled()
		}
		imgui.End()

		if imgui.Begin("FreeRTOS") {
			imgui.Text(fmt.Sprintf("Free heap bytes: %d", freertosFreeBytesRemaining.Read()))
		}
		imgui.End()

		imgui.Render() // This call only creates the draw data list. Actual rendering to framebuffer is done below.

		r.PreRender(clearColor)
		r.Render(p.DisplaySize(), p.FramebufferSize(), imgui.RenderedDrawData())
		p.PostRender()

		mouseWasDown = mouseIsDown
	}
}
