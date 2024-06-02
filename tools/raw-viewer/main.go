package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
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

func (v *CPUVariable) Read() uint64 {
	if v.sym == nil {
		return 0
	}

	switch v.sym.Length {
	case 1:
		return uint64(C.memreg_read_byte(v.mem, C.uint(v.sym.Start)))
	case 2:
		return uint64(C.memreg_read_halfword(v.mem, C.uint(v.sym.Start)))
	case 4:
		return uint64(C.memreg_read(v.mem, C.uint(v.sym.Start)))
	case 8:
		return uint64(C.memreg_read(v.mem, C.uint(v.sym.Start))) | (uint64(C.memreg_read(v.mem, C.uint(v.sym.Start+4))) << 32)
	default:
		panic("unsupported length")
	}
}

func (v *CPUVariable) Write(value uint64) {
	if v.sym == nil {
		return
	}

	switch v.sym.Length {
	case 1, 2, 4:
		C.memreg_write(v.mem, C.uint(v.sym.Start), C.uint(value), C.byte_size_t(v.sym.Length))
	case 8:
		C.memreg_write(v.mem, C.uint(v.sym.Start), C.uint(value), C.SIZE_WORD)
		C.memreg_write(v.mem, C.uint(v.sym.Start+4), C.uint(value>>32), C.SIZE_WORD)
	}
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

var platform *imgui.GLFW
var renderer *imgui.OpenGL3

var lcd *C.st7789_t
var touchScreen *C.cst816s_t
var pins *C.pins_t

var allowScreenSwipes = true
var screenTextureID imgui.TextureID
var screenMouseDownPos imgui.Vec2
var screenDidSwipe bool

var mouseLeftIsDown, mouseLeftWasDown bool
var mouseRightIsDown, mouseRightWasDown bool

func screenWindow(screenBuffer []byte, brightness Brightness) {
	var err error

	flags := imgui.WindowFlagsNoResize | imgui.WindowFlagsAlwaysAutoResize
	if allowScreenSwipes {
		flags |= imgui.WindowFlagsNoMove
	}

	imgui.SetNextWindowPosV(imgui.Vec2{X: 20, Y: 20}, imgui.ConditionOnce, imgui.Vec2{})
	if imgui.BeginV("Display", nil, flags) {
		renderer.ReleaseImage(screenTextureID)
		var img *image.RGBA

		if C.st7789_is_sleeping(lcd) || brightness == BrightnessOff {
			img = blackScreenImage
		} else {
			C.st7789_read_screen(lcd, (*C.uchar)(&screenBuffer[0]), displayWidth, displayHeight)
			img = convertImage(screenBuffer)
		}

		screenTextureID, err = renderer.LoadImage(img)
		if err != nil {
			log.Fatal(err)
		}

		imgui.Image(screenTextureID, imgui.Vec2{X: displayWidth, Y: displayHeight})

		if imgui.IsItemHovered() {
			if mouseLeftIsDown && !mouseLeftWasDown {
				screenMouseDownPos = imgui.MousePos().Minus(imgui.GetItemRectMin())
				screenDidSwipe = false

				if !allowScreenSwipes {
					C.cst816s_do_touch(touchScreen, C.GESTURE_SINGLETAP, C.ushort(screenMouseDownPos.X), C.ushort(screenMouseDownPos.Y))
				}
			} else if mouseLeftIsDown && mouseLeftWasDown && !screenDidSwipe && allowScreenSwipes {
				pos := imgui.MousePos().Minus(imgui.GetItemRectMin())
				distVec := pos.Minus(screenMouseDownPos)
				dist := math.Sqrt(float64(distVec.X*distVec.X) + float64(distVec.Y*distVec.Y))

				if dist > 20 {
					screenDidSwipe = true

					var gesture C.touch_gesture_t

					xDist := math.Abs(float64(distVec.X))
					yDist := math.Abs(float64(distVec.Y))

					if xDist > yDist {
						if distVec.X > 0 {
							gesture = C.GESTURE_SLIDERIGHT
						} else {
							gesture = C.GESTURE_SLIDELEFT
						}
					} else {
						if distVec.Y > 0 {
							gesture = C.GESTURE_SLIDEDOWN
						} else {
							gesture = C.GESTURE_SLIDEUP
						}
					}

					C.cst816s_do_touch(touchScreen, gesture, C.ushort(pos.X), C.ushort(pos.Y))
				}
			} else if !mouseLeftIsDown && mouseLeftWasDown {
				if allowScreenSwipes && !screenDidSwipe {
					C.cst816s_do_touch(touchScreen, C.GESTURE_SINGLETAP, C.ushort(screenMouseDownPos.X), C.ushort(screenMouseDownPos.Y))
					time.Sleep(50 * time.Millisecond) // TODO: Do this better?
				}

				C.cst816s_release_touch(touchScreen)
			}

			if mouseRightIsDown && !mouseRightWasDown {
				C.pins_set(pins, pinButton)
			} else if !mouseRightIsDown && mouseRightWasDown {
				C.pins_clear(pins, pinButton)
			}
		}

		imgui.Checkbox("Allow swiping with mouse", &allowScreenSwipes)

		imgui.Separator()

		imgui.Text(fmt.Sprintf("Brightness: %s", brightness.String()))
	}
	imgui.End()
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

	lcd = C.pinetime_get_st7789(pt)
	touchScreen = C.pinetime_get_cst816s(pt)
	pins = C.nrf52832_get_pins(C.pinetime_get_nrf52832(pt))
	rtcs := []*RTCTracker{
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC0))),
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC1))),
		NewRTCTracker((*C.RTC_t)(C.nrf52832_get_peripheral(C.pinetime_get_nrf52832(pt), C.INSTANCE_RTC2))),
	}

	freertosFreeBytesRemaining := NewCPUVariable(pt, program, "xFreeBytesRemaining")

	NewCPUVariable(pt, program, "NoInit_MagicWord").Write(0xDEAD0000)
	NewCPUVariable(pt, program, "NoInit_BackUpTime").Write(uint64(time.Now().UnixNano()))

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

	screenBuffer := make([]byte, displayWidth*displayHeight*displayBytesPerPixel)

	context := imgui.CreateContext(nil)
	defer context.Destroy()

	imgui.ImPlotCreateContext()
	defer imgui.ImPlotDestroyContext()

	io := imgui.CurrentIO()
	io.Fonts().AddFontDefault()

	platform, err = imgui.NewGLFW(io, "InfiniEmu", 600, 750, 0)
	if err != nil {
		panic(err)
	}
	defer platform.Dispose()

	renderer, err = imgui.NewOpenGL3(io, 1.0)
	if err != nil {
		panic(err)
	}
	defer renderer.Dispose()

	renderer.SetFontTexture(io.Fonts().TextureDataRGBA32())

	clearColor := [4]float32{0.7, 0.7, 0.7, 1.0}

	imgui.StyleColorsDark()

	t := time.Tick(time.Second / 60)

	var releaseTouchTime time.Time

	brightness := BrightnessOff

	var speed float32 = 1

	freeHeapHistory := make([]float64, 0)

	for !platform.ShouldStop() {
		<-t

		mouseLeftIsDown = imgui.IsMouseDown(0)
		mouseRightIsDown = imgui.IsMouseDown(1)

		if !releaseTouchTime.IsZero() && time.Now().After(releaseTouchTime) {
			releaseTouchTime = time.Time{}
			C.cst816s_release_touch(touchScreen)
		}

		platform.ProcessEvents()

		platform.NewFrame()
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

		screenWindow(screenBuffer, brightness)

		imgui.SetNextWindowPosV(imgui.Vec2{X: 300, Y: 20}, imgui.ConditionOnce, imgui.Vec2{})
		if imgui.BeginV("Inputs", nil, imgui.WindowFlagsAlwaysAutoResize) {
			imgui.Button("Side button")
			if imgui.IsItemHovered() {
				if mouseLeftIsDown && !mouseLeftWasDown {
					C.pins_set(pins, pinButton)
				} else if !mouseLeftIsDown && mouseLeftWasDown {
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

		imgui.SetNextWindowPosV(imgui.Vec2{X: 300, Y: 230}, imgui.ConditionOnce, imgui.Vec2{})
		if imgui.BeginV("Performance", nil, imgui.WindowFlagsAlwaysAutoResize) {
			for i, rtc := range rtcs {
				status := "off"
				if rtc.Running {
					status = "running"
				}

				imgui.Text(fmt.Sprintf("RTC%d (%s)", i, status))

				if rtc.Running {
					imgui.LabelText(fmt.Sprint(rtc.TicksPerSecond), "Ticks per second")
					imgui.LabelText(fmt.Sprint(rtc.TargetTicksPerSecond), "Target ticks per second")
				}

				imgui.Separator()
			}

			imgui.LabelText(fmt.Sprint(instPerSecond), "Instructions per second")

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

		imgui.SetNextWindowPosV(imgui.Vec2{X: 20, Y: 500}, imgui.ConditionOnce, imgui.Vec2{})
		imgui.SetNextWindowSizeV(imgui.Vec2{X: 500, Y: 300}, imgui.ConditionOnce)
		if imgui.BeginV("FreeRTOS", nil, 0) {
			freeHeap := freertosFreeBytesRemaining.Read()

			freeHeapHistory = append(freeHeapHistory, float64(freeHeap))
			for len(freeHeapHistory) > 500 {
				freeHeapHistory = freeHeapHistory[1:]
			}

			imgui.LabelText(strconv.FormatUint(freeHeap, 10), "Free heap bytes")

			winSize := imgui.WindowSize()

			if imgui.ImPlotBegin("Free heap", "", "", imgui.Vec2{X: winSize.X - 20, Y: winSize.Y - 70}, 0, imgui.ImPlotAxisFlags_AutoFit, imgui.ImPlotAxisFlags_AutoFit, 0, 0, "", "") {
				imgui.ImPlotLine("", freeHeapHistory, 1, 0, 0)

				imgui.ImPlotEnd()
			}
		}
		imgui.End()

		imgui.Render()

		renderer.PreRender(clearColor)
		renderer.Render(platform.DisplaySize(), platform.FramebufferSize(), imgui.RenderedDrawData())
		platform.PostRender()

		mouseLeftWasDown = mouseLeftIsDown
		mouseRightWasDown = mouseRightIsDown
	}
}
