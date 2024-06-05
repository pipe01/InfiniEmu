package main

/*
#cgo CFLAGS: -I../../include
#cgo LDFLAGS: libinfiniemu.o -lcapstone

#include "gdb.h"
#include "pinetime.h"
#include "scheduler.h"

volatile unsigned long inst_counter = 0;
volatile bool stop_loop = false;

static void loop(pinetime_t *pt)
{
	stop_loop = false;

	while (!stop_loop)
	{
		pinetime_step(pt);
		inst_counter++;
	}
}

static scheduler_t *create_sched(pinetime_t *pt, size_t freq)
{
	return scheduler_new((scheduler_cb_t)pinetime_step, pt, freq);
}
*/
import "C"

import (
	"context"
	"encoding/binary"
	"runtime"
	"sync/atomic"
	"time"
)

const (
	displayWidth         = 240
	displayHeight        = 240
	displayBytesPerPixel = C.BYTES_PER_PIXEL
)

type TouchGesture int

const (
	GestureNone       TouchGesture = C.GESTURE_NONE
	GestureSlideDown  TouchGesture = C.GESTURE_SLIDEDOWN
	GestureSlideUp    TouchGesture = C.GESTURE_SLIDEUP
	GestureSlideLeft  TouchGesture = C.GESTURE_SLIDELEFT
	GestureSlideRight TouchGesture = C.GESTURE_SLIDERIGHT
	GestureSingleTap  TouchGesture = C.GESTURE_SINGLETAP
	GestureDoubleTap  TouchGesture = C.GESTURE_DOUBLETAP
	GestureLongPress  TouchGesture = C.GESTURE_LONGPRESS
)

type RunMode int

const (
	RunModeLoop RunMode = iota
	RunModeScheduled
	RunModeGDB
)

type Brightness int

const (
	BrightnessOff Brightness = iota
	BrightnessLow
	BrightnessMedium
	BrightnessHigh
	BrightnessInvalid
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

type RTCTracker struct {
	rtc *C.RTC_t

	TicksPerSecond       uint32
	TargetTicksPerSecond uint32
	Running              bool

	lastTicks uint32
}

func (r *RTCTracker) update(updateInterval time.Duration) {
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

func (v *CPUVariable) Available() bool {
	return v.sym != nil
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

type Emulator struct {
	program *Program

	initialSP uint32

	pt          *C.pinetime_t
	nrf52       *C.NRF52832_t
	cpu         *C.cpu_t
	lcd         *C.st7789_t
	touchScreen *C.cst816s_t
	pins        *C.pins_t
	rtcs        []*C.RTC_t

	rtcTrackers []*RTCTracker

	sched          *C.scheduler_t
	isRunning      atomic.Bool
	currentRunMode RunMode

	instPerSecond uint64

	perfLoopCtx    context.Context
	perfLoopCancel func()
}

func NewEmulator(program *Program) *Emulator {
	flash := program.Flatten()

	var pinner runtime.Pinner
	defer pinner.Unpin()

	pinner.Pin(&flash[0])

	// The C code makes a copy of the flash contents, so we can unpin it after
	pt := C.pinetime_new((*C.uchar)(&flash[0]), C.ulong(len(flash)), true)
	C.pinetime_reset(pt)

	nrf52 := C.pinetime_get_nrf52832(pt)
	pins := C.nrf52832_get_pins(nrf52)

	// Active low pins with pull ups
	C.pins_set(pins, pinCharging)
	C.pins_set(pins, pinPowerPresent)

	rtcs := []*C.RTC_t{
		(*C.RTC_t)(C.nrf52832_get_peripheral(nrf52, C.INSTANCE_RTC0)),
		(*C.RTC_t)(C.nrf52832_get_peripheral(nrf52, C.INSTANCE_RTC1)),
		(*C.RTC_t)(C.nrf52832_get_peripheral(nrf52, C.INSTANCE_RTC2)),
	}

	rtcTrackers := make([]*RTCTracker, len(rtcs))
	for i := range rtcs {
		rtcTrackers[i] = &RTCTracker{
			rtc: rtcs[i],
		}
	}

	return &Emulator{
		program: program,
		pt:      pt,
		sched:   C.create_sched(pt, baseFrequencyHZ),

		initialSP: binary.LittleEndian.Uint32(flash),

		cpu:         C.nrf52832_get_cpu(nrf52),
		nrf52:       nrf52,
		lcd:         C.pinetime_get_st7789(pt),
		touchScreen: C.pinetime_get_cst816s(pt),
		pins:        pins,
		rtcs:        rtcs,
		rtcTrackers: rtcTrackers,
	}
}

func (e *Emulator) perfLoop() {
	interval := 500 * time.Millisecond

	var lastCounter uint64

	t := time.Tick(interval)

	for {
		select {
		case <-t:
		case <-e.perfLoopCtx.Done():
			return
		}

		if !e.isRunning.Load() {
			break
		}

		for _, rtc := range e.rtcTrackers {
			rtc.update(interval)
		}

		var instCounter uint64
		if e.currentRunMode == RunModeLoop {
			instCounter = uint64(C.inst_counter)
		} else {
			instCounter = uint64(C.scheduler_get_counter(e.sched))
		}

		e.instPerSecond = (1e6 * (instCounter - lastCounter)) / uint64(interval.Microseconds())
		lastCounter = instCounter
	}
}

func (e *Emulator) Start(mode RunMode) {
	if !e.isRunning.CompareAndSwap(false, true) {
		panic("emulator already running")
	}

	e.currentRunMode = mode
	e.perfLoopCtx, e.perfLoopCancel = context.WithCancel(context.Background())

	switch mode {
	case RunModeLoop:
		go C.loop(e.pt)

	case RunModeScheduled:
		go C.scheduler_run(e.sched)

	case RunModeGDB:
		gdb := C.gdb_new(e.pt, true)
		go C.gdb_start(gdb)
	}

	go e.perfLoop()
}

func (e *Emulator) Stop() {
	if !e.isRunning.CompareAndSwap(true, false) {
		return
	}

	e.perfLoopCancel()

	switch e.currentRunMode {
	case RunModeLoop:
		C.stop_loop = true

	case RunModeScheduled:
		C.scheduler_stop(e.sched)

	case RunModeGDB:
		panic("can't stop gdb")
	}

	time.Sleep(100 * time.Millisecond) // TODO: Properly wait for loop or scheduler to stop
}

func (e *Emulator) InstructionsPerSecond() uint64 {
	return e.instPerSecond
}

func (e *Emulator) NumRTC() int {
	return len(e.rtcs)
}

func (e *Emulator) RTCTrackers() []*RTCTracker {
	return e.rtcTrackers
}

func (e *Emulator) SetFrequency(hz uint) {
	C.scheduler_set_frequency(e.sched, C.size_t(hz))
}

func (e *Emulator) Brightness() Brightness {
	lcdLow := bool(C.pins_is_set(e.pins, pinLcdBacklightLow))
	lcdMedium := bool(C.pins_is_set(e.pins, pinLcdBacklightMedium))
	lcdHigh := bool(C.pins_is_set(e.pins, pinLcdBacklightHigh))

	if !lcdLow && lcdMedium && lcdHigh {
		return BrightnessLow
	} else if !lcdLow && !lcdMedium && lcdHigh {
		return BrightnessMedium
	} else if !lcdLow && !lcdMedium && !lcdHigh {
		return BrightnessHigh
	} else if lcdLow && lcdMedium && lcdHigh {
		return BrightnessOff
	}

	return BrightnessInvalid
}

func (e *Emulator) Variable(name string) *CPUVariable {
	return &CPUVariable{
		mem: C.cpu_mem(e.cpu),
		sym: e.program.FindSymbol(name),
	}
}

func (e *Emulator) DoTouch(gesture TouchGesture, x, y int) {
	C.cst816s_do_touch(e.touchScreen, C.touch_gesture_t(gesture), C.uint16_t(x), C.uint16_t(y))
}

func (e *Emulator) ReleaseTouch() {
	C.cst816s_release_touch(e.touchScreen)
}

func (e *Emulator) PinSet(pin int) {
	C.pins_set(e.pins, C.int(pin))
}

func (e *Emulator) PinClear(pin int) {
	C.pins_clear(e.pins, C.int(pin))
}

func (e *Emulator) IsPinSet(pin int) bool {
	return bool(C.pins_is_set(e.pins, C.int(pin)))
}

func (e *Emulator) IsDisplaySleeping() bool {
	return bool(C.st7789_is_sleeping(e.lcd))
}

func (e *Emulator) ReadDisplayBuffer(p []byte) {
	if len(p) != displayWidth*displayHeight*displayBytesPerPixel {
		panic("invalid buffer size")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	pinner.Pin(&p[0])

	C.st7789_read_screen(e.lcd, (*C.uchar)(&p[0]), displayWidth, displayHeight)
}
