package emulator

/*
#cgo CFLAGS: -I../../../include -I../../lib/capstone/include
#cgo LDFLAGS: libinfiniemu.a

#include <setjmp.h>

#include "gdb.h"
#include "fault.h"
#include "pinetime.h"
#include "segger_rtt.h"
#include "scheduler.h"

extern unsigned long inst_counter;
extern bool stop_loop;

scheduler_t *create_sched(pinetime_t *pt, size_t freq);
int run(int type, void *arg, rtt_t *rtt);
void set_cpu_branch_cb(cpu_t *cpu, void *userdata);
*/
import "C"

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	DisplayWidth         = C.PINETIME_LCD_WIDTH
	DisplayHeight        = C.PINETIME_LCD_HEIGHT
	DisplayBytesPerPixel = C.BYTES_PER_PIXEL
)

const (
	portBYTE_ALIGNMENT_MASK = 7
	portBYTE_ALIGNMENT      = 8
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

	usInterval := float64(C.rtc_get_tick_interval_us(r.rtc))
	if usInterval == 0 {
		return
	}

	r.TargetTicksPerSecond = uint32(1e6 / usInterval)
	r.TicksPerSecond = (1e6 * (ticks - r.lastTicks)) / uint32(updateInterval.Microseconds())

	r.lastTicks = ticks
}

type HeapAllocation struct {
	PC      uint32
	Address uint32
	Size    uint
	Freed   bool
}

type ByteState uint8

const (
	ByteStateNone ByteState = (1 << iota) >> 1
	ByteStateUsed
	ByteStateFreed
)

type HeapTracker struct {
	heapStart uint32
	heapSize  int

	bytes []ByteState

	pendingMalloc         bool
	pendingMallocSize     uint
	pendingMallocReturnPC uint32

	mallocs []HeapAllocation
}

func newHeapTracker(start uint32, size int) *HeapTracker {
	return &HeapTracker{
		heapStart: start,
		heapSize:  size,
		bytes:     make([]ByteState, size),
	}
}

func (h *HeapTracker) HeapStart() uint32 {
	return h.heapStart
}

func (h *HeapTracker) HeapSize() int {
	return h.heapSize
}

func (h *HeapTracker) getAllocAt(addr uint32) (*HeapAllocation, bool) {
	for i := len(h.mallocs) - 1; i >= 0; i-- {
		if h.mallocs[i].Address <= addr && addr < h.mallocs[i].Address+uint32(h.mallocs[i].Size) {
			return &h.mallocs[i], true
		}
	}

	return nil, false
}

func (h *HeapTracker) GetBytes() []ByteState {
	return h.bytes
}

func (h *HeapTracker) GetInUse() []HeapAllocation {
	var inUse []HeapAllocation

	for i := range h.mallocs {
		if !h.mallocs[i].Freed {
			inUse = append(inUse, h.mallocs[i])
		}
	}

	return inUse
}

func (h *HeapTracker) GetAll() []HeapAllocation {
	return h.mallocs
}

//export branch_callback
func branch_callback(cpu *C.cpu_t, old_pc, new_pc C.uint, userdata unsafe.Pointer) {
	emulator := emulators[*(*uint64)(userdata)]
	heap := emulator.Heap

	if new_pc == C.uint(emulator.mallocPC) {
		heap.pendingMallocReturnPC = uint32(C.cpu_reg_read(cpu, C.ARM_REG_LR)) &^ 1
		heap.pendingMallocSize = uint(C.cpu_reg_read(cpu, C.ARM_REG_R0))
		heap.pendingMalloc = true
	} else if new_pc == C.uint(emulator.freePC) {
		addr := uint32(C.cpu_reg_read(cpu, C.ARM_REG_R0))

		if addr != 0 {
			if alloc, ok := heap.getAllocAt(addr); ok {
				if alloc.Freed {
					fmt.Printf("Double free of 0x%08x at 0x%x\n", addr, C.cpu_reg_read(cpu, C.ARM_REG_LR))
				} else {
					for i := 0; i < int(heap.pendingMallocSize); i++ {
						heap.bytes[addr-heap.heapStart+uint32(i)] |= ByteStateFreed
						heap.bytes[addr-heap.heapStart+uint32(i)] &^= ByteStateUsed
					}
				}

				alloc.Freed = true
			} else {
				fmt.Printf("Freeing unknown address 0x%08x\n", addr)
			}
		}
	} else if heap.pendingMalloc && new_pc == C.uint(heap.pendingMallocReturnPC) {
		heap.pendingMalloc = false

		addr := uint32(C.cpu_reg_read(cpu, C.ARM_REG_R0))

		for i := 0; i < int(heap.pendingMallocSize); i++ {
			heap.bytes[addr-heap.heapStart+uint32(i)] |= ByteStateUsed
		}

		heap.mallocs = append(heap.mallocs, HeapAllocation{
			PC:      uint32(new_pc),
			Address: addr,
			Size:    heap.pendingMallocSize,
		})
	}
}

type Emulator struct {
	id uint64

	program *Program

	initialSP uint32

	pt          *C.pinetime_t
	nrf52       *C.NRF52832_t
	cpu         *C.cpu_t
	mem         *C.memreg_t
	lcd         *C.st7789_t
	touchScreen *C.cst816s_t
	hrs         *C.hrs3300_t
	extflash    *C.spinorflash_t
	pins        *C.pins_t
	rtcs        []*C.RTC_t
	rtt         *C.rtt_t

	extflashContents   []byte
	extflashWriteCount uint64

	rtcTrackers []*RTCTracker

	sched          *C.scheduler_t
	isRunning      atomic.Bool
	currentRunMode RunMode

	instPerSecond uint64

	perfLoopCtx    context.Context
	perfLoopCancel func()

	longPinner runtime.Pinner

	mallocPC, freePC uint32
	Heap             *HeapTracker

	runlog *C.runlog_t
}

var emulators = map[uint64]*Emulator{}

func NewEmulator(program *Program, spiFlash []byte, big bool) *Emulator {
	flash := program.Flatten()

	var pinner runtime.Pinner
	defer pinner.Unpin()

	var longPinner runtime.Pinner

	// The C code makes a copy of the flash contents, so we can safely unpin it afterwards
	pinner.Pin(&flash[0])

	flashSize := C.size_t(C.NRF52832_FLASH_SIZE)
	if big {
		flashSize = 0x800000
	}

	ptProgram := C.program_new(flashSize)
	if !C.program_load_elf(ptProgram, 0, (*C.uchar)(&flash[0]), C.size_t(len(flash))) {
		C.program_load_binary(ptProgram, 0, (*C.uchar)(&flash[0]), C.size_t(len(flash)))
	}

	pt := C.pinetime_new(ptProgram)
	C.pinetime_reset(pt)

	nrf52 := C.pinetime_get_nrf52832(pt)
	cpu := C.nrf52832_get_cpu(nrf52)
	pins := C.nrf52832_get_pins(nrf52)
	extflash := C.pinetime_get_spinorflash(pt)

	extflashContents := make([]byte, C.PINETIME_EXTFLASH_SIZE)
	longPinner.Pin(&extflashContents[0])

	if len(spiFlash) > 0 {
		copy(extflashContents, spiFlash)
	}

	C.spinorflash_set_buffer(extflash, (*C.uchar)(&extflashContents[0]))

	// Active low pins with pull ups
	C.pins_set(pins, PinCharging)
	C.pins_set(pins, PinPowerPresent)

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

	id := rand.Uint64()

	emulator := Emulator{
		id:      id,
		program: program,
		pt:      pt,
		sched:   C.create_sched(pt, BaseFrequencyHZ),

		initialSP: binary.LittleEndian.Uint32(flash),

		cpu:         cpu,
		nrf52:       nrf52,
		mem:         C.cpu_mem(cpu),
		lcd:         C.pinetime_get_st7789(pt),
		touchScreen: C.pinetime_get_cst816s(pt),
		hrs:         C.pinetime_get_hrs3300(pt),
		rtt:         C.rtt_new(C.cpu_mem(cpu)),
		extflash:    extflash,
		pins:        pins,
		rtcs:        rtcs,
		rtcTrackers: rtcTrackers,

		extflashContents: extflashContents,

		longPinner: longPinner,
	}
	longPinner.Pin(&emulator)

	emulators[id] = &emulator

	longPinner.Pin(&id)

	if pc, ok := program.GetPCAtFunction("pvPortMalloc"); ok {
		emulator.mallocPC = pc
	}
	if pc, ok := program.GetPCAtFunction("vPortFree"); ok {
		emulator.freePC = pc
	}
	if sym, ok := program.Symbols["ucHeap"]; ok {
		emulator.Heap = newHeapTracker(sym.Start, int(sym.Length))
	}

	return &emulator
}

func (e *Emulator) Close() {
	e.longPinner.Unpin()
}

func (e *Emulator) perfLoop() {
	interval := 500 * time.Millisecond

	var lastCounter uint64

	t := time.Tick(interval)
	ctx := e.perfLoopCtx

	for {
		select {
		case <-t:
		case <-ctx.Done():
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

var lock sync.Mutex

func (e *Emulator) Start(mode RunMode) {
	if !e.isRunning.CompareAndSwap(false, true) {
		panic("emulator already running")
	}

	e.currentRunMode = mode
	e.perfLoopCtx, e.perfLoopCancel = context.WithCancel(context.Background())

	go func() {
		lock.Lock()
		defer lock.Unlock()

		fault := 0

		switch mode {
		case RunModeLoop:
			fault = int(C.run(0, unsafe.Pointer(e.pt), e.rtt))

		case RunModeScheduled:
			fault = int(C.run(1, unsafe.Pointer(e.sched), nil))

		case RunModeGDB:
			gdb := C.gdb_new(e.pt, true)
			fault = int(C.run(2, unsafe.Pointer(gdb), nil))
		}

		pc := C.cpu_reg_read(e.cpu, C.ARM_REG_PC) - 4

		fmt.Printf("Execution stopped at PC = 0x%08x with fault %d\n", pc, fault)
	}()

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

func (e *Emulator) EnableHeapTracker() {
	if e.Heap != nil {
		C.set_cpu_branch_cb(e.cpu, unsafe.Pointer(&e.id))
	}
}

func (e *Emulator) DisableHeapTracker() {
	C.set_cpu_branch_cb(e.cpu, nil)
}

func (e *Emulator) SetFrequency(hz uint) {
	C.scheduler_set_frequency(e.sched, C.size_t(hz))
}

func (e *Emulator) Brightness() Brightness {
	lcdLow := bool(C.pins_is_set(e.pins, PinLcdBacklightLow))
	lcdMedium := bool(C.pins_is_set(e.pins, PinLcdBacklightMedium))
	lcdHigh := bool(C.pins_is_set(e.pins, PinLcdBacklightHigh))

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

func (e *Emulator) ReadMemory(addr uint32) uint32 {
	return uint32(C.memreg_read(e.mem, C.uint(addr)))
}

func (e *Emulator) ReadVariable(name string, offset uint32) (value uint64, found bool) {
	sym, ok := e.program.Symbols[name]
	if !ok {
		return 0, false
	}

	switch sym.Length {
	case 1:
		value = uint64(C.memreg_read_byte(e.mem, C.uint(sym.Start+offset)))
	case 2:
		value = uint64(C.memreg_read_halfword(e.mem, C.uint(sym.Start+offset)))
	case 4:
		value = uint64(C.memreg_read(e.mem, C.uint(sym.Start+offset)))
	case 8:
		value = uint64(C.memreg_read(e.mem, C.uint(sym.Start+offset))) | (uint64(C.memreg_read(e.mem, C.uint(sym.Start+offset+4))) << 32)
	default:
		panic("unsupported length")
	}

	return value, true
}

func (e *Emulator) WriteVariable(name string, offset uint32, value uint64) {
	sym, ok := e.program.Symbols[name]
	if !ok {
		return
	}

	switch sym.Length {
	case 1, 2, 4:
		C.memreg_write(e.mem, C.uint(sym.Start+offset), C.uint(value), C.byte_size_t(sym.Length))
	case 8:
		C.memreg_write(e.mem, C.uint(sym.Start+offset), C.uint(value), C.SIZE_WORD)
		C.memreg_write(e.mem, C.uint(sym.Start+offset+4), C.uint(value>>32), C.SIZE_WORD)

	default:
		panic("unsupported length")
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
	if len(p) != DisplayWidth*DisplayHeight*DisplayBytesPerPixel {
		panic("invalid buffer size")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	pinner.Pin(&p[0])

	C.st7789_read_screen(e.lcd, (*C.uchar)(&p[0]), DisplayWidth, DisplayHeight)
}

func (e *Emulator) SetHeartrateValue(val uint32) {
	C.hrs3300_set_ch0(e.hrs, C.uint(val))
}

func (e *Emulator) DidSPIFlashChange() bool {
	newWriteCount := uint64(C.spinorflash_get_write_count(e.extflash))

	if newWriteCount != e.extflashWriteCount {
		e.extflashWriteCount = newWriteCount
		return true
	}

	return false
}

func (e *Emulator) SPIFlash() []byte {
	return e.extflashContents
}

func (e *Emulator) FindFreeHeapBlocks() {
	var blockAddr uint32

	if sym, ok := e.program.Symbols["ucHeap"]; !ok {
		return
	} else {
		blockAddr = sym.Start

		if blockAddr&portBYTE_ALIGNMENT_MASK != 0 {
			blockAddr += portBYTE_ALIGNMENT - 1
			blockAddr &^= portBYTE_ALIGNMENT_MASK
		}

		println(sym.Length)
	}

	blockAllocatedBitSym, ok := e.program.Symbols["xBlockAllocatedBit"]
	if !ok {
		return
	}

	blockAllocatedBit := e.ReadMemory(blockAllocatedBitSym.Start)

	fmt.Printf("Found FreeRTOS heap at 0x%x\n", blockAddr)

	var prevBlockAddr, prevBlockSize uint32

	for blockAddr != 0 {
		// nextFreeBlock := e.ReadMemory(blockAddr)
		blockSize := e.ReadMemory(blockAddr + 4)

		isAllocated := blockSize&blockAllocatedBit != 0

		blockSize &^= blockAllocatedBit

		fmt.Printf("Block at 0x%08x, size %d, in use: %t\n", blockAddr, blockSize, isAllocated)

		if blockSize == 0 {
			break
		}

		if prevBlockAddr != 0 {
			gap := int32(blockAddr) - int32(prevBlockAddr+prevBlockSize)

			if gap > 0 {
				fmt.Printf("Gap between 0x%08x and 0x%08x: %d bytes\n", prevBlockAddr, blockAddr, gap)
			}
		}

		prevBlockAddr = blockAddr
		prevBlockSize = blockSize

		blockAddr += blockSize
	}
}

func (e *Emulator) RecordRunlog(path string) error {
	pathC := C.CString(path)
	modeC := C.CString("wb")

	defer C.free(unsafe.Pointer(pathC))
	defer C.free(unsafe.Pointer(modeC))

	file := C.fopen(pathC, modeC)
	if file == nil {
		return fmt.Errorf("failed to open file")
	}

	e.runlog = C.runlog_new(file)
	C.cpu_set_runlog(e.cpu, e.runlog)
	C.cpu_reset(e.cpu)

	return nil
}

func (e *Emulator) CloseRunlog() {
	if e.runlog == nil {
		return
	}

	C.runlog_free(e.runlog)
}
