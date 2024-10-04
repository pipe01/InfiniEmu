package gui

import (
	"fmt"
	"image"
	"image/color"
	"log"
	"math"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/AllenDang/imgui-go"
	"github.com/pipe01/InfiniEmu/frontend/desktop/emulator"
)

const touchDuration = 200 * time.Millisecond

var blackScreenImage = image.NewRGBA(image.Rect(0, 0, emulator.DisplayWidth, emulator.DisplayHeight))

var platform *imgui.GLFW
var renderer *imgui.OpenGL3

var allowScreenSwipes = true
var screenTextureID, heapTextureID imgui.TextureID
var screenMouseDownPos imgui.Vec2
var screenDidSwipe bool

var heapSize int32 = 1

var mouseLeftIsDown, mouseLeftWasDown bool
var mouseRightIsDown, mouseRightWasDown bool

func pinCheckbox(id string, emulator *emulator.Emulator, pin int) {
	state := emulator.IsPinSet(pin)

	if imgui.Checkbox(id, &state) {
		if state {
			emulator.PinSet(pin)
		} else {
			emulator.PinClear(pin)
		}
	}
}

func screenWindow(screenBuffer []byte, e *emulator.Emulator) {
	var err error

	flags := imgui.WindowFlagsNoResize | imgui.WindowFlagsAlwaysAutoResize
	if allowScreenSwipes {
		flags |= imgui.WindowFlagsNoMove
	}

	imgui.SetNextWindowPosV(imgui.Vec2{X: 20, Y: 20}, imgui.ConditionOnce, imgui.Vec2{})
	if imgui.BeginV("Display", nil, flags) {
		renderer.ReleaseImage(screenTextureID)
		var img *image.RGBA

		if e.IsDisplaySleeping() || e.Brightness() == emulator.BrightnessOff {
			img = blackScreenImage
		} else {
			e.ReadDisplayBuffer(screenBuffer)

			img = emulator.ConvertImage(screenBuffer)
		}

		screenTextureID, err = renderer.LoadImage(img)
		if err != nil {
			log.Fatal(err)
		}

		imgui.Image(screenTextureID, imgui.Vec2{X: emulator.DisplayWidth, Y: emulator.DisplayHeight})

		if imgui.IsItemHovered() {
			if mouseLeftIsDown && !mouseLeftWasDown {
				screenMouseDownPos = imgui.MousePos().Minus(imgui.GetItemRectMin())
				screenDidSwipe = false

				if !allowScreenSwipes {
					e.DoTouch(emulator.GestureSingleTap, int(screenMouseDownPos.X), int(screenMouseDownPos.Y))
				}
			} else if mouseLeftIsDown && mouseLeftWasDown && !screenDidSwipe && allowScreenSwipes {
				pos := imgui.MousePos().Minus(imgui.GetItemRectMin())
				distVec := pos.Minus(screenMouseDownPos)
				dist := math.Sqrt(float64(distVec.X*distVec.X) + float64(distVec.Y*distVec.Y))

				if dist > 40 {
					screenDidSwipe = true

					var gesture emulator.TouchGesture

					xDist := math.Abs(float64(distVec.X))
					yDist := math.Abs(float64(distVec.Y))

					if xDist > yDist {
						if distVec.X > 0 {
							gesture = emulator.GestureSlideRight
						} else {
							gesture = emulator.GestureSlideLeft
						}
					} else {
						if distVec.Y > 0 {
							gesture = emulator.GestureSlideDown
						} else {
							gesture = emulator.GestureSlideUp
						}
					}

					e.DoTouch(gesture, int(pos.X), int(pos.Y))
				}
			} else if !mouseLeftIsDown && mouseLeftWasDown {
				if allowScreenSwipes && !screenDidSwipe {
					e.DoTouch(emulator.GestureSingleTap, int(screenMouseDownPos.X), int(screenMouseDownPos.Y))
					time.Sleep(50 * time.Millisecond) // TODO: Do this better?
				}

				e.ReleaseTouch()
			}

			if mouseRightIsDown && !mouseRightWasDown {
				e.PinSet(emulator.PinButton)
			} else if !mouseRightIsDown && mouseRightWasDown {
				e.PinClear(emulator.PinButton)
			}
		}

		imgui.Checkbox("Allow swiping with mouse", &allowScreenSwipes)

		imgui.Separator()

		imgui.Text(fmt.Sprintf("Brightness: %v", e.Brightness()))
	}
	imgui.End()
}

func heapWindow(heap *emulator.HeapTracker) {
	if imgui.BeginV("Heap", nil, imgui.WindowFlagsAlwaysAutoResize) {
		renderer.ReleaseImage(heapTextureID)

		img := buildHeapImage(*heap, int(heapSize))
		if img != nil {
			heapTextureID, _ = renderer.LoadImage(img)
			imgui.Image(heapTextureID, imgui.Vec2{X: float32(img.Bounds().Dx()), Y: float32(img.Bounds().Dy())})
		}

		allocs := heap.GetInUse()
		slices.SortFunc(allocs, func(i, j emulator.HeapAllocation) int {
			if i.Address < j.Address {
				return -1
			} else if i.Address > j.Address {
				return 1
			}

			return 0
		})

		var usedBytes int
		var holeBytes int

		for i, alloc := range allocs {
			usedBytes += int(alloc.Size)

			if i > 0 {
				prevAlloc := &allocs[i-1]
				holeSize := int32(alloc.Address) - int32(prevAlloc.Address+uint32(prevAlloc.Size))

				if holeSize > 0 {
					holeBytes += int(holeSize)
				}
			}
		}

		imgui.Text(fmt.Sprintf("Used heap: %d out of %d bytes (%d bytes free)", usedBytes, heap.HeapSize(), heap.HeapSize()-usedBytes))
		imgui.Text(fmt.Sprintf("Bytes lost to fragmentation: %d bytes", holeBytes))

		imgui.SliderInt("Size", &heapSize, 1, 5)
	}
	imgui.End()
}

func buildHeapImage(heap emulator.HeapTracker, pixelsPerByte int) *image.RGBA {
	if heap.HeapSize() == 0 {
		return nil
	}

	bytesPerRow := 512
	if pixelsPerByte >= 3 {
		bytesPerRow = 256
	}

	rows := (heap.HeapSize() + bytesPerRow - 1) / bytesPerRow // Round up

	img := image.NewRGBA(image.Rect(0, 0, int(bytesPerRow)*pixelsPerByte, int(rows)*pixelsPerByte))

	bytes := heap.GetBytes()

	for y := 0; y < rows; y++ {
		for x := 0; x < bytesPerRow; x++ {
			byteIndex := uint32(y*bytesPerRow + x)

			if byteIndex >= uint32(len(bytes)) {
				break
			}

			byteState := bytes[byteIndex]

			byteUsed := byteState&emulator.ByteStateUsed != 0
			byteFreed := byteState&emulator.ByteStateFreed != 0

			for py := 0; py < pixelsPerByte; py++ {
				for px := 0; px < pixelsPerByte; px++ {
					var clr color.RGBA

					if byteUsed && byteFreed {
						clr = color.RGBA{0, 0x50, 0xa0, 0xff}
					} else if byteUsed {
						clr = color.RGBA{0xa0, 0, 0, 0xff}
					} else if byteFreed {
						clr = color.RGBA{0, 0xa0, 0, 0xff}
					} else {
						clr = color.RGBA{0, 0, 0, 0xff}
					}

					img.Set(int(x)*pixelsPerByte+px, int(y)*pixelsPerByte+py, clr)
				}
			}
		}
	}

	return img
}

func RunGUI(e *emulator.Emulator, analyzeHeap, runGDB, noScheduler bool) error {
	e.WriteVariable("NoInit_MagicWord", 0, 0xDEAD0000)
	e.WriteVariable("NoInit_BackUpTime", 0, uint64(time.Now().UnixNano()))

	screenBuffer := make([]byte, emulator.DisplayWidth*emulator.DisplayHeight*emulator.DisplayBytesPerPixel)

	context := imgui.CreateContext(nil)
	defer context.Destroy()

	imgui.ImPlotCreateContext()
	defer imgui.ImPlotDestroyContext()

	io := imgui.CurrentIO()
	io.Fonts().AddFontDefault()

	platform, err := imgui.NewGLFW(io, "InfiniEmu", 600, 750, 0)
	if err != nil {
		return fmt.Errorf("create imgui: %w", err)
	}
	defer platform.Dispose()

	renderer, err = imgui.NewOpenGL3(io, 1.0)
	if err != nil {
		return fmt.Errorf("create imgui renderer: %w", err)
	}
	defer renderer.Dispose()

	renderer.SetFontTexture(io.Fonts().TextureDataRGBA32())

	clearColor := [4]float32{0.7, 0.7, 0.7, 1.0}

	imgui.StyleColorsDark()

	t := time.Tick(time.Second / 60)

	var releaseTouchTime time.Time

	var speed float32 = 1

	freeHeapHistory := make([]float64, 0)

	if runGDB {
		e.Start(emulator.RunModeGDB)
	} else if noScheduler {
		e.Start(emulator.RunModeLoop)
	} else {
		e.Start(emulator.RunModeScheduled)
	}

	i := 0

	for !platform.ShouldStop() {
		<-t
		i++

		e.SetHeartrateValue(uint32(((math.Sin(float64(i)/60) + 1) / 2) * 4000))

		if e.DidSPIFlashChange() {
			fmt.Println("External SPI flash contents changed")
			os.WriteFile("spiflash.bin", e.SPIFlash(), os.ModePerm)
		}

		mouseLeftIsDown = imgui.IsMouseDown(0)
		mouseRightIsDown = imgui.IsMouseDown(1)

		if !releaseTouchTime.IsZero() && time.Now().After(releaseTouchTime) {
			releaseTouchTime = time.Time{}

			e.ReleaseTouch()
		}

		platform.ProcessEvents()

		platform.NewFrame()
		imgui.NewFrame()

		screenWindow(screenBuffer, e)

		imgui.SetNextWindowPosV(imgui.Vec2{X: 300, Y: 20}, imgui.ConditionOnce, imgui.Vec2{})
		if imgui.BeginV("Inputs", nil, imgui.WindowFlagsAlwaysAutoResize) {
			imgui.Button("Side button")
			if imgui.IsItemHovered() {
				if mouseLeftIsDown && !mouseLeftWasDown {
					e.PinSet(emulator.PinButton)
				} else if !mouseLeftIsDown && mouseLeftWasDown {
					e.PinClear(emulator.PinButton)
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
						e.DoTouch(emulator.GestureSlideUp, emulator.DisplayWidth/2, emulator.DisplayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}

					imgui.TableNextRow(0, 0)
					imgui.TableSetColumnIndex(0)
					if imgui.Button("Slide left") {
						e.DoTouch(emulator.GestureSlideLeft, emulator.DisplayWidth/2, emulator.DisplayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}
					imgui.TableSetColumnIndex(2)
					if imgui.Button("Slide right") {
						e.DoTouch(emulator.GestureSlideRight, emulator.DisplayWidth/2, emulator.DisplayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}

					imgui.TableNextRow(0, 0)
					imgui.TableSetColumnIndex(1)
					if imgui.Button("Slide down") {
						e.DoTouch(emulator.GestureSlideDown, emulator.DisplayWidth/2, emulator.DisplayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}
				}
				imgui.EndDisabled()
			}
			imgui.EndTable()

			imgui.Separator()

			pinCheckbox("Charging (active low)", e, emulator.PinCharging)
			pinCheckbox("Power present (active low)", e, emulator.PinPowerPresent)
		}
		imgui.End()

		imgui.SetNextWindowPosV(imgui.Vec2{X: 300, Y: 230}, imgui.ConditionOnce, imgui.Vec2{})
		if imgui.BeginV("Performance", nil, imgui.WindowFlagsAlwaysAutoResize) {
			for i, rtc := range e.RTCTrackers() {
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

			imgui.LabelText(strconv.FormatUint(e.InstructionsPerSecond(), 10), "Instructions per second")

			imgui.BeginDisabled(runGDB)
			{
				if imgui.Checkbox("Disable scheduler", &noScheduler) {
					e.Stop()

					if noScheduler {
						e.Start(emulator.RunModeLoop)
					} else {
						e.Start(emulator.RunModeScheduled)
					}
				}

				imgui.BeginDisabled(noScheduler)
				{
					if imgui.SliderFloat("Speed", &speed, 0, 2) {
						e.SetFrequency(uint(speed * emulator.BaseFrequencyHZ))
					}
				}
				imgui.EndDisabled()
			}
			imgui.EndDisabled()

			if imgui.Button("Heap") {
				e.FindFreeHeapBlocks()
			}
		}
		imgui.End()

		imgui.SetNextWindowPosV(imgui.Vec2{X: 20, Y: 500}, imgui.ConditionOnce, imgui.Vec2{})
		imgui.SetNextWindowSizeV(imgui.Vec2{X: 500, Y: 300}, imgui.ConditionOnce)
		if imgui.BeginV("FreeRTOS", nil, 0) {
			freeHeap, ok := e.ReadVariable("xFreeBytesRemaining", 0)

			if !ok {
				imgui.PushTextWrapPos()
				imgui.Text("FreeRTOS data not available, try loading an ELF file with FreeRTOS symbols")
				imgui.PopTextWrapPos()
			} else {
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
		}
		imgui.End()

		if analyzeHeap {
			heapWindow(e.Heap)
		}

		imgui.Render()

		renderer.PreRender(clearColor)
		renderer.Render(platform.DisplaySize(), platform.FramebufferSize(), imgui.RenderedDrawData())
		platform.PostRender()

		mouseLeftWasDown = mouseLeftIsDown
		mouseRightWasDown = mouseRightIsDown
	}

	return nil
}
