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
	"strconv"
	"strings"
	"time"

	"github.com/AllenDang/imgui-go"
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

func constCheckbox(id string, state bool) {
	imgui.Checkbox(id, &state)
}

func pinCheckbox(id string, emulator *Emulator, pin int) {
	state := emulator.IsPinSet(pin)

	if imgui.Checkbox(id, &state) {
		if state {
			emulator.PinSet(pin)
		} else {
			emulator.PinClear(pin)
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

var allowScreenSwipes = true
var screenTextureID imgui.TextureID
var screenMouseDownPos imgui.Vec2
var screenDidSwipe bool

var mouseLeftIsDown, mouseLeftWasDown bool
var mouseRightIsDown, mouseRightWasDown bool

func screenWindow(screenBuffer []byte, emulator *Emulator) {
	var err error

	flags := imgui.WindowFlagsNoResize | imgui.WindowFlagsAlwaysAutoResize
	if allowScreenSwipes {
		flags |= imgui.WindowFlagsNoMove
	}

	imgui.SetNextWindowPosV(imgui.Vec2{X: 20, Y: 20}, imgui.ConditionOnce, imgui.Vec2{})
	if imgui.BeginV("Display", nil, flags) {
		renderer.ReleaseImage(screenTextureID)
		var img *image.RGBA

		if emulator.IsDisplaySleeping() || emulator.Brightness() == BrightnessOff {
			img = blackScreenImage
		} else {
			emulator.ReadDisplayBuffer(screenBuffer)

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
					emulator.DoTouch(GestureSingleTap, int(screenMouseDownPos.X), int(screenMouseDownPos.Y))
				}
			} else if mouseLeftIsDown && mouseLeftWasDown && !screenDidSwipe && allowScreenSwipes {
				pos := imgui.MousePos().Minus(imgui.GetItemRectMin())
				distVec := pos.Minus(screenMouseDownPos)
				dist := math.Sqrt(float64(distVec.X*distVec.X) + float64(distVec.Y*distVec.Y))

				if dist > 40 {
					screenDidSwipe = true

					var gesture TouchGesture

					xDist := math.Abs(float64(distVec.X))
					yDist := math.Abs(float64(distVec.Y))

					if xDist > yDist {
						if distVec.X > 0 {
							gesture = GestureSlideRight
						} else {
							gesture = GestureSlideLeft
						}
					} else {
						if distVec.Y > 0 {
							gesture = GestureSlideDown
						} else {
							gesture = GestureSlideUp
						}
					}

					emulator.DoTouch(gesture, int(pos.X), int(pos.Y))
				}
			} else if !mouseLeftIsDown && mouseLeftWasDown {
				if allowScreenSwipes && !screenDidSwipe {
					emulator.DoTouch(GestureSingleTap, int(screenMouseDownPos.X), int(screenMouseDownPos.Y))
					time.Sleep(50 * time.Millisecond) // TODO: Do this better?
				}

				emulator.ReleaseTouch()
			}

			if mouseRightIsDown && !mouseRightWasDown {
				emulator.PinSet(pinButton)
			} else if !mouseRightIsDown && mouseRightWasDown {
				emulator.PinClear(pinButton)
			}
		}

		imgui.Checkbox("Allow swiping with mouse", &allowScreenSwipes)

		imgui.Separator()

		imgui.Text(fmt.Sprintf("Brightness: %v", emulator.Brightness()))
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

	emulator := NewEmulator(program)

	emulator.WriteVariable("NoInit_MagicWord", 0, 0xDEAD0000)
	emulator.WriteVariable("NoInit_BackUpTime", 0, uint64(time.Now().UnixNano()))

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

	var speed float32 = 1

	freeHeapHistory := make([]float64, 0)

	if *runGDB {
		emulator.Start(RunModeGDB)
	} else if noScheduler {
		emulator.Start(RunModeLoop)
	} else {
		emulator.Start(RunModeScheduled)
	}

	i := 0

	for !platform.ShouldStop() {
		<-t
		i++

		emulator.SetHeartrateValue(uint32(((math.Sin(float64(i)/60) + 1) / 2) * 4000))

		mouseLeftIsDown = imgui.IsMouseDown(0)
		mouseRightIsDown = imgui.IsMouseDown(1)

		if !releaseTouchTime.IsZero() && time.Now().After(releaseTouchTime) {
			releaseTouchTime = time.Time{}

			emulator.ReleaseTouch()
		}

		platform.ProcessEvents()

		platform.NewFrame()
		imgui.NewFrame()

		screenWindow(screenBuffer, emulator)

		imgui.SetNextWindowPosV(imgui.Vec2{X: 300, Y: 20}, imgui.ConditionOnce, imgui.Vec2{})
		if imgui.BeginV("Inputs", nil, imgui.WindowFlagsAlwaysAutoResize) {
			imgui.Button("Side button")
			if imgui.IsItemHovered() {
				if mouseLeftIsDown && !mouseLeftWasDown {
					emulator.PinSet(pinButton)
				} else if !mouseLeftIsDown && mouseLeftWasDown {
					emulator.PinClear(pinButton)
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
						emulator.DoTouch(GestureSlideUp, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}

					imgui.TableNextRow(0, 0)
					imgui.TableSetColumnIndex(0)
					if imgui.Button("Slide left") {
						emulator.DoTouch(GestureSlideLeft, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}
					imgui.TableSetColumnIndex(2)
					if imgui.Button("Slide right") {
						emulator.DoTouch(GestureSlideRight, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}

					imgui.TableNextRow(0, 0)
					imgui.TableSetColumnIndex(1)
					if imgui.Button("Slide down") {
						emulator.DoTouch(GestureSlideDown, displayWidth/2, displayHeight/2)
						releaseTouchTime = time.Now().Add(touchDuration)
					}
				}
				imgui.EndDisabled()
			}
			imgui.EndTable()

			imgui.Separator()

			pinCheckbox("Charging (active low)", emulator, pinCharging)
			pinCheckbox("Power present (active low)", emulator, pinPowerPresent)
		}
		imgui.End()

		imgui.SetNextWindowPosV(imgui.Vec2{X: 300, Y: 230}, imgui.ConditionOnce, imgui.Vec2{})
		if imgui.BeginV("Performance", nil, imgui.WindowFlagsAlwaysAutoResize) {
			for i, rtc := range emulator.RTCTrackers() {
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

			imgui.LabelText(strconv.FormatUint(emulator.InstructionsPerSecond(), 10), "Instructions per second")

			imgui.BeginDisabled(*runGDB)
			{
				if imgui.Checkbox("Disable scheduler", &noScheduler) {
					emulator.Stop()

					if noScheduler {
						emulator.Start(RunModeLoop)
					} else {
						emulator.Start(RunModeScheduled)
					}
				}

				imgui.BeginDisabled(noScheduler)
				{
					if imgui.SliderFloat("Speed", &speed, 0, 2) {
						emulator.SetFrequency(uint(speed * baseFrequencyHZ))
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
			freeHeap, ok := emulator.ReadVariable("xFreeBytesRemaining", 0)

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

		imgui.Render()

		renderer.PreRender(clearColor)
		renderer.Render(platform.DisplaySize(), platform.FramebufferSize(), imgui.RenderedDrawData())
		platform.PostRender()

		mouseLeftWasDown = mouseLeftIsDown
		mouseRightWasDown = mouseRightIsDown
	}
}
