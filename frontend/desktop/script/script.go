package script

import (
	"bufio"
	"bytes"
	"fmt"
	"image"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/pipe01/InfiniEmu/frontend/desktop/emulator"
)

var ErrNeedsArguments = fmt.Errorf("needs arguments")

const iterationsPerMicrosecond = 64

func parseScriptInt(str string) (uint64, error) {
	return strconv.ParseUint(strings.ReplaceAll(str, "_", ""), 10, 64)
}

func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

func parseTouchGesture(str string) (emulator.TouchGesture, error) {
	switch str {
	case "left":
		return emulator.GestureSlideLeft, nil
	case "right":
		return emulator.GestureSlideRight, nil
	case "up":
		return emulator.GestureSlideUp, nil
	case "down":
		return emulator.GestureSlideDown, nil
	case "tap":
		return emulator.GestureSingleTap, nil
	case "doubleTap":
		return emulator.GestureDoubleTap, nil
	case "longTap":
		return emulator.GestureLongPress, nil
	}

	return 0, fmt.Errorf("swipe: invalid direction")
}

func runEmulatorTime(e *emulator.Emulator, t time.Duration) {
	iterations := uint64(t.Microseconds()) * iterationsPerMicrosecond

	e.RunIterations(iterations, iterationsPerMicrosecond)
}

var commands = map[string]func(*emulator.Emulator, []string) error{
	"run": func(e *emulator.Emulator, args []string) error {
		if len(args) != 1 {
			return ErrNeedsArguments
		}

		if dur, err := time.ParseDuration(args[0]); err == nil {
			runEmulatorTime(e, dur)
			return nil
		}

		iterations, err := parseScriptInt(args[0])
		if err != nil {
			return fmt.Errorf("parse iterations number: %w", err)
		}

		e.RunIterations(iterations, iterationsPerMicrosecond)

		return nil
	},

	"setDateTime": func(e *emulator.Emulator, args []string) (err error) {
		if len(args) != 1 {
			return ErrNeedsArguments
		}

		var date time.Time

		if args[0] == "now" {
			date = time.Now()
		} else {
			date, err = time.Parse("2006-01-02T15:04:05", args[0])
			if err != nil {
				return fmt.Errorf("parse date: %w", err)
			}
		}

		e.WriteVariable("NoInit_MagicWord", 0, 0xDEAD0000)
		e.WriteVariable("NoInit_BackUpTime", 0, uint64(date.UnixNano()))

		return nil
	},

	"+touch": func(e *emulator.Emulator, args []string) error {
		if len(args) == 0 {
			return ErrNeedsArguments
		}

		gesture, err := parseTouchGesture(args[0])
		if err != nil {
			return err
		}

		var x, y uint64

		if len(args) > 1 {
			x, err = parseScriptInt(args[1])
			if err != nil {
				return err
			}

			if len(args) > 2 {
				y, err = parseScriptInt(args[2])
				if err != nil {
					return err
				}
			}
		}

		e.DoTouch(gesture, int(x), int(y))

		return nil
	},

	"-touch": func(e *emulator.Emulator, args []string) error {
		e.ReleaseTouch()

		return nil
	},

	// Shortcut for +touch and -touch
	"tap": func(e *emulator.Emulator, args []string) error {
		if len(args) != 2 {
			return ErrNeedsArguments
		}

		x, err := parseScriptInt(args[0])
		if err != nil {
			return err
		}

		y, err := parseScriptInt(args[1])
		if err != nil {
			return err
		}

		e.DoTouch(emulator.GestureSingleTap, int(x), int(y))

		runEmulatorTime(e, 50*time.Millisecond)

		e.ReleaseTouch()

		return nil
	},

	// Shortcut for +touch and -touch
	"swipe": func(e *emulator.Emulator, args []string) error {
		if len(args) == 0 {
			return ErrNeedsArguments
		}

		gesture, err := parseTouchGesture(args[0])
		if err != nil {
			return err
		}

		e.DoTouch(gesture, 0, 0)

		runEmulatorTime(e, 50*time.Millisecond)

		e.ReleaseTouch()

		return nil
	},

	"+button": func(e *emulator.Emulator, args []string) error {
		e.PinSet(emulator.PinButton)

		return nil
	},

	"-button": func(e *emulator.Emulator, args []string) error {
		e.PinClear(emulator.PinButton)

		return nil
	},
}

func Execute(e *emulator.Emulator, script []byte) ([]image.Image, error) {
	sc := bufio.NewScanner(bytes.NewReader(script))
	sc.Split(splitLinesSemicolon)

	screenshots := make([]image.Image, 0)
	screenBuffer := make([]byte, emulator.DisplayWidth*emulator.DisplayHeight*emulator.DisplayBytesPerPixel)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		hashtag := strings.Index(line, "#")
		if hashtag != -1 {
			line = line[:hashtag]
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		log.Println(line)

		cmd, argsStr, _ := strings.Cut(line, " ")

		args := strings.Fields(argsStr)

		if cmd == "screenshot" {
			e.ReadDisplayBuffer(screenBuffer)

			screenshots = append(screenshots, emulator.ConvertImage(screenBuffer))

			continue
		}

		fn, ok := commands[cmd]
		if !ok {
			return nil, fmt.Errorf("unknown command: %s", cmd)
		}

		err := fn(e, args)
		if err != nil {
			return nil, fmt.Errorf("command %s: %w", cmd, err)
		}
	}

	if sc.Err() != nil {
		return nil, fmt.Errorf("scan script: %w", sc.Err())
	}

	return screenshots, nil
}

func splitLinesSemicolon(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	semicolon := bytes.IndexByte(data, ';')
	newline := bytes.IndexByte(data, '\n')

	if semicolon >= 0 && (newline == -1 || semicolon < newline) {
		return semicolon + 1, data[0:semicolon], nil
	}
	if newline >= 0 && (semicolon == -1 || newline < semicolon) {
		return newline + 1, dropCR(data[0:newline]), nil
	}

	if atEOF {
		return len(data), dropCR(data), nil
	}
	return 0, nil, nil
}
