package main

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrExit            = errors.New("exit")
	ErrInvalidArgument = errors.New("invalid argument")
)

type Command func(arg string) error

var Commands = map[string]Command{
	"next":     CommandNextPreviousFrame(1),
	"previous": CommandNextPreviousFrame(-1),
	"frame":    CommandFrame,
	"view":     CommandView,
	"exit":     func(arg string) error { return ErrExit },
}

func FindCommand(name string) (Command, bool) {
	cmd, ok := Commands[name]
	if !ok {
		for k, v := range Commands {
			if strings.HasPrefix(k, name) {
				if cmd != nil {
					return nil, false // Ambiguous command
				}

				cmd = v
			}
		}
	}

	return cmd, cmd != nil
}

func CommandNextPreviousFrame(dir int) Command {
	return func(arg string) error {
		offset := dir

		if arg != "" {
			n, err := parseInt(arg)
			if err != nil {
				return ErrInvalidArgument
			}

			offset *= n
		}

		if offset > 0 && frameIndex+offset >= len(frames) {
			frameIndex = len(frames) - 1
		} else if offset < 0 && frameIndex+offset < 0 {
			frameIndex = 0
		} else {
			frameIndex += offset
		}

		return nil
	}
}

func CommandFrame(arg string) error {
	if arg == "" {
		fmt.Printf("On frame %d out of %d\n", frameIndex, len(frames))
	} else if arg == "end" {
		frameIndex = len(frames) - 1
	} else {
		n, err := parseInt(arg)
		if err != nil || n < 0 || n >= len(frames) {
			return errors.New("invalid or out of range frame index")
		}

		frameIndex = n
	}

	return nil
}

func CommandView(arg string) error {
	currentFrame := frames[frameIndex]

	if arg == "" {
		for i := RUNLOG_REG_R0; i <= RUNLOG_REG_MAX; i++ {
			fmt.Printf("%s\t0x%08x\n", i.String(), currentFrame.Registers[i])
		}
	} else if strings.HasPrefix(arg, "$") {
		reg, err := parseRegister(arg[1:])
		if err != nil {
			return err
		}

		fmt.Printf("%s: 0x%08x\n", arg, currentFrame.Registers[reg])
	} else {
		fmt.Println("invalid argument, expected register or memory address")
	}

	return nil
}
