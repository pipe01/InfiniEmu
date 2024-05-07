package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
)

func parseRegister(str string) (RunlogRegister, error) {
	if len(str) < 2 {
		return 0, fmt.Errorf("invalid register: %s", str)
	}

	str = strings.ToLower(str)

	if str[0] == 'r' {
		n, err := strconv.Atoi(str[1:])
		if err != nil {
			return 0, fmt.Errorf("invalid register number: %s", str)
		}

		if n < 0 || n > int(RUNLOG_REG_PC) {
			return 0, fmt.Errorf("register number out of range: %d", n)
		}

		return RunlogRegister(n) + RUNLOG_REG_R0, nil
	}

	switch str {
	case "sp":
		return RUNLOG_REG_SP, nil
	case "lr":
		return RUNLOG_REG_LR, nil
	case "pc":
		return RUNLOG_REG_PC, nil
	}

	return 0, fmt.Errorf("invalid register: %s", str)
}

func parseInt(str string) (int, error) {
	n, err := strconv.ParseInt(str, 0, 32)
	return int(n), err
}

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatalf("usage: %s <runlog path>", os.Args[0])
	}

	runlogPath := flag.Arg(0)

	f, err := os.Open(runlogPath)
	if err != nil {
		log.Fatalf("failed to open runlog: %v", err)
	}
	defer f.Close()

	frames, err := ReadFrames(f)
	if err != nil {
		log.Fatalf("failed to read frames: %v", err)
	}

	fmt.Printf("Loaded %d frames from %s\n", len(frames), runlogPath)

	rl, err := readline.NewEx(&readline.Config{
		EOFPrompt:       "exit",
		InterruptPrompt: "exit",
		AutoComplete: readline.NewPrefixCompleter(
			readline.PcItem("exit"),
			readline.PcItem("frame"),
			readline.PcItem("next"),
			readline.PcItem("preview"),
			readline.PcItem("view"),
		),
	})
	if err != nil {
		log.Fatalf("failed to create readline: %v", err)
	}
	defer rl.Close()

	// rl.CaptureExitSignal()

	frameIndex := 0
	lastCommand := ""

	for {
		currentFrame := frames[frameIndex]

		rl.SetPrompt(fmt.Sprintf("#%d (0x%x %s)> ", frameIndex, currentFrame.NextInstruction.Address, currentFrame.NextInstruction.Mnemonic))

		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			}
			continue
		} else if err == io.EOF {
			break
		}

		if line == "" {
			line = lastCommand
		} else {
			lastCommand = line
		}

		command, arg, hasArg := strings.Cut(line, " ")

		if hasArg {
			arg = strings.TrimSpace(arg)
			hasArg = arg != ""
		}

		switch command {
		case "next", "n", "previous", "p":
			offset := 1
			if command == "previous" || command == "p" {
				offset = -1
			}

			if hasArg {
				n, err := parseInt(arg)
				if err != nil || n < 0 {
					fmt.Println("invalid argument")
					break
				}

				offset *= n
			}

			frameIndex += offset

		case "frame", "fr":
			if !hasArg {
				fmt.Printf("On frame %d out of %d\n", frameIndex, len(frames))
			} else if arg == "end" {
				frameIndex = len(frames) - 1
			} else {
				n, err := parseInt(arg)
				if err != nil || n < 0 || n >= len(frames) {
					fmt.Println("invalid or out of range frame index")
					break
				}

				frameIndex = n
			}

		case "view", "v":
			if !hasArg {
				for i := RUNLOG_REG_R0; i <= RUNLOG_REG_MAX; i++ {
					fmt.Printf("%s\t0x%08x\n", i.String(), currentFrame.Registers[i])
				}
			} else if strings.HasPrefix(arg, "$") {
				reg, err := parseRegister(arg[1:])
				if err != nil {
					fmt.Println(err)
					break
				}

				fmt.Printf("%s: 0x%08x\n", arg, currentFrame.Registers[reg])
			} else {
				fmt.Println("invalid argument, expected register or memory address")
			}

		case "exit":
			return

		case "":
			// Do nothing

		default:
			fmt.Printf("unknown command: %s\n", command)
		}
	}
}
