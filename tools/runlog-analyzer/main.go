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

func parseInt(str string) (int, error) {
	n, err := strconv.ParseInt(str, 0, 32)
	return int(n), err
}

var frames Frames
var frameIndex = 0

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

	frames, err = ReadFrames(f)
	if err != nil {
		log.Fatalf("failed to read frames: %v", err)
	}

	fmt.Printf("Loaded %d frames from %s\n", len(frames), runlogPath)

	pcItems := make([]readline.PrefixCompleterInterface, 0, len(frames))
	for name := range Commands {
		pcItems = append(pcItems, readline.PcItem(name))
	}

	rl, err := readline.NewEx(&readline.Config{
		EOFPrompt:       "exit",
		InterruptPrompt: "",
		AutoComplete:    readline.NewPrefixCompleter(pcItems...),
	})
	if err != nil {
		log.Fatalf("failed to create readline: %v", err)
	}
	defer rl.Close()

	// rl.CaptureExitSignal()

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

		line = strings.TrimSpace(line)

		if line == "" {
			line = lastCommand
		} else {
			lastCommand = line
		}

		if line == "" {
			continue
		}

		cmdName, arg, hasArg := strings.Cut(line, " ")

		if hasArg {
			arg = strings.TrimSpace(arg)
			hasArg = arg != ""
		}

		modifier := ""
		if cmd, mod, ok := strings.Cut(cmdName, "/"); ok {
			cmdName = cmd
			modifier = mod
		}

		cmd, err := FindCommand(cmdName)
		if err != nil {
			fmt.Println(err)
			continue
		}

		err = cmd(modifier, arg)
		if err != nil {
			if err == ErrExit {
				break
			}

			fmt.Println(err)
		}
	}
}
