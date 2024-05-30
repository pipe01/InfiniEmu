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
var frameIndexStack = []int{}

var bookmarks []int

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

	fmt.Println("Loading frames...")

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
		if frameIndex < 0 || frameIndex >= len(frames) {
			frameIndex = 0
			fmt.Printf("frame index out of bounds (%d), resetting to 0. This is most likely a programming error\n", frameIndex)
		}

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

		err = executeLine(line)
		if err != nil {
			if err == ErrExit {
				break
			}

			fmt.Println(err)
		}
	}
}

func doFrameJump(newIndex int) {
	if newIndex == frameIndex {
		return
	}

	dir := "forward"
	amount := newIndex - frameIndex
	if newIndex < frameIndex {
		dir = "backward"
		amount = frameIndex - newIndex
	}

	fmt.Printf("Jumping %d frames %s\n", amount, dir)

	frameIndex = newIndex
}

func executeLine(line string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panicked while executing command:", r)
		}
	}()

	line = strings.TrimSpace(line)

	if line == "" {
		return nil
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
		return err
	}

	err = cmd(modifier, arg)
	if err != nil {
		return err
	}

	return nil
}
