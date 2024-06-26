package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrExit            = errors.New("exit")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrMissingArgument = errors.New("missing argument")
)

const digits = "0123456789"

type Command func(mod, arg string) error

var Commands = map[string]Command{
	"accesses": CommandAccesses,
	"bookmark": CommandBookmark,
	"disasm":   CommandDisassemble,
	"eval":     CommandEval,
	"exit":     func(string, string) error { return ErrExit },
	"find":     CommandFind(false),
	"frame":    CommandFrame,
	"log":      CommandLog,
	"next":     CommandNextPreviousFrame(1),
	"pop":      CommandPop,
	"previous": CommandNextPreviousFrame(-1),
	"push":     CommandPush,
	"rfind":    CommandFind(true),
	"view":     CommandView,
}

func printInt(v uint32, modifier string) {
	if strings.ContainsRune(modifier, 'd') {
		fmt.Printf("%d\n", v)
	} else if strings.ContainsRune(modifier, 's') {
		fmt.Printf("%d\n", int32(v))
	} else if strings.ContainsRune(modifier, 'b') {
		fmt.Printf("0b%032b\n", int32(v))
	} else {
		fmt.Printf("0x%08x\n", v)
	}
}

func splitQuoted(str string) []string {
	parts := []string{}

	var sb strings.Builder

	inQuote := false

	for _, r := range str {
		if r == '"' {
			inQuote = !inQuote
		} else if r == ' ' && !inQuote {
			if sb.Len() > 0 {
				parts = append(parts, sb.String())
				sb.Reset()
			}
		} else {
			sb.WriteRune(r)
		}
	}

	if sb.Len() > 0 {
		parts = append(parts, sb.String())
	}

	return parts

}

func FindCommand(name string) (Command, error) {
	cmd, ok := Commands[name]
	if ok {
		return cmd, nil
	}

	matches := []string{}

	for k := range Commands {
		if strings.HasPrefix(k, name) {
			matches = append(matches, k)
		}
	}

	if len(matches) == 0 {
		return nil, errors.New("unknown command")
	}
	if len(matches) == 1 {
		return Commands[matches[0]], nil
	}

	return nil, fmt.Errorf("ambiguous command: %s", strings.Join(matches, ", "))
}

func CommandNextPreviousFrame(dir int) Command {
	return func(_, arg string) error {
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

func CommandFrame(_, arg string) error {
	if arg == "" {
		fmt.Printf("On frame %d out of %d\n", frameIndex, len(frames))
	} else if arg == "end" {
		doFrameJump(len(frames) - 1)
	} else {
		n, err := parseInt(arg)
		if err != nil || n < 0 || n >= len(frames) {
			return errors.New("invalid or out of range frame index")
		}

		doFrameJump(n)
	}

	return nil
}

func CommandView(modifier, arg string) error {
	currentFrame := frames[frameIndex]

	if arg == "" {
		for i := RUNLOG_REG_R0; i <= RUNLOG_REG_MAX; i++ {
			fmt.Printf("%s\t0x%08x\n", i.String(), currentFrame.Registers[i])
		}
	} else {
		baseAddr, err := EvaluateExpression(arg, ExpressionContext{Frames: frames.Until(frameIndex)})
		if err != nil {
			return err
		}

		count := 1
		if modifier != "" {
			firstNum := strings.IndexAny(modifier, digits)
			lastNum := strings.LastIndexAny(modifier, digits)

			if firstNum == 0 {
				count, err = strconv.Atoi(modifier[firstNum : lastNum+1])
				if err != nil {
					return errors.New("invalid count")
				}
			} else if firstNum != -1 {
				return errors.New("invalid modifier")
			}
		}

		for i := uint32(0); i < uint32(count); i++ {
			addr := uint32(baseAddr) + i*4

			val, err := frames[:frameIndex+1].ReadMemoryAt(addr)
			if err != nil {
				return err
			}

			fmt.Printf("0x%08x: ", addr)
			printInt(val, modifier)
		}
	}

	return nil
}

func CommandEval(modifier, arg string) error {
	expr, err := ParseExpression(arg)
	if err != nil {
		return err
	}

	size := 4
	count := 1

	if modifier != "" {
		firstNum := strings.LastIndexAny(modifier, digits)
		lastNum := strings.LastIndexAny(modifier, digits)

		if firstNum == 0 {
			count, err = strconv.Atoi(modifier[firstNum : lastNum+1])
			if err != nil {
				return errors.New("invalid count")
			}
		} else if firstNum != -1 {
			return errors.New("invalid modifier")
		}

		if strings.ContainsRune(modifier, 'b') {
			size = 1
		} else if strings.ContainsRune(modifier, 'h') {
			size = 2
		}
	}

	for i := 0; i < count; i++ {
		val, err := expr.Evaluate(ExpressionContext{
			Frames: frames[:frameIndex+1],
			Offset: uint32(i * size),
		})
		if err != nil {
			return fmt.Errorf("at %d: %w", i, err)
		}

		printInt(val, modifier)
	}

	return nil
}

func doFindFrame(reverse bool, pred func(*Frame) bool) (int, bool) {
	dir := 1
	if reverse {
		dir = -1
	}

	wrapped := false

	for i := frameIndex + dir; ; i += dir {
		if (reverse && i < 0) || (!reverse && i > len(frames)-1) {
			if wrapped {
				break
			}

			wrapped = true
			fmt.Println("Wrapped around")

			if reverse {
				i = len(frames) - 1
			} else {
				i = 0
			}
		}

		frame := frames[i]

		if pred(frame) {
			return i, true
		}
	}

	return 0, false
}

func CommandFind(reverse bool) Command {
	return func(modifier, arg string) error {
		if arg == "" {
			return ErrMissingArgument
		}

		subcmd, arg, hasArg := strings.Cut(arg, " ")

		switch subcmd {
		case "memw", "memr":
			if !hasArg {
				return ErrMissingArgument
			}

			isWrite := subcmd == "memw"

			addrStr, valueStr, hasValue := strings.Cut(arg, " ")

			addr, err := parseInt(addrStr)
			if err != nil {
				return errors.New("invalid address")
			}

			var value int

			if hasValue {
				value, err = parseInt(valueStr)
				if err != nil {
					return errors.New("invalid value")
				}

				hasValue = true
			}

			idx, found := doFindFrame(reverse, func(f *Frame) bool {
				for _, acc := range f.MemoryAccesses {
					if acc.Address == uint32(addr) && acc.IsWrite == isWrite && (!hasValue || acc.Value == uint32(value)) {
						printInt(acc.Value, modifier)
						return true
					}
				}

				return false
			})

			if found {
				doFrameJump(idx)
			} else {
				dirStr := "after"
				if reverse {
					dirStr = "before"
				}

				fmt.Printf("No memory access found on address 0x%08x %s frame #%d\n", addr, dirStr, frameIndex)
			}

		case "regw":
			if !hasArg {
				return ErrMissingArgument
			}

			regStr, valueStr, hasValue := strings.Cut(arg, " ")

			reg, err := ParseRegister(regStr)
			if err != nil {
				return errors.New("invalid register")
			}

			var value uint32

			if hasValue {
				v, err := parseInt(valueStr)
				if err != nil {
					return errors.New("invalid value")
				}

				value = uint32(v)
				hasValue = true
			}

			originalValue := frames[frameIndex].Registers[reg]

			idx, found := doFindFrame(reverse, func(f *Frame) bool {
				if (hasValue && f.Registers[reg] == uint32(value)) || (!hasValue && f.Registers[reg] != originalValue) {
					fmt.Printf("%s = 0x%08x\n", reg.String(), f.Registers[reg])

					return true
				}

				return false
			})

			if found {
				doFrameJump(idx)

				// The frame index we found is the frame *after* the change, so we need to go back one
				// in order to find the instruction that caused the change
				// frameIndex--
			} else {
				dirStr := "after"
				if reverse {
					dirStr = "before"
				}

				fmt.Printf("No registry %s access found %s frame #%d\n", reg.String(), dirStr, frameIndex)
			}

		case "at":
			pc, err := EvaluateExpression(arg, ExpressionContext{Frames: frames.Until(frameIndex)})
			if err != nil {
				return err
			}

			idx, found := doFindFrame(reverse, func(f *Frame) bool {
				return f.NextInstruction.Address == pc
			})

			if found {
				doFrameJump(idx)
			} else {
				dirStr := "after"
				if reverse {
					dirStr = "before"
				}

				fmt.Printf("No instruction found at address 0x%08x %s frame #%d\n", pc, dirStr, frameIndex)
			}

		case "inst":
			if arg == "" {
				return ErrMissingArgument
			}

			var regex *regexp.Regexp
			if len(arg) > 2 && arg[0] == '/' && arg[len(arg)-1] == '/' {
				var err error

				regex, err = regexp.Compile(arg[1 : len(arg)-1])
				if err != nil {
					return errors.New("invalid regular expression")
				}
			}

			idx, found := doFindFrame(reverse, func(f *Frame) bool {
				if regex != nil {
					return regex.MatchString(f.NextInstruction.Mnemonic)
				}
				return strings.HasPrefix(f.NextInstruction.Mnemonic, arg)
			})

			if found {
				doFrameJump(idx)
			} else {
				dirStr := "after"
				if reverse {
					dirStr = "before"
				}

				fmt.Printf("No matching instruction found at %s frame #%d\n", dirStr, frameIndex)
			}

		case "change":
			expr, err := ParseExpression(arg)
			if err != nil {
				return err
			}

			initialValue, err := expr.Evaluate(ExpressionContext{
				Frames: frames.Until(frameIndex),
			})
			if err != nil {
				return err
			}

			seenFrames := make(Frames, 0, len(frames))

			idx, found := doFindFrame(reverse, func(f *Frame) bool {
				seenFrames = append(seenFrames, f)

				val, err := expr.Evaluate(ExpressionContext{
					Frames: seenFrames,
				})
				if err != nil {
					return false
				}

				return val != initialValue
			})

			if found {
				finalValue, err := expr.Evaluate(ExpressionContext{
					Frames: frames.Until(idx),
				})
				if err != nil {
					return err
				}

				doFrameJump(idx)

				fmt.Printf("%s changed from 0x%08x to 0x%08x\n", arg, initialValue, finalValue)
			} else {
				fmt.Println("No change found")
			}

		default:
			return errors.New("unknown subcommand")
		}

		return nil
	}
}

func CommandPush(_, arg string) error {
	frameIndexStack = append(frameIndexStack, frameIndex)

	return nil
}

func CommandPop(_, arg string) error {
	if len(frameIndexStack) == 0 {
		return errors.New("stack is empty")
	}

	frameIndex = frameIndexStack[len(frameIndexStack)-1]
	frameIndexStack = frameIndexStack[:len(frameIndexStack)-1]

	return nil
}

func CommandAccesses(_, arg string) error {
	currentFrame := frames[frameIndex]

	for _, acc := range currentFrame.MemoryAccesses {
		if acc.IsWrite {
			fmt.Printf("0x%08x = %s (0x%08x)\n", acc.Address, acc.Register.String(), acc.Value)
		} else {
			fmt.Printf("%s = 0x%08x (0x%08x)\n", acc.Register.String(), acc.Address, acc.Value)
		}
	}

	return nil
}

func CommandBookmark(_, arg string) error {
	if arg == "" {
		if len(bookmarks) == 0 {
			fmt.Println("No bookmarks")
		} else {
			for i, frameIndex := range bookmarks {
				frame := frames[frameIndex]

				fmt.Printf("%d at frame #%d: 0x%08x %s\n", i, frameIndex, frame.NextInstruction.Address, frame.NextInstruction.Mnemonic)
			}
		}

		return nil
	}

	subcmd, arg, hasArg := strings.Cut(arg, " ")

	switch subcmd {
	case "add":
		if hasArg {
			idx, err := parseInt(arg)
			if err != nil || idx < 0 || idx >= len(frames) {
				return errors.New("invalid frame index")
			}

			bookmarks = append(bookmarks, idx)
		} else {
			bookmarks = append(bookmarks, frameIndex)
		}

	case "remove":
		if !hasArg {
			return ErrMissingArgument
		}

		idx, err := parseInt(arg)
		if err != nil || idx < 0 || idx >= len(bookmarks) {
			return errors.New("invalid bookmark index")
		}

		bookmarks = append(bookmarks[:idx], bookmarks[idx+1:]...)

	default:
		idx, err := parseInt(subcmd)
		if err != nil {
			return errors.New("unknown subcommand")
		}
		if idx < 0 || idx >= len(bookmarks) {
			return errors.New("invalid bookmark index")
		}

		frameIndex = bookmarks[idx]
	}

	return nil
}

func CommandLog(_, arg string) (err error) {
	before := 10
	after := 0

	if arg != "" {
		beforeStr, afterStr, hasAfter := strings.Cut(arg, " ")

		before, err = strconv.Atoi(beforeStr)
		if err != nil || before < 0 {
			return errors.New("invalid before count")
		}

		if hasAfter {
			after, err = strconv.Atoi(afterStr)
			if err != nil || after < 0 {
				return errors.New("invalid after count")
			}
		}
	}

	for i := frameIndex - before; i <= frameIndex+after; i++ {
		if i < 0 || i >= len(frames) {
			continue
		}

		frame := frames[i]

		fmt.Printf("0x%08x %s\n", frame.NextInstruction.Address, frame.NextInstruction.Mnemonic)
	}

	return nil
}

func CommandDisassemble(_, arg string) (err error) {
	addr := frames[frameIndex].NextInstruction.Address
	count := 10

	if arg != "" {
		args := splitQuoted(arg)
		if len(args) > 2 {
			return errors.New("too many arguments")
		}

		if len(args) > 0 {
			addr, err = EvaluateExpression(args[0], ExpressionContext{Frames: frames.Until(frameIndex)})
			if err != nil {
				return err
			}
		}
		if len(args) > 1 {
			count, err = strconv.Atoi(args[1])
			if err != nil || count < 0 {
				return errors.New("invalid count")
			}
		}
	}

	if addr >= uint32(len(frames[frameIndex].Program)) {
		return errors.New("address out of bounds")
	}

	program := frames[frameIndex].Program[addr:]

	disasm, err := NewDisassembler()
	if err != nil {
		return fmt.Errorf("failed to create disassembler: %w", err)
	}

	for i := 0; i < count; i++ {
		inst, err := disasm.Disassemble(program, addr)
		if err != nil {
			return err
		}

		marker := "  "
		if addr == frames[frameIndex].NextInstruction.Address {
			marker = "=>"
		}

		fmt.Printf("%s 0x%08x %s\n", marker, addr, inst.Mnemonic)

		addr += uint32(inst.Size)
		program = program[inst.Size:]
	}

	return nil
}
