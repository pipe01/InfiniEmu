package asm

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type ToolPaths struct {
	As      string
	Objcopy string
}

func Assemble(code string, tools ToolPaths) ([]byte, error) {
	asmOut, err := os.CreateTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	asmOut.Close()
	defer os.Remove(asmOut.Name())

	as := exec.Command(tools.As, "-mcpu=cortex-m4", "-march=armv7-m", "-mthumb", "-o", asmOut.Name())
	as.Stdin = strings.NewReader(code)
	as.Stderr = os.Stderr
	if err := as.Run(); err != nil {
		return nil, fmt.Errorf("run as: %w", err)
	}

	binOut, err := os.CreateTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(binOut.Name())
	defer binOut.Close()

	objcopy := exec.Command(tools.Objcopy, "-Obinary", asmOut.Name(), binOut.Name())
	objcopy.Stderr = os.Stderr
	if err := objcopy.Run(); err != nil {
		return nil, fmt.Errorf("run objcopy: %w", err)
	}

	bin, err := io.ReadAll(binOut)
	if err != nil {
		return nil, fmt.Errorf("read bin: %w", err)
	}

	return bin, nil
}
