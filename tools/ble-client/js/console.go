package js

import (
	"log"
	"os"
	"strings"

	"github.com/dop251/goja"
)

var (
	stderrLogger = log.Default() // the default logger output to stderr
	stdoutLogger = log.New(os.Stdout, "", log.LstdFlags)

	defaultStdPrinter Printer = &StdPrinter{
		StdoutPrint: func(s string) { stdoutLogger.Print(s) },
		StderrPrint: func(s string) { stderrLogger.Print(s) },
	}
)

// StdPrinter implements the console.Printer interface
// that prints to the stdout or stderr.
type StdPrinter struct {
	StdoutPrint func(s string)
	StderrPrint func(s string)
}

// Log prints s to the stdout.
func (p StdPrinter) Log(s string) {
	p.StdoutPrint(s)
}

// Warn prints s to the stderr.
func (p StdPrinter) Warn(s string) {
	p.StderrPrint(s)
}

// Error prints s to the stderr.
func (p StdPrinter) Error(s string) {
	p.StderrPrint(s)
}

type Console struct {
	runtime *goja.Runtime
}

type Printer interface {
	Log(string)
	Warn(string)
	Error(string)
}

func (c *Console) log(p func(string)) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			p("")
			return nil
		}

		var str strings.Builder
		str.WriteString(call.Arguments[0].String())

		for _, arg := range call.Arguments[1:] {
			str.WriteByte(' ')
			str.WriteString(arg.String())
		}

		p(str.String())

		return nil
	}
}

func NewConsole(runtime *goja.Runtime) *goja.Object {
	return NewConsoleWithPrinter(runtime, defaultStdPrinter)
}

func NewConsoleWithPrinter(runtime *goja.Runtime, printer Printer) *goja.Object {
	c := &Console{
		runtime: runtime,
	}

	o := runtime.NewObject()
	o.Set("log", c.log(printer.Log))
	o.Set("error", c.log(printer.Error))
	o.Set("warn", c.log(printer.Warn))
	o.Set("info", c.log(printer.Log))
	o.Set("debug", c.log(printer.Log))

	return o
}
