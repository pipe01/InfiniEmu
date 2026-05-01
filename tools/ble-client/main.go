package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
	"github.com/pipe01/InfiniEmu/tools/ble-client/hostble"
	"github.com/pipe01/InfiniEmu/tools/ble-client/js/services"
	"github.com/pipe01/InfiniEmu/tools/ble-client/server"
)

var notifiers []services.Notifier
var scriptParams = map[string]any{}
var currentScript *PinePartnerScript
var hostBLE *hostble.HostBLE

var output io.Writer

func main() {
	addr := flag.String("addr", "localhost:9345", "address of the BLE server to connect to")
	flag.Parse()

	rl, err := readline.NewEx(&readline.Config{
		EOFPrompt:       "exit",
		InterruptPrompt: "",
		Prompt:          "> ",
	})
	if err != nil {
		log.Fatalf("failed to create readline: %v", err)
	}
	defer rl.Close()

	output = rl
	log.Default().SetOutput(output)

	sv, err := server.Dial(*addr, func(handle uint16, value []byte) {
		// fmt.Fprintf(rl, "Handle %d notified value %x (%s)\n", handle, value, string(value))

		for _, n := range notifiers {
			n(handle, value)
		}
	})
	if err != nil {
		log.Fatalf("failed to connect to server: %v\n", err)
	}
	defer sv.Close()

	defer func() {
		if hostBLE != nil {
			hostBLE.Stop()
		}
	}()

	for _, l := range flag.Args() {
		runLine(l, sv)
	}

	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			}
			continue
		} else if err == io.EOF {
			break
		}

		runLine(line, sv)
	}
}

func runLine(line string, sv *server.Server) {
	cmdName, arg, _ := strings.Cut(line, " ")
	args := strings.Split(arg, " ")

	switch cmdName {
	case "connect":
		log.Print("connecting to watch...")
		sv.Connect(context.Background())
		log.Print("connected")

	case "list":
		switch args[0] {
		case "attrs", "attributes":
			attrs, err := sv.GetAttributes()
			if err != nil {
				fmt.Fprintf(output, "failed to read attributes: %v\n", err)
				break
			}

			fmt.Fprintln(output, "Handle  UUID")
			for _, ch := range attrs {
				fmt.Fprintf(output, "% 6d  ", ch.Handle)

				if ch.UUID128 == nil {
					fmt.Fprintf(output, "0x%x\n", ch.UUID16)
				} else if len(ch.UUID128) == 16 {
					fmt.Fprintf(output, "%s\n", server.FormatUUID128(ch.UUID128))
				}
			}

		case "svcs", "services":
			svcs, err := sv.ListServices()
			if err != nil {
				fmt.Fprintf(output, "failed to read services: %v\n", err)
				break
			}

			for _, svc := range svcs {
				fmt.Fprintf(output, "Service %s\n", svc.UUID)

				for _, ch := range svc.Characteristics {
					fmt.Fprintf(output, "  Characteristic %s\n", ch.UUID)
					fmt.Fprintf(output, "    Properties: %08b\n", ch.Properties)
					fmt.Fprintf(output, "    Handle: %d\n", ch.Handle)
				}
			}

		default:
			fmt.Fprintln(output, "invalid argument")
		}

	case "read":
		switch args[0] {
		case "attr", "attribute":
			handle, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintf(output, "invalid handle: %v\n", err)
				break
			}

			data, err := sv.ReadAttribute(uint16(handle))
			if err != nil {
				fmt.Fprintf(output, "failed to read attribute: %v\n", err)
				break
			}

			fmt.Fprintf(output, "data: %x (%s)\n", data, string(data))

		default:
			fmt.Fprintln(output, "invalid argument")
		}

	case "write":
		switch args[0] {
		case "attr", "attribute":
			handle, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintf(output, "invalid handle: %v\n", err)
				break
			}

			var data []byte
			if strings.HasPrefix(args[2], "0x") {
				b, err := parseHexData(args[2][2:])
				if err != nil {
					fmt.Fprintf(output, "invalid hex data: %v\n", err)
					break
				}
				data = b
			} else {
				data = []byte(args[2])
			}

			err = sv.WriteAttribute(uint16(handle), data)
			if err != nil {
				fmt.Fprintf(output, "failed to write attribute: %v\n", err)
				break
			}

		default:
			fmt.Fprintln(output, "invalid argument")
		}

	case "param":
		key, value, _ := strings.Cut(arg, " ")
		scriptParams[key] = value

	case "run":
		notifiers = []services.Notifier{}

		source, err := os.ReadFile(arg)
		if err != nil {
			fmt.Fprintf(output, "failed to read file: %v\n", err)
			break
		}

		currentScript, err = RunPinePartnerScript(string(source), sv, &notifiers, scriptParams)
		if err != nil {
			fmt.Fprintf(output, "failed to run script: %v\n", err)
		}

	case "eval":
		if currentScript == nil {
			fmt.Fprintln(output, "no script is currently running")
			break
		}

		val, err := currentScript.vm.RunString(arg)
		if err != nil {
			fmt.Fprintln(output, err.Error())
		} else {
			fmt.Fprintln(output, val.Export())
		}

	case "exit", "quit":
		os.Exit(0)

	case "echo":
		fmt.Fprintln(output, arg)

	case "host":
		switch arg {
		case "on":
			if hostBLE == nil {
				hostBLE = hostble.NewHostBLE(sv)

				err := hostBLE.Start()
				if err != nil {
					log.Fatalf("failed to start host BLE emulator: %v", err)
				}

				notifiers = append(notifiers, hostBLE.Notify)
			}
		}

	default:
		fmt.Fprintln(output, "unknown command")
	}
}

func parseHexData(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "_", "")

	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex data: must have even length")
	}

	data := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		byteVal, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex data: %v", err)
		}
		data[i/2] = byte(byteVal)
	}
	return data, nil
}
