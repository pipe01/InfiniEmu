package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

const (
	DeclarationPrimaryService   = 0x2800
	DeclarationSecondaryService = 0x2801
	DeclarationInclude          = 0x2802
	DeclarationCharacteristic   = 0x2803
)

type MessageType string

const (
	MessageError   MessageType = "error"
	MessageConnect MessageType = "connect"
)

type GenericMessage struct {
	Type    string `json:"type"`
	Payload []byte
}

type Attribute struct {
	Handle  uint16 `json:"handle"`
	UUID16  uint16 `json:"uuid16"`
	UUID128 []byte `json:"uuid128"`
}

type PayloadListAttributes struct {
	Attributes []Attribute `json:"attributes"`
}

func (p *PayloadListAttributes) Sort() {
	slices.SortFunc(p.Attributes, func(a, b Attribute) int {
		if a.Handle < b.Handle {
			return -1
		} else if a.Handle > b.Handle {
			return 1
		} else {
			return 0
		}
	})
}

type PayloadReadChar struct {
	Data []byte `json:"data"`
}

type PayloadNotify struct {
	Handle uint16 `json:"handle"`
	Value  []byte `json:"value"`
}

type JSONBytes []uint8

func (u JSONBytes) MarshalJSON() ([]byte, error) {
	var result string
	if u == nil {
		result = "null"
	} else {
		result = strings.Join(strings.Fields(fmt.Sprintf("%d", u)), ",")
	}
	return []byte(result), nil
}

var conn net.Conn
var msgch chan GenericMessage = make(chan GenericMessage, 5)

func main() {
	addr := flag.String("addr", "localhost:9345", "address of the BLE server to connect to")
	flag.Parse()

	c, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to connect to server: %v\n", err)
	}
	defer c.Close()
	conn = c

	rl, err := readline.NewEx(&readline.Config{
		EOFPrompt:       "exit",
		InterruptPrompt: "",
		Prompt:          "> ",
	})
	if err != nil {
		log.Fatalf("failed to create readline: %v", err)
	}
	defer rl.Close()

	go func() {
		buffer := make([]byte, 32*1024)

		for {
			n, err := conn.Read(buffer)
			if err != nil {
				log.Fatalf("failed to read from server: %v\n", err)
			}

			data := buffer[:n]

			var msg GenericMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				fmt.Fprintf(os.Stderr, "failed to decode response from server: %v\n", err)
				continue
			}
			msg.Payload = data

			if msg.Type == "notify" {
				var payload PayloadNotify
				json.Unmarshal(msg.Payload, &payload)

				fmt.Fprintf(rl, "Handle %d notified value %x (%s)\n", payload.Handle, payload.Value, string(payload.Value))
			} else {
				msgch <- msg
			}
		}
	}()

	for _, l := range flag.Args() {
		runLine(l)
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

		runLine(line)
	}
}

func runLine(line string) {
	cmdName, arg, _ := strings.Cut(line, " ")
	args := strings.Split(arg, " ")

	switch cmdName {
	case "connect":
		sendMessage("connect", nil)

		t := time.Tick(1 * time.Second)
		for {
			resp, err := sendRequest[struct {
				Ready bool `json:"ready"`
			}]("ready?", nil)
			if err == nil && resp.Ready {
				break
			}

			<-t
		}

		println("Connected")

	case "list":
		switch args[0] {
		case "attrs", "attributes":
			sendMessage("list_attrs", nil)

			resp := <-msgch

			if resp.Type != "response" {
				handleError(&resp)
			} else {
				var payload PayloadListAttributes
				json.Unmarshal(resp.Payload, &payload)
				payload.Sort()

				println("Handle  UUID")
				for _, ch := range payload.Attributes {
					fmt.Printf("% 6d  ", ch.Handle)

					if ch.UUID128 == nil {
						fmt.Printf("0x%x\n", ch.UUID16)
					} else if len(ch.UUID128) == 16 {
						fmt.Printf("%s\n", formatUUID128(ch.UUID128))
					}
				}
			}

		case "svcs", "services":
			err := listServices()
			if err != nil {
				fmt.Printf("failed to read services: %v\n", err)
				break
			}

		default:
			println("invalid argument")
		}

	case "read":
		switch args[0] {
		case "attr", "attribute":
			handle, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Printf("invalid handle: %v\n", err)
				break
			}

			data, err := readAttribute(uint16(handle))
			if err != nil {
				fmt.Printf("failed to read attribute: %v\n", err)
				break
			}

			fmt.Printf("data: %x (%s)\n", data, string(data))

		default:
			println("invalid argument")
		}

	case "write":
		switch args[0] {
		case "attr", "attribute":
			handle, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Printf("invalid handle: %v\n", err)
				break
			}

			var data []byte
			if strings.HasPrefix(args[2], "0x") {
				b, err := parseHexData(args[2][2:])
				if err != nil {
					fmt.Printf("invalid hex data: %v\n", err)
					break
				}
				data = b
			} else {
				data = []byte(args[2])
			}

			err = sendMessage("write_attr", map[string]any{
				"handle": handle,
				"value":  JSONBytes(data),
			})
			if err != nil {
				fmt.Printf("failed to write attribute: %v\n", err)
				break
			}

		default:
			println("invalid argument")
		}

	case "exit", "quit":
		os.Exit(0)

	default:
		println("unknown command")
	}
}

func handleError(msg *GenericMessage) error {
	if msg.Type == "error" {
		var payload struct {
			Error string `json:"error"`
		}
		json.Unmarshal(msg.Payload, &payload)

		fmt.Printf("got an error response: %s\n", payload.Error)

		return fmt.Errorf("response error: %s", payload.Error)
	} else {
		fmt.Printf("got an error response:%s\n", string(msg.Payload))

		return fmt.Errorf("response error: %s", string(msg.Payload))
	}
}

func sendMessage(typ string, payload map[string]any) error {
	msg := map[string]any{
		"type": typ,
	}

	if payload != nil {
		maps.Insert(msg, maps.All(payload))
	}

	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("failed to send command: %v\n", err)
		return err
	}

	_, err = conn.Write(data)
	if err != nil {
		fmt.Printf("failed to send command: %v\n", err)
		return err
	}

	return nil
}

func sendRequest[T any](requestType string, payload map[string]any) (*T, error) {
	if err := sendMessage(requestType, payload); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	resp := <-msgch
	if resp.Type != "response" {
		return nil, handleError(&resp)
	}

	var respPayload T
	json.Unmarshal(resp.Payload, &respPayload)

	return &respPayload, nil
}

func readAttribute(handle uint16) ([]byte, error) {
	resp, err := sendRequest[PayloadReadChar]("read_attr", map[string]any{
		"handle": handle,
	})
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

func formatUUID128(uuid []byte) string {
	rev := uuid[:]
	slices.Reverse(rev)

	return fmt.Sprintf("%x-%x-%x-%x-%x", rev[:4], rev[4:6], rev[6:8], rev[8:10], rev[10:])
}

type UUID struct {
	UUID16  uint16
	UUID128 []byte
}

func (u UUID) String() string {
	if u.UUID128 == nil {
		return fmt.Sprintf("0x%x", u.UUID16)
	}

	rev := u.UUID128[:]
	slices.Reverse(rev)

	return fmt.Sprintf("%x-%x-%x-%x-%x", rev[:4], rev[4:6], rev[6:8], rev[8:10], rev[10:])
}

func (u UUID) Is16() bool {
	return u.UUID128 == nil
}

func UUIDFromBytes(b []byte) UUID {
	if len(b) == 16 {
		return UUID{
			UUID128: b,
		}
	} else if len(b) == 2 {
		return UUID{
			UUID16: binary.LittleEndian.Uint16(b),
		}
	} else {
		panic("invalid uuid length")
	}
}

type Service struct {
	UUID            UUID
	Characteristics []Characteristic
}

type Characteristic struct {
	Properties uint8
	Handle     uint16
	UUID       UUID
}

func listServices() error {
	listResp, err := sendRequest[PayloadListAttributes]("list_attrs", nil)
	if err != nil {
		return fmt.Errorf("list attributes: %w", err)
	}
	listResp.Sort()

	services := make([]*Service, 0)
	var currentService *Service

	for _, ch := range listResp.Attributes {
		if ch.UUID128 != nil {
			continue // Skip 128-bit UUIDs
		}

		switch ch.UUID16 {
		case DeclarationPrimaryService, DeclarationSecondaryService:
			currentService = &Service{}
			services = append(services, currentService)

			r, err := readAttribute(ch.Handle)
			if err != nil {
				return err
			}
			currentService.UUID = UUIDFromBytes(r)

		case DeclarationCharacteristic:
			r, err := readAttribute(ch.Handle)
			if err != nil {
				return err
			}

			currentService.Characteristics = append(currentService.Characteristics, Characteristic{
				Properties: r[0],
				Handle:     binary.LittleEndian.Uint16(r[1:]),
				UUID:       UUIDFromBytes(r[3:]),
			})
		}
	}

	slices.SortFunc(services, func(a, b *Service) int {
		// 16-bit UUIDs should appear before 128-bit UUIDs
		// Same-length UUIDs should be ordered numerically

		if a.UUID.Is16() && !b.UUID.Is16() {
			return -1
		} else if !a.UUID.Is16() && b.UUID.Is16() {
			return 1
		} else if a.UUID.Is16() && b.UUID.Is16() {
			if a.UUID.UUID16 < b.UUID.UUID16 {
				return -1
			} else if a.UUID.UUID16 > b.UUID.UUID16 {
				return 1
			} else {
				return 0
			}
		} else {
			return bytes.Compare(a.UUID.UUID128, b.UUID.UUID128)
		}
	})

	for _, svc := range services {
		fmt.Printf("Service %s\n", svc.UUID)

		for _, ch := range svc.Characteristics {
			fmt.Printf("  Characteristic %s\n", ch.UUID)
			fmt.Printf("    Properties: %08b\n", ch.Properties)
			fmt.Printf("    Handle: %d\n", ch.Handle)
		}
	}

	return nil
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
