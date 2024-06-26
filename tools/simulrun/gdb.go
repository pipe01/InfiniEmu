package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
)

const RegisterCount = 17

var RegisterNames = []string{"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC", "xPSR"}

const logMessages = false

const defaultResetCommand = "reset halt"

type GDBClient struct {
	conn io.ReadWriteCloser

	regs [RegisterCount]uint32

	resetCmd  string
	noAckMode bool
}

func DialGDB(addr string) (*GDBClient, error) {
	log.Printf("connecting to gdb at %s", addr)

	if !strings.HasPrefix(addr, "tcp://") {
		addr = "tcp://" + addr
	}

	uri, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	conn, err := net.Dial("tcp", uri.Host)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	gdb := &GDBClient{
		conn:     conn,
		resetCmd: defaultResetCommand,
	}

	if uri.Query().Has("resetcmd") {
		gdb.resetCmd = uri.Query().Get("resetcmd")
	}

	if err = gdb.startNoAck(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("start no ack mode: %w", err)
	}

	return gdb, nil
}

func readMessage(br *bufio.Reader) ([]byte, error) {
	start, err := br.ReadByte()
	if err != nil {
		return nil, err
	}
	for start == '+' {
		start, err = br.ReadByte()
		if err != nil {
			return nil, err
		}
	}
	if start != '$' {
		return nil, fmt.Errorf("invalid start: 0x%x", start)
	}

	var data bytes.Buffer

	nextEscaped := false

	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err
		}

		if nextEscaped {
			nextEscaped = false
			data.WriteByte(b ^ 0x20)
		} else if b == 0x7D {
			nextEscaped = true
		} else if b == '#' {
			break
		} else {
			data.WriteByte(b)
		}
	}

	// Skip checksum
	br.ReadByte()
	br.ReadByte()

	return data.Bytes(), nil
}

func parseRegisters(p []byte) (*[RegisterCount]uint32, error) {
	data := make([]byte, len(p)/2)

	n, err := hex.Decode(data, p)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}

	if n < RegisterCount*4 {
		return nil, fmt.Errorf("invalid register count: %d", n)
	}
	n = RegisterCount * 4

	var regs [RegisterCount]uint32

	for i := 0; i < len(regs); i++ {
		regs[i] = binary.LittleEndian.Uint32(data[i*4 : i*4+4])
	}

	return &regs, nil
}

func (g *GDBClient) sendRequest(data []byte) error {
	if logMessages {
		log.Printf("-> %s", string(data))
	}

	var msg bytes.Buffer
	msg.WriteByte('$')
	msg.Write(data)

	var checksum uint8
	for _, b := range data {
		checksum += b
	}

	fmt.Fprintf(&msg, "#%02x", checksum)

	_, err := g.conn.Write(msg.Bytes())
	if err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	return nil
}

func (g *GDBClient) readResponse() ([]byte, error) {
	br := bufio.NewReader(g.conn)

	reply, err := readMessage(br)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	if logMessages {
		log.Printf("<- %s", string(reply))
	}

	return reply, nil
}

func (g *GDBClient) makeRequest(data []byte) ([]byte, error) {
	err := g.sendRequest(data)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	reply, err := g.readResponse()
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return reply, nil
}

func (g *GDBClient) runCommand(cmd string) error {
	err := g.sendRequest([]byte("qRcmd," + hex.EncodeToString([]byte(cmd))))
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	for {
		data, err := g.readResponse()
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}

		if string(data) == "OK" {
			break
		}

		isIntermediate := false
		if data[0] == 'O' {
			data = data[1:]
			isIntermediate = true
		}

		msg, err := hex.AppendDecode(nil, data)
		if err != nil {
			return fmt.Errorf("decode output: %w", err)
		}

		log.Printf("command '%s' output: %s", cmd, string(msg))

		if !isIntermediate {
			break
		}
	}

	return nil
}

func (g *GDBClient) startNoAck() error {
	resp, err := g.makeRequest([]byte("QStartNoAckMode"))
	if err != nil {
		return err
	}
	if string(resp) != "OK" {
		log.Print("remote doesn't support no-ack mode")
		return nil
	}

	g.noAckMode = true
	return nil
}

func (g *GDBClient) Registers() *[RegisterCount]uint32 {
	return &g.regs
}

func (g *GDBClient) ReadRegisters() error {
	reply, err := g.makeRequest([]byte("g"))
	if err != nil {
		return err
	}

	r, err := parseRegisters(reply)
	if err != nil {
		return err
	}

	g.regs = *r
	return nil
}

func (g *GDBClient) WriteRegisters() error {
	var data bytes.Buffer

	g.regs[15] |= 1 // Ensure PC has the Thumb bit set

	for _, r := range g.regs {
		binary.Write(&data, binary.LittleEndian, r)
	}

	_, err := g.makeRequest([]byte(fmt.Sprintf("G%s", hex.EncodeToString(data.Bytes()))))
	return err

}

func (g *GDBClient) Reset() error {
	return g.runCommand(g.resetCmd)
}

func (g *GDBClient) Step() error {
	_, err := g.makeRequest([]byte("s"))
	return err
}

func (g *GDBClient) Continue() error {
	_, err := g.makeRequest([]byte("c"))
	return err
}

func (g *GDBClient) AddBreakpoint(addr uint32) error {
	_, err := g.makeRequest([]byte(fmt.Sprintf("Z1,%x,2", addr)))
	return err
}

func (g *GDBClient) RemoveBreakpoint(addr uint32) error {
	_, err := g.makeRequest([]byte(fmt.Sprintf("z1,%x,2", addr)))
	return err
}

func (g *GDBClient) WriteMemory(addr uint32, data []byte) error {
	_, err := g.makeRequest([]byte(fmt.Sprintf("M%x,%x:%s", addr, len(data), hex.EncodeToString(data))))
	return err
}
