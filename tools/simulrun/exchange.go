package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

type ExchangeInstruction struct {
	BeforeRegisters   [RegisterCount]uint32
	ExpectedRegisters [RegisterCount]uint32
	Instruction       []byte
	Mnemonic          string
}

func (i ExchangeInstruction) String() string {
	var data bytes.Buffer

	gw := gzip.NewWriter(&data)
	bw := bufio.NewWriter(gw)

	bw.WriteByte(byte(len(i.BeforeRegisters)))
	for _, reg := range i.BeforeRegisters {
		binary.Write(bw, binary.LittleEndian, reg)
	}

	bw.WriteByte(byte(len(i.ExpectedRegisters)))
	for _, reg := range i.ExpectedRegisters {
		binary.Write(bw, binary.LittleEndian, reg)
	}

	bw.WriteByte(byte(len(i.Instruction)))
	bw.Write(i.Instruction)

	bw.WriteByte(byte(len(i.Mnemonic)))
	bw.WriteString(i.Mnemonic)

	bw.Flush()
	gw.Close()

	return base64.StdEncoding.EncodeToString(data.Bytes())
}

func ParseExchangeInstruction(s string) (ExchangeInstruction, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ExchangeInstruction{}, err
	}

	var i ExchangeInstruction

	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return ExchangeInstruction{}, err
	}

	var n byte
	binary.Read(r, binary.LittleEndian, &n)
	if n != byte(len(i.BeforeRegisters)) {
		return ExchangeInstruction{}, fmt.Errorf("invalid register count: %d", n)
	}

	for j := range i.BeforeRegisters {
		binary.Read(r, binary.LittleEndian, &i.BeforeRegisters[j])
	}

	binary.Read(r, binary.LittleEndian, &n)
	if n != byte(len(i.ExpectedRegisters)) {
		return ExchangeInstruction{}, fmt.Errorf("invalid register count: %d", n)
	}

	for j := range i.ExpectedRegisters {
		binary.Read(r, binary.LittleEndian, &i.ExpectedRegisters[j])
	}

	binary.Read(r, binary.LittleEndian, &n)
	i.Instruction = make([]byte, n)
	r.Read(i.Instruction)

	binary.Read(r, binary.LittleEndian, &n)
	mnemonic := make([]byte, n)
	r.Read(mnemonic)
	i.Mnemonic = string(mnemonic)

	return i, nil
}
