package server

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
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

func FormatUUID128(uuid []byte) string {
	rev := slices.Clone(uuid)
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

	return FormatUUID128(u.UUID128)
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
