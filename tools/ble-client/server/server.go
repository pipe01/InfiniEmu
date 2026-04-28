package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"slices"
	"sync"
	"time"
)

type Server struct {
	conn     net.Conn
	msgch    chan GenericMessage
	onNotify func(uint16, []byte)

	lock sync.Mutex
}

func Dial(addr string, onNotify func(uint16, []byte)) (*Server, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	sv := &Server{
		conn:     c,
		msgch:    make(chan GenericMessage),
		onNotify: onNotify,
	}
	go sv.read()

	return sv, nil
}

func (s *Server) Close() error {
	return s.conn.Close()
}

func (s *Server) read() {
	buffer := make([]byte, 32*1024)

	for {
		n, err := s.conn.Read(buffer)
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

			s.onNotify(payload.Handle, payload.Value)
		} else {
			select {
			case s.msgch <- msg:
			default:
			}
		}
	}
}

func (s *Server) sendMessage(typ string, payload map[string]any) error {
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

	_, err = s.conn.Write(data)
	if err != nil {
		fmt.Printf("failed to send command: %v\n", err)
		return err
	}

	return nil
}

func handleError(msg *GenericMessage) error {
	if msg.Type == "error" {
		var payload struct {
			Error string `json:"error"`
		}
		json.Unmarshal(msg.Payload, &payload)

		return fmt.Errorf("response error: %s", payload.Error)
	} else {
		return fmt.Errorf("response error: %s", string(msg.Payload))
	}
}

func sendRequest[T any](s *Server, requestType string, payload map[string]any) (*T, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.sendMessage(requestType, payload); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	resp := <-s.msgch
	if resp.Type != "response" {
		return nil, handleError(&resp)
	}

	var respPayload T
	json.Unmarshal(resp.Payload, &respPayload)

	return &respPayload, nil
}

func (s *Server) Connect(ctx context.Context) error {
	s.sendMessage("connect", nil)

	t := time.Tick(1 * time.Second)
	for {
		resp, err := sendRequest[struct {
			Ready bool `json:"ready"`
		}](s, "ready?", nil)
		if err == nil && resp.Ready {
			break
		}

		select {
		case <-t:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (s *Server) GetAttributes() ([]Attribute, error) {
	resp, err := sendRequest[PayloadListAttributes](s, "list_attrs", nil)
	if err != nil {
		return nil, err
	}

	return resp.Attributes, nil
}

func (s *Server) ReadAttribute(handle uint16) ([]byte, error) {
	resp, err := sendRequest[PayloadReadChar](s, "read_attr", map[string]any{
		"handle": handle,
	})
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

func (s *Server) WriteAttribute(handle uint16, value []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.sendMessage("write_attr", map[string]any{
		"handle": handle,
		"value":  JSONBytes(value),
	})
}

func (s *Server) ListServices() ([]*Service, error) {
	listResp, err := sendRequest[PayloadListAttributes](s, "list_attrs", nil)
	if err != nil {
		return nil, fmt.Errorf("list attributes: %w", err)
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

			r, err := s.ReadAttribute(ch.Handle)
			if err != nil {
				return nil, err
			}
			currentService.UUID = UUIDFromBytes(r)

		case DeclarationCharacteristic:
			r, err := s.ReadAttribute(ch.Handle)
			if err != nil {
				return nil, err
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

	return services, nil
}
