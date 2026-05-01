package hostble

import (
	"context"
	"fmt"
	"log"

	"github.com/pipe01/InfiniEmu/tools/ble-client/server"
	"tinygo.org/x/bluetooth"
)

var adapter = bluetooth.DefaultAdapter

type HostBLE struct {
	srv *server.Server
	adv *bluetooth.Advertisement

	services  []*server.Service
	bservices []*bluetooth.Service

	chars map[bluetooth.UUID]map[bluetooth.UUID]*bluetooth.Characteristic
}

func NewHostBLE(srv *server.Server) *HostBLE {
	return &HostBLE{
		srv:   srv,
		chars: map[bluetooth.UUID]map[bluetooth.UUID]*bluetooth.Characteristic{},
	}
}

func (h *HostBLE) Start() error {
	log.Print("starting host BLE stack")

	err := adapter.Enable()
	if err != nil {
		return fmt.Errorf("start adapter: %w", err)
	}

	manageConnection := !h.srv.Connected()

	adapter.SetConnectHandler(func(device bluetooth.Device, connected bool) {
		if connected {
			log.Print("device connected:", device.Address.String())

			if manageConnection {
				h.srv.Connect(context.Background())
			}
		} else {
			log.Print("device disconnected:", device.Address.String())

			if manageConnection {
				h.srv.Disconnect(context.Background())
			}
		}
	})

	h.adv = adapter.DefaultAdvertisement()
	h.adv.Configure(bluetooth.AdvertisementOptions{
		LocalName: "InfiniTime Emulator",
	})

	// We need to connect at startup to load the watch's BLE services and characteristics
	if manageConnection {
		h.srv.Connect(context.Background())
		defer h.srv.Disconnect(context.Background())
	}

	services, err := h.srv.ListServices()
	if err != nil {
		return fmt.Errorf("list emulated services: %w", err)
	}
	h.services = services

	err = h.adv.Start()
	if err != nil {
		return fmt.Errorf("start advertising: %w", err)
	}

	for _, svc := range services {
		svcUUID := convertUUID(svc.UUID)

		h.chars[svcUUID] = map[bluetooth.UUID]*bluetooth.Characteristic{}

		chars := make([]bluetooth.CharacteristicConfig, len(svc.Characteristics))

		for i, char := range svc.Characteristics {
			charUUID := convertUUID(char.UUID)

			handle := new(bluetooth.Characteristic)

			bch := bluetooth.CharacteristicConfig{
				UUID:   charUUID,
				Flags:  bluetooth.CharacteristicPermissions(char.Properties),
				Handle: handle,
				WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
					log.Printf("write %s: %v", charUUID, value)

					err := h.srv.WriteAttribute(char.Handle, value)
					if err != nil {
						log.Printf("failed to write characteristic %s: %v", char.UUID, err)
					}
				},
				ReadEvent: func(client bluetooth.Connection) []byte {
					val, err := h.srv.ReadAttribute(char.Handle)
					if err != nil {
						log.Printf("failed to read characteristic %s: %v", char.UUID, err)
					}
					log.Printf("read %s: %v", charUUID, val)

					return val
				},
			}

			h.chars[svcUUID][charUUID] = handle
			chars[i] = bch
		}

		bsvc := &bluetooth.Service{
			UUID:            svcUUID,
			Characteristics: chars,
		}
		adapter.AddService(bsvc)
		h.bservices = append(h.bservices, bsvc)
	}

	return nil
}

func (h *HostBLE) Stop() {
	h.adv.Stop()

	for _, svc := range h.bservices {
		adapter.RemoveService(svc)
	}
}

func (h *HostBLE) Notify(handle uint16, value []byte) {
	for _, svc := range h.services {
		for _, ch := range svc.Characteristics {
			if ch.Handle == handle {
				bhandle := h.chars[convertUUID(svc.UUID)][convertUUID(ch.UUID)]
				if bhandle != nil {
					bhandle.Write(value)
				}

				return
			}
		}
	}
}

func convertUUID(uuid server.UUID) bluetooth.UUID {
	if uuid.Is16() {
		return bluetooth.New16BitUUID(uuid.UUID16)
	} else {
		return bluetooth.NewUUID([16]byte(uuid.UUID128))
	}
}
