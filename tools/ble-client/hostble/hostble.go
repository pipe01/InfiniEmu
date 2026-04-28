package hostble

import (
	"fmt"
	"log"

	"github.com/pipe01/InfiniEmu/tools/ble-client/server"
	"tinygo.org/x/bluetooth"
)

var adapter = bluetooth.DefaultAdapter

type HostBLE struct {
	srv *server.Server

	services []*server.Service

	chars map[bluetooth.UUID]map[bluetooth.UUID]*bluetooth.Characteristic
}

func NewHostBLE(srv *server.Server) *HostBLE {
	return &HostBLE{
		srv:   srv,
		chars: map[bluetooth.UUID]map[bluetooth.UUID]*bluetooth.Characteristic{},
	}
}

func (h *HostBLE) Start() error {
	err := adapter.Enable()
	if err != nil {
		return fmt.Errorf("start adapter: %w", err)
	}

	adapter.SetConnectHandler(func(device bluetooth.Device, connected bool) {
		if connected {
			println("device connected:", device.Address.String())
		} else {
			println("device disconnected:", device.Address.String())
		}
	})

	adv := adapter.DefaultAdvertisement()
	adv.Configure(bluetooth.AdvertisementOptions{
		LocalName: "InfiniTime Emulator",
	})

	services, err := h.srv.ListServices()
	if err != nil {
		return fmt.Errorf("list emulated services: %w", err)
	}
	h.services = services

	err = adv.Start()
	if err != nil {
		return fmt.Errorf("start advertising: %w", err)
	}
	defer adv.Stop()

	for _, svc := range services {
		svcUUID := convertUUID(svc.UUID)

		h.chars[svcUUID] = map[bluetooth.UUID]*bluetooth.Characteristic{}

		chars := make([]bluetooth.CharacteristicConfig, len(svc.Characteristics))

		println(svcUUID.String())

		for i, char := range svc.Characteristics {
			charUUID := convertUUID(char.UUID)

			handle := new(bluetooth.Characteristic)

			println("  " + charUUID.String())

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

		adapter.AddService(&bluetooth.Service{
			UUID:            svcUUID,
			Characteristics: chars,
		})
	}

	return nil
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
