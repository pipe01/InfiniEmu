package services

import (
	"github.com/dop251/goja"
	"github.com/pipe01/InfiniEmu/tools/ble-client/server"
)

type Notifier = func(uint16, []byte)

type Watch struct {
	Server    *server.Server
	Notifiers *[]Notifier

	svcs []*server.Service
}

func (w *Watch) GetService(uuid string) any {
	if w.svcs == nil {
		var err error
		w.svcs, err = w.Server.ListServices()
		if err != nil {
			return nil
		}
	}

	for _, svc := range w.svcs {
		if svc.UUID.String() == uuid {
			return &Service{
				Service: *svc,
				w:       w,
			}
		}
	}

	return nil
}

type Service struct {
	server.Service

	w *Watch
}

func (svc *Service) GetCharacteristic(uuid string) *Characteristic {
	for _, ch := range svc.Characteristics {
		str := ch.UUID.String()
		if str == uuid {
			return &Characteristic{
				Characteristic: ch,
				w:              svc.w,
			}
		}
	}

	return nil
}

type Characteristic struct {
	server.Characteristic

	w *Watch
}

func (ch *Characteristic) Write(data []byte) {
	ch.w.Server.WriteAttribute(ch.Handle, data)
}

func (ch *Characteristic) AddEventListener(fc goja.FunctionCall, vm *goja.Runtime) goja.Value {
	if len(fc.Arguments) != 2 || fc.Arguments[0].String() != "notify" {
		return goja.Null()
	}

	cbFunc := fc.Arguments[1].Export().(func(goja.FunctionCall) goja.Value)

	*ch.w.Notifiers = append(*ch.w.Notifiers, func(handle uint16, v []byte) {
		if handle != ch.Handle {
			return
		}

		cbFunc(goja.FunctionCall{
			This: goja.Null(),
			Arguments: []goja.Value{
				vm.ToValue(v),
			},
		})
	})

	return goja.Null()
}

type WatchesService struct {
	All []Watch
}

func (w *WatchesService) AddEventListener(event string, cb goja.Value) {
}
