package main

import (
	"fmt"

	"github.com/dop251/goja"
	"github.com/pipe01/InfiniEmu/tools/ble-client/js"
	"github.com/pipe01/InfiniEmu/tools/ble-client/js/services"
	"github.com/pipe01/InfiniEmu/tools/ble-client/server"
)

type PinePartnerScript struct {
	vm *goja.Runtime
}

func RunPinePartnerScript(script string, sv *server.Server, notifiers *[]services.Notifier, params map[string]any) (*PinePartnerScript, error) {
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())

	watches := &services.WatchesService{
		All: []services.Watch{
			{
				Server:    sv,
				Notifiers: notifiers,
			},
		},
	}

	modules := map[string]any{
		"watches": watches,
		"http":    services.HttpService{VM: vm},
	}

	vm.Set("require", js.NewRequire(vm, modules))
	vm.Set("console", js.NewConsole(vm))
	vm.Set("params", params)

	_, err := vm.RunString(script)
	if err != nil {
		return nil, fmt.Errorf("run script: %w", err)
	}

	return &PinePartnerScript{vm: vm}, nil
}
