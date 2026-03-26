package js

import (
	"github.com/dop251/goja"
)

func NewRequire(vm *goja.Runtime, modules map[string]any) goja.Value {
	return vm.ToValue(func(module string) any {
		return modules[module]
	})
}
