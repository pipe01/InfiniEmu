package main

import (
	"debug/elf"
	"fmt"
	"io"

	"github.com/ianlancetaylor/demangle"
)

type Section struct {
	Start uint32
	Data  []byte
}

type SymbolType byte

const (
	SymbolTypeObject SymbolType = iota + 1
	SymbolTypeFunction
)

type Symbol struct {
	Name, PrettyName string
	Start, Length    uint32
	Type             SymbolType
}

type Program struct {
	FilePath string // only used to allow GDB to load the program from disk and can thus be left empty
	Sections []Section
	Symbols  map[string]Symbol
}

func (p *Program) Flatten() []byte {
	var maxSize uint32

	for _, section := range p.Sections {
		end := section.Start + uint32(len(section.Data))
		if end > maxSize {
			maxSize = end
		}
	}

	flash := make([]byte, maxSize)

	for _, section := range p.Sections {
		copy(flash[section.Start:], section.Data)
	}

	return flash
}

func LoadELF(r io.ReaderAt, loadSymbols bool) (*Program, error) {
	p := Program{
		Symbols: make(map[string]Symbol),
	}

	elff, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("open elf file: %w", err)
	}
	defer elff.Close()

	for i, sec := range elff.Progs {
		start := sec.Paddr

		mem := make([]byte, sec.Memsz)

		data, err := io.ReadAll(sec.Open())
		if err != nil {
			return nil, fmt.Errorf("read section %d: %w", i, err)
		}

		copy(mem, data)

		p.Sections = append(p.Sections, Section{
			Start: uint32(start),
			Data:  mem,
		})
	}

	if loadSymbols {
		sym, err := elff.Symbols()
		if err != nil {
			return nil, fmt.Errorf("load symbols: %w", err)
		}

		for _, s := range sym {
			symType := SymbolType(s.Info & 0xf)
			if symType != SymbolTypeObject && symType != SymbolTypeFunction {
				continue
			}

			pretty, err := demangle.ToString(s.Name)
			if err != nil {
				pretty = s.Name
			}

			p.Symbols[s.Name] = Symbol{
				Name:       s.Name,
				PrettyName: pretty,
				Start:      uint32(s.Value),
				Length:     uint32(s.Size),
				Type:       SymbolType(symType),
			}
		}
	}

	return &p, nil
}

func LoadBinary(r io.Reader) (*Program, error) {
	p, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return &Program{
		Sections: []Section{
			{
				Start: 0,
				Data:  p,
			},
		},
	}, nil
}
