package emulator

import (
	"debug/dwarf"
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
	FilePath  string // only used to allow GDB to load the program from disk and can thus be left empty
	Sections  []Section
	Symbols   map[string]Symbol
	Functions map[string]*Function
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

func (p *Program) GetFunctionAtPC(pc uint32) (*Function, bool) {
	for _, fn := range p.Functions {
		for _, def := range fn.Definitions {
			if pc >= def.StartPC && pc < def.EndPC {
				return fn, true
			}
		}
	}

	return nil, false
}

func (p *Program) GetPCAtFunction(name string) (uint32, bool) {
	fn, ok := p.Functions[name]
	if !ok {
		return 0, false
	}

	if len(fn.Definitions) == 0 {
		return 0, false
	}

	return fn.Definitions[0].StartPC, true
}

type SourceLocation struct {
	File         string
	Line, Column int
}

type FunctionDefinition struct {
	CompilationUnit *dwarf.Entry
	Entry           *dwarf.Entry
	Location        *SourceLocation
	StartPC, EndPC  uint32
}

type Function struct {
	Name        string
	Definitions []FunctionDefinition
	Declaration *dwarf.Entry

	DWARF *dwarf.Data
}

func (f *Function) GetLineAtPC(pc uint32) (*dwarf.LineEntry, bool) {
	for _, def := range f.Definitions {
		if pc < def.StartPC || pc > def.EndPC {
			continue
		}

		lr, err := f.DWARF.LineReader(def.CompilationUnit)
		if err != nil {
			return nil, false
		}

		var entry dwarf.LineEntry

		err = lr.SeekPC(uint64(pc), &entry)
		if err != nil {
			continue
		}

		return &entry, true
	}

	return nil, false
}

func getLocation(entry *dwarf.Entry, compUnit *dwarf.Entry, dw *dwarf.Data) (*SourceLocation, bool) {
	fileNum := entry.Val(dwarf.AttrDeclFile)
	if fileNum == nil {
		return nil, false
	}

	lr, err := dw.LineReader(compUnit)
	if err != nil {
		return nil, false
	}

	file := lr.Files()[fileNum.(int64)]

	var line int
	if v := entry.Val(dwarf.AttrDeclLine); v != nil {
		line = int(v.(int64))
	}

	var column int
	if v := entry.Val(dwarf.AttrDeclColumn); v != nil {
		column = int(v.(int64))
	}

	return &SourceLocation{
		File:   file.Name,
		Line:   line,
		Column: column,
	}, true
}

func loadFunctions(dw *dwarf.Data) (map[string]*Function, error) {
	reader := dw.Reader()

	subprograms := map[dwarf.Offset]*Function{}

	var currentCU *dwarf.Entry

	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("get next entry: %w", err)
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			currentCU = entry
		}

		if entry.Tag == dwarf.TagSubprogram {
			if entry.Val(dwarf.AttrInline) != nil {
				continue
			}

			name := entry.Val(dwarf.AttrName)
			isDeclaration, _ := entry.Val(dwarf.AttrDeclaration).(bool)

			if isDeclaration {
				if name != nil {
					subprograms[entry.Offset] = &Function{
						Name:        name.(string),
						Declaration: entry,
						DWARF:       dw,
					}
				}

				continue
			}

			var declOffset dwarf.Offset

			if name == nil {
				// Entry is only definition

				var ok bool
				declOffset, ok = entry.Val(dwarf.AttrSpecification).(dwarf.Offset)
				if !ok {
					continue
				}
			} else {
				declOffset = entry.Offset
			}

			r := dw.Reader()
			r.Seek(declOffset)

			decl, err := r.Next()
			if err != nil {
				return nil, fmt.Errorf("seek to declaration: %w", err)
			}

			defLocation, _ := getLocation(entry, currentCU, dw)

			var pcStart uint32
			if v := entry.Val(dwarf.AttrLowpc); v != nil {
				pcStart = uint32(v.(uint64))
			} else {
				continue
			}

			def := FunctionDefinition{
				CompilationUnit: currentCU,
				Entry:           entry,
				Location:        defLocation,
				StartPC:         pcStart,
				EndPC:           pcStart + uint32(entry.Val(dwarf.AttrHighpc).(int64)),
			}

			if sub, ok := subprograms[declOffset]; ok {
				sub.Definitions = append(sub.Definitions, def)
			} else {
				subprograms[declOffset] = &Function{
					Name:        name.(string),
					Definitions: []FunctionDefinition{def},
					Declaration: decl,
					DWARF:       dw,
				}
			}
		}
	}

	functions := map[string]*Function{}

	for _, sub := range subprograms {
		if len(sub.Definitions) > 0 {
			if fn, ok := functions[sub.Name]; ok {
				fn.Definitions = append(fn.Definitions, sub.Definitions...)
			} else {
				functions[sub.Name] = sub
			}
		}
	}

	return functions, nil
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
		dw, err := elff.DWARF()
		if err == nil {
			p.Functions, err = loadFunctions(dw)
			if err != nil {
				return nil, fmt.Errorf("load DWARF functions: %w", err)
			}
		} else {
			fmt.Printf("failed to load DWARF data: %v\n", err)
		}

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
