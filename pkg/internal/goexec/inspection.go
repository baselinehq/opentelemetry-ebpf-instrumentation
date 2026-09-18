// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"sync"

	"go.opentelemetry.io/obi/internal/goabi"
	"go.opentelemetry.io/obi/internal/goversion"
)

// Inspector shares parsed metadata during one executable inspection. It is not
// safe for concurrent use and must not be retained with the resulting Offsets.
// The caller owns the ELF file and must keep it open until inspection finishes.
type Inspector struct {
	file      *elf.File
	symbols   func() ([]elf.Symbol, error)
	dwarf     func() (*dwarf.Data, error)
	goSymbols func() (*gosym.Table, error)
	abis      map[goversion.Version]abiResult
}

type abiResult struct {
	abi goabi.ABI
	err error
}

func NewInspector(file *elf.File) *Inspector {
	i := &Inspector{file: file}
	i.symbols = sync.OnceValues(i.readSymbols)
	i.dwarf = sync.OnceValues(file.DWARF)
	i.goSymbols = sync.OnceValues(i.findGoSymbolTable)
	return i
}

// HasGoTLS checks for both TLS read and write functions, sharing metadata with
// subsequent offset inspection, including the runtime table in stripped binaries.
func (i *Inspector) HasGoTLS() (bool, error) {
	names := []string{"crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).Write"}
	symbols, err := i.symbols()
	if err == nil {
		found := make(map[string]bool, len(names))
		for _, symbol := range symbols {
			for _, name := range names {
				if symbol.Name == name {
					found[name] = true
				}
			}
		}
		for _, name := range names {
			if !found[name] {
				return false, nil
			}
		}
		return true, nil
	}
	if i.file.Section(".gopclntab") == nil && i.file.Section(".data.rel.ro.gopclntab") == nil {
		return false, nil
	}
	table, err := i.goSymbols()
	if err != nil {
		return false, err
	}
	for _, name := range names {
		if table.LookupFunc(name) == nil {
			return false, nil
		}
	}
	return true, nil
}

func (i *Inspector) readSymbols() ([]elf.Symbol, error) {
	symbols, err := i.file.Symbols()
	if err != nil {
		return nil, err
	}
	// Only these symbols are consumed by TLS classification, moduledata discovery
	// and interface inspection. Retaining the full table inflates peak memory.
	var needed []elf.Symbol
	for _, symbol := range symbols {
		if symbol.Name == "runtime.firstmoduledata" || isITabEntry(symbol.Name) ||
			symbol.Name == "crypto/tls.(*Conn).Read" || symbol.Name == "crypto/tls.(*Conn).Write" {
			needed = append(needed, symbol)
		}
	}
	return needed, nil
}
