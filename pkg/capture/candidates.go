// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"debug/elf"
	"debug/gosym"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	goTLSWriteSymbol = "crypto/tls.(*Conn).Write"
	goTLSReadSymbol  = "crypto/tls.(*Conn).Read"
	sslWriteSymbol   = "SSL_write"
	sslReadSymbol    = "SSL_read"
)

type tlsFlavour uint8

const (
	tlsNone tlsFlavour = iota
	tlsGo
	tlsGeneric
)

func classify(procFS string, pid int32, exePath string) tlsFlavour {
	if hasGoTLSSymbols(exePath) {
		return tlsGo
	}
	if mapsLibSSL(procFS, pid) {
		return tlsGeneric
	}
	return tlsNone
}

func hasGoTLSSymbols(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err == nil {
		return elfHasAll(syms, goTLSWriteSymbol, goTLSReadSymbol)
	}
	// Stripped Go executables retain the runtime function table.
	text := f.Section(".text")
	pcln := f.Section(".gopclntab")
	if pcln == nil {
		pcln = f.Section(".data.rel.ro.gopclntab")
	}
	if text == nil || pcln == nil {
		return false
	}
	data, err := pcln.Data()
	if err != nil {
		return false
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	return err == nil && table.LookupFunc(goTLSWriteSymbol) != nil && table.LookupFunc(goTLSReadSymbol) != nil
}

func mapsLibSSL(procFS string, pid int32) bool {
	maps, err := os.ReadFile(filepath.Join(procFS, strconv.Itoa(int(pid)), "maps"))
	if err != nil {
		return false
	}

	seen := make(map[string]struct{})
	for line := range strings.SplitSeq(string(maps), "\n") {
		path, ok := mappedLibSSL(line)
		if !ok {
			continue
		}
		if _, dup := seen[path]; dup {
			continue // one library maps at several address ranges
		}
		seen[path] = struct{}{}

		if hasSSLSymbols(filepath.Join(procFS, strconv.Itoa(int(pid)), "root", path)) {
			return true
		}
	}
	return false
}

func mappedLibSSL(line string) (string, bool) {
	i := strings.IndexByte(line, '/')
	if i < 0 {
		return "", false
	}
	path := strings.TrimRight(line[i:], " \t")
	if strings.HasSuffix(path, " (deleted)") {
		return "", false
	}
	if !strings.HasPrefix(filepath.Base(path), "libssl.so") {
		return "", false
	}
	return path, true
}

func hasSSLSymbols(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	syms, err := f.DynamicSymbols()
	if err != nil {
		return false // no .dynsym: not a shared library
	}
	return elfHasAll(syms, sslWriteSymbol, sslReadSymbol)
}

func elfHasAll(syms []elf.Symbol, want ...string) bool {
	found := make(map[string]struct{}, len(want))
	for _, s := range syms {
		for _, w := range want {
			if s.Name == w {
				found[w] = struct{}{}
			}
		}
	}
	return len(found) == len(want)
}
