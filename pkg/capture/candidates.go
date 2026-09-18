// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"debug/elf"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	sslWriteSymbol = "SSL_write"
	sslReadSymbol  = "SSL_read"
)

type tlsFlavour uint8

const (
	tlsNone tlsFlavour = iota
	tlsGo
	tlsGeneric
)

type executableID struct {
	inodeKey
	size, modified, changed int64
}

func executableIdentity(st *syscall.Stat_t) executableID {
	return executableID{inodeKey{uint64(st.Dev), st.Ino}, st.Size, st.Mtim.Nano(), st.Ctim.Nano()}
}

func classify(procFS string, pid int32, id executableID, cache map[executableID]bool, hasGoTLS func() (bool, error)) tlsFlavour {
	goTLS, known := cache[id]
	if !known {
		var err error
		goTLS, err = hasGoTLS()
		if err == nil {
			cache[id] = goTLS
		}
	}
	if goTLS {
		return tlsGo
	}
	// Libraries can be loaded after the executable was first inspected.
	if mapsLibSSL(procFS, pid) {
		return tlsGeneric
	}
	return tlsNone
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
