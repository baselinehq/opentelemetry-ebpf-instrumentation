// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package goexec helps analyzing Go executables
package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type Offsets struct {
	// Funcs key: requested function name. Each value contains every resolved
	// canonical or vendored copy of that function.
	Funcs  map[string][]FuncOffsets
	Field  FieldOffsets
	ITypes map[string]uint64
}

type FuncOffsets struct {
	Symbol      string
	Start       uint64
	Returns     []uint64
	CallTargets []uint64
	PadStart    uint64
	PadOffset   uint64
}

type FieldOffsets map[GoOffset]any

// HasGoChannelOffsets reports whether all runtime.hchan offsets needed for Go channel
// span linking are available for an inspected executable.
func (o *Offsets) HasGoChannelOffsets() bool {
	if o == nil {
		return false
	}

	for _, field := range []GoOffset{
		HchanQcountPos,
		HchanDataqsizPos,
		HchanSendxPos,
		HchanRecvxPos,
	} {
		if _, ok := o.Field[field].(uint64); !ok {
			return false
		}
	}

	return true
}

// SupportsGoAutoSDKActivation reports whether an inspected executable has a
// supported ABI and every offset needed for Go Auto SDK span integration.
func (o *Offsets) SupportsGoAutoSDKActivation() bool {
	if o == nil {
		return false
	}
	if supported, ok := o.Field[AutoSDKActivationSupported].(uint64); !ok || supported != 1 {
		return false
	}

	for _, field := range []GoOffset{
		SpanContextTraceIDPos,
		SpanContextSpanIDPos,
		SpanContextTraceFlagsPos,
		AutoSDKSpanContextPos,
	} {
		if _, ok := o.Field[field].(uint64); !ok {
			return false
		}
	}

	return true
}

// InspectOffsets gets the memory addresses/offsets of the instrumenting function, as well as the required
// parameters fields to be read from the eBPF code
func InspectOffsets(execElf *exec.FileInfo, funcs []string) (*Offsets, error) {
	if execElf == nil {
		return nil, errors.New("executable not found")
	}
	return NewInspector(execElf.ELF()).inspectOffsets(funcs, structMembers, nil)
}

// InspectHTTPOffsets retains the layout and interface metadata used by HTTP/TLS
// probes without inspecting unrelated protocol, SDK or runtime-metric fields.
func InspectHTTPOffsets(execElf *exec.FileInfo, funcs []string) (*Offsets, error) {
	if execElf == nil {
		return nil, errors.New("executable not found")
	}
	return NewInspector(execElf.ELF()).InspectHTTPOffsets(funcs)
}

// InspectHTTPOffsets reuses metadata loaded while classifying this executable.
func (i *Inspector) InspectHTTPOffsets(funcs []string) (*Offsets, error) {
	members := map[string]structInfo{}
	for name, member := range structMembers {
		if strings.HasPrefix(name, "net/http.") || strings.HasPrefix(name, "net/http/") ||
			strings.HasPrefix(name, "golang.org/x/net/http2.") || strings.HasPrefix(name, "net.") ||
			strings.HasPrefix(name, "net/url.") || strings.HasPrefix(name, "net/textproto.") ||
			strings.HasPrefix(name, "bufio.") {
			members[name] = member
		}
	}
	return i.inspectOffsets(funcs, members, []string{"*crypto/tls.Conn", "*errors.errorString"})
}

func (i *Inspector) inspectOffsets(funcs []string, members map[string]structInfo, interfaceTypes []string) (*Offsets, error) {
	if i.file == nil {
		return nil, errors.New("executable not found")
	}

	defer func() {
		i.dwarf = sync.OnceValues(i.file.DWARF)
		i.abis = nil
	}()

	// Analyze executable ELF file and find instrumentation points
	found, err := i.instrumentationPoints(funcs)
	i.goSymbols = sync.OnceValues(i.findGoSymbolTable)
	if err != nil {
		return nil, fmt.Errorf("finding instrumentation points: %w", err)
	}
	if len(found) == 0 {
		return nil, errors.New("couldn't find any instrumentation point")
	}

	itypes, err := i.findInterfaceImpls(interfaceTypes...)
	i.symbols = sync.OnceValues(i.readSymbols)
	if err != nil {
		slog.Warn("error reading itab section in Go program, manual spans will not work", "error", err)
	}

	// Release function/symbol tables before walking struct layouts. Only DWARF
	// is shared with this final stage; retaining all tables raises peak RSS.
	structFieldOffsets, err := i.structMemberOffsetsFor(members)
	if err != nil {
		return nil, fmt.Errorf("checking struct members: %w", err)
	}

	return &Offsets{
		Funcs:  found,
		Field:  structFieldOffsets,
		ITypes: itypes,
	}, nil
}
