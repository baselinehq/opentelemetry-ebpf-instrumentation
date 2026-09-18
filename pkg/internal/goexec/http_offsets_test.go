// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/tools"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

var httpInspectionFunctions = []string{
	"net/http.(*conn).serve", "net/http.(*Transport).roundTrip",
	"crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).Write", "runtime.newproc1",
}

func TestInspectHTTPOffsets(t *testing.T) {
	for _, stripped := range []bool{false, true} {
		name := "debug"
		var args []string
		if stripped {
			name = "stripped"
			args = []string{"-ldflags", "-s -w"}
		}
		t.Run(name, func(t *testing.T) {
			f := compileELF(tools.ProjectDir()+"/internal/test/cmd/pingserver/server.go", args...)
			defer f.Close()
			info := exec.New(exec.Init{ELF: f})
			full, err := InspectOffsets(info, httpInspectionFunctions)
			require.NoError(t, err)
			got, err := InspectHTTPOffsets(info, httpInspectionFunctions)
			require.NoError(t, err)
			require.Equal(t, full.Funcs, got.Funcs)
			for _, field := range []GoOffset{
				ConnFdPos, FdLaddrPos, FdRaddrPos, TCPAddrPortPtrPos, TCPAddrIPPtrPos,
				URLPtrPos, PathPtrPos, MethodPtrPos, ContentLengthPtrPos, ReqHeaderPtrPos,
				PcConnPos, PcTLSPos, NetConnPos, CRwcPos, CTlsPos,
				IoWriterBufPtrPos, IoWriterNPos, IoWriterWrPos,
				CcNextStreamIDVendoredPos, CcFramerVendoredPos, CcTconnVendoredPos, CcTLSVendoredPos,
				FramerWPos, MetaHeadersFrameFieldsPtrPos,
			} {
				require.Contains(t, full.Field, field)
				require.Equal(t, full.Field[field], got.Field[field], "HTTP field %d", field)
			}
			for field, value := range got.Field {
				// The upstream prefetched table shares this slot across x/net and
				// pre/post-Go-1.27 serverConn layouts; map iteration chooses the winner.
				// Compare its DWARF value only. Live tests exercise capture on stripped binaries.
				if stripped && field == ScConnPos {
					continue
				}
				require.Equal(t, full.Field[field], value, "field %d", field)
			}
			require.Contains(t, got.Field, ScConnPos)
			expectedTypes := map[string]uint64{}
			for _, name := range []string{"*crypto/tls.Conn", "*errors.errorString"} {
				if address, found := full.ITypes[name]; found {
					expectedTypes[name] = address
				}
			}
			// Stripped binaries before Go 1.27 do not expose these itab identities.
			require.Equal(t, expectedTypes, got.ITypes)
			if !stripped {
				require.Len(t, got.ITypes, 2)
			}
			require.NotContains(t, got.Field, RuntimeMemstatsNumGCPos)
			require.NotContains(t, got.Field, SpanContextTraceIDPos)
			require.NotContains(t, got.Field, GrpcStreamMethodPtrPos)
		})
	}
	_, err := InspectHTTPOffsets(nil, nil)
	require.Error(t, err)
	_, err = InspectHTTPOffsets(exec.New(exec.Init{ELF: smallELF}), []string{"missing.function"})
	require.Error(t, err)
}

func BenchmarkInspectOffsets(b *testing.B) {
	f := smallELF
	if path := os.Getenv("OBI_INSPECT_BENCH_EXE"); path != "" {
		var err error
		f, err = elf.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		defer f.Close()
	}
	info := exec.New(exec.Init{ELF: f})
	for name, inspect := range map[string]func(*exec.FileInfo, []string) (*Offsets, error){
		"full": InspectOffsets, "http": InspectHTTPOffsets,
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := inspect(info, httpInspectionFunctions); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
