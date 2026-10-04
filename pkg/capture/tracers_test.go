// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
)

func TestHTTPProbeSelection(t *testing.T) {
	for _, symbol := range []string{"crypto/tls.(*Conn).Read", "net.(*netFD).Close", "net/http.(*Transport).roundTrip", "runtime.newproc1", "net/http/internal/http2.(*ClientConn).RoundTrip"} {
		if !httpGoFunction(symbol) {
			t.Errorf("missing required HTTP probe %s", symbol)
		}
	}
	for _, symbol := range []string{"database/sql.(*DB).queryDC", "github.com/jackc/pgx/v5.(*Conn).Query", "runtime.mallocgc", "github.com/redis/go-redis/v9.(*Client).Process"} {
		if httpGoFunction(symbol) {
			t.Errorf("unrelated probe %s", symbol)
		}
	}
}

func TestCaptureMapSizes(t *testing.T) {
	const capacityBudget = 40 << 20
	for name, load := range map[string]func() (*ebpf.CollectionSpec, error){"go": gotracer.LoadBpf, "ssl": generictracer.LoadBpf} {
		t.Run(name, func(t *testing.T) {
			spec, err := load()
			if err != nil {
				t.Fatal(err)
			}
			before := spec.Copy()
			limitCaptureMaps(spec)
			var saved, capacity uint64
			for name, m := range spec.Maps {
				original := before.Maps[name]
				capacity += uint64(m.MaxEntries) * uint64(m.KeySize+m.ValueSize)
				if m.MaxEntries == original.MaxEntries {
					continue
				}
				trimmed := m.MaxEntries == 1 && (m.Type == ebpf.Hash || m.Type == ebpf.LRUHash)
				capped := m.MaxEntries == captureLRUMapMaxEntries && m.Type == ebpf.LRUHash
				if !trimmed && !capped {
					t.Fatalf("unexpected change to %s", name)
				}
				saved += uint64(original.MaxEntries-m.MaxEntries) * uint64(m.KeySize+m.ValueSize)
			}
			if capacity > capacityBudget {
				t.Fatalf("map key/value capacity %.1f MiB exceeds %.1f MiB", float64(capacity)/(1<<20), float64(capacityBudget)/(1<<20))
			}
			t.Logf("map key/value capacity %.1f MiB, reduced by %.1f MiB (excludes kernel overhead)", float64(capacity)/(1<<20), float64(saved)/(1<<20))
			for _, name := range []string{"ongoing_http", "ongoing_http2_grpc", "ongoing_tcp_req", "go_offsets_map", "handled_by_go_conn", "events", "costgraph_h2_connections", "ssl_to_conn"} {
				original := before.Maps[name]
				if original == nil {
					continue
				}
				want := original.Copy()
				if want.Type == ebpf.LRUHash {
					want.MaxEntries = min(want.MaxEntries, captureLRUMapMaxEntries)
				}
				if !reflect.DeepEqual(want, spec.Maps[name]) {
					t.Errorf("required capture map %s was changed beyond the LRU cap", name)
				}
			}
		})
	}
}
