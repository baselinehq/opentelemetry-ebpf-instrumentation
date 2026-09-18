// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import "testing"

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
