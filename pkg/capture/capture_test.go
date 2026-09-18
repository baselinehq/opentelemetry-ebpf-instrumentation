// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import "testing"

func TestCaptureConfigAllowsReaderProgress(t *testing.T) {
	cfg, err := buildConfig([]string{"x-costgraph-*"})
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.EBPF.TLSHTTP2Capture {
		t.Fatal("capture requires complete HTTP/2 client messages")
	}

	// SharedRingbuf allocates its record pool from BatchLength. Zero leaves
	// the reader waiting on an empty free-slot channel before its first read.
	if cfg.EBPF.BatchLength <= 0 {
		t.Errorf("BatchLength = %d: ring-buffer reader has no record slots", cfg.EBPF.BatchLength)
	}
	// A quiet workload must emit its partial batch without waiting for more
	// requests to fill it. This is separate from the kernel ring-buffer flush.
	if cfg.EBPF.BatchTimeout <= 0 {
		t.Errorf("BatchTimeout = %v: partial span batches never flush", cfg.EBPF.BatchTimeout)
	}
}
