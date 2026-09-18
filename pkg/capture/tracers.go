// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"strings"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
)

// Keep OBI's HTTP/TLS hooks and their runtime dependencies; omit database,
// messaging and runtime-metrics hooks that do not contribute attribution.
type httpGoTracer struct{ *gotracer.Tracer }

func (t *httpGoTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	probes := t.Tracer.GoProbes()
	for name := range probes {
		if !httpGoFunction(name) {
			delete(probes, name)
		}
	}
	return probes
}

func httpGoFunction(name string) bool {
	switch name {
	case "runtime.newproc1", "runtime.casgstatus", "runtime.mstart1", "runtime.mexit":
		return true
	}
	for _, prefix := range []string{"net/http.", "net/http/", "golang.org/x/net/http2.", "net.(*netFD).", "crypto/tls."} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

type sslTracer struct{ *generictracer.Tracer }

func (t *sslTracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	probes := t.Tracer.UProbes()
	for library := range probes {
		if library != "libssl.so" {
			delete(probes, library)
		}
	}
	return probes
}

func (t *sslTracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc { return nil }
