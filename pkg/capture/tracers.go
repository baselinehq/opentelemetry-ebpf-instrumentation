// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"strings"

	"github.com/cilium/ebpf"

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

func (t *httpGoTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	bundles, err := t.Tracer.LoadSpecs()
	for _, bundle := range bundles {
		limitNonHTTPMaps(bundle.Spec)
	}
	return bundles, err
}

func (t *sslTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	bundles, err := t.Tracer.LoadSpecs()
	for _, bundle := range bundles {
		limitNonHTTPMaps(bundle.Spec)
	}
	return bundles, err
}

func limitNonHTTPMaps(spec *ebpf.CollectionSpec) {
	// Generated bindings still require these maps. Keep a minimal allocation
	// for protocols/runtime hooks excluded from this HTTP-only adapter.
	for name, m := range spec.Maps {
		switch name {
		case "ongoing_sql_queries", "pq_hostnames",
			"ongoing_mongo_requests", "ongoing_redis_requests", "redis_writes",
			"produce_traceparents_by_goroutine", "produce_traceparents",
			"ongoing_produce_topics", "ongoing_produce_messages", "produce_requests",
			"fetch_requests", "kafka_requests", "ongoing_kafka_requests",
			"java_tasks", "java_vt_threads", "jvm_mem_pool_samples",
			"nodejs_fd_map", "python_context_task", "python_task_generation",
			"python_task_state", "python_thread_state", "python_runtime_metric_targets",
			"python_runtime_metric_snapshots", "puma_task_connections", "puma_worker_tasks",
			"nginx_upstream", "upstream_init_args", "obi_usdt_ip_to_spec_id", "obi_usdt_specs":
			if m.Type == ebpf.Hash || m.Type == ebpf.LRUHash {
				m.MaxEntries = 1
			}
		}
	}
}
