// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture // import "go.opentelemetry.io/obi/pkg/capture"

import (
	"strings"

	"github.com/cilium/ebpf"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
)

// Keep OBI's HTTP/TLS, database and messaging client hooks and their runtime
// dependencies; omit framework and runtime-metrics hooks.
type captureGoTracer struct {
	*gotracer.Tracer
	protocolMapEntries uint32
}

func (t *captureGoTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	probes := t.Tracer.GoProbes()
	for name := range probes {
		if !captureGoFunction(name) {
			delete(probes, name)
		}
	}
	return probes
}

var captureGoPrefixes = []string{
	"net/http.", "net/http/", "golang.org/x/net/http2.", "net.(*netFD).", "crypto/tls.",
	"database/sql.", "github.com/lib/pq.", "github.com/jackc/pgx/", "*github.com/go-sql-driver/mysql.", "github.com/go-sql-driver/mysql.",
	"github.com/redis/go-redis/",
	"github.com/segmentio/kafka-go", "github.com/IBM/sarama.", "github.com/Shopify/sarama.",
	"go.mongodb.org/mongo-driver/",
}

func captureGoFunction(name string) bool {
	switch name {
	case "runtime.newproc1", "runtime.casgstatus", "runtime.mstart1", "runtime.mexit":
		return true
	}
	for _, prefix := range captureGoPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

type sslTracer struct {
	*generictracer.Tracer
	protocolMapEntries uint32
}

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

const captureLRUMapMaxEntries = 4096

func (t *captureGoTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	bundles, err := t.Tracer.LoadSpecs()
	for _, bundle := range bundles {
		limitCaptureMaps(bundle.Spec, t.protocolMapEntries)
	}
	return bundles, err
}

func (t *sslTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	bundles, err := t.Tracer.LoadSpecs()
	for _, bundle := range bundles {
		limitCaptureMaps(bundle.Spec, t.protocolMapEntries)
	}
	return bundles, err
}

func limitCaptureMaps(spec *ebpf.CollectionSpec, protocolMapEntries uint32) {
	limitUnusedMaps(spec)
	limitProtocolMaps(spec, protocolMapEntries)
	capLRUMaps(spec)
}

func capLRUMaps(spec *ebpf.CollectionSpec) {
	for _, m := range spec.Maps {
		if m.Type == ebpf.LRUHash && m.Pinning != ebpf.PinByName && m.MaxEntries > captureLRUMapMaxEntries {
			m.MaxEntries = captureLRUMapMaxEntries
		}
	}
}

var protocolMaps = map[string]struct{}{
	"ongoing_sql_queries": {}, "pq_hostnames": {},
	"ongoing_mongo_requests": {}, "ongoing_redis_requests": {}, "redis_writes": {},
	"ongoing_produce_topics": {}, "ongoing_produce_messages": {}, "produce_requests": {},
	"fetch_requests": {}, "kafka_requests": {}, "ongoing_kafka_requests": {},
}

func limitProtocolMaps(spec *ebpf.CollectionSpec, entries uint32) {
	for name, m := range spec.Maps {
		if _, ok := protocolMaps[name]; ok && (m.Type == ebpf.Hash || m.Type == ebpf.LRUHash) && m.MaxEntries > entries {
			m.MaxEntries = entries
		}
	}
}

func limitUnusedMaps(spec *ebpf.CollectionSpec) {
	// Generated bindings still require these maps. Keep a minimal allocation
	// for runtime hooks excluded from this adapter.
	for name, m := range spec.Maps {
		switch name {
		case "produce_traceparents_by_goroutine", "produce_traceparents",
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
