// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"context"
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const scanInterval = 30 * time.Second

const channelBufferLen = 100

const maxCapturedBytes = 256 << 10

type Capture struct {
	procFS string

	tracer  *obiebpf.ProcessTracer
	events  *ebpfcommon.EBPFEventContext
	spans   *msg.Queue[[]request.Span]
	records chan []Exchange

	mu      sync.Mutex
	seen    map[inodeKey]*obiebpf.Instrumentable
	allowed map[int32]allowedProcess
	goTLS   map[executableID]bool

	closeOnce sync.Once
}

type inodeKey struct{ dev, ino uint64 }

type allowedProcess struct {
	key   inodeKey
	ns    uint32
	start string
}

type Options struct {
	ProcFSPath string

	HeaderPrefixes []string
}

func New(opts Options) (*Capture, error) {
	if opts.ProcFSPath == "" {
		return nil, fmt.Errorf("obicapture: no procfs path")
	}

	cfg, err := buildConfig(opts.HeaderPrefixes)
	if err != nil {
		return nil, err
	}

	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(channelBufferLen))

	discovery := &services.DiscoveryConfig{BPFPidFilterOff: cfg.Discovery.BPFPidFilterOff}
	pidFilter := ebpfcommon.NewPIDsFilter(discovery, slog.Default(), imetrics.NoopReporter{})

	programs := []obiebpf.Tracer{
		&httpGoTracer{gotracer.New(pidFilter, cfg, imetrics.NoopReporter{})},
		&sslTracer{generictracer.New(pidFilter, cfg, imetrics.NoopReporter{})},
	}

	tracer := obiebpf.NewProcessTracer(obiebpf.Generic, programs, cfg, imetrics.NoopReporter{})
	events := ebpfcommon.NewEBPFEventContext()

	if err := tracer.Init(events, cfg); err != nil {
		return nil, fmt.Errorf("obicapture: loading eBPF programs: %w", err)
	}

	return &Capture{
		procFS:  opts.ProcFSPath,
		tracer:  tracer,
		events:  events,
		spans:   spans,
		records: make(chan []Exchange, channelBufferLen),
		seen:    make(map[inodeKey]*obiebpf.Instrumentable),
		allowed: make(map[int32]allowedProcess),
		goTLS:   make(map[executableID]bool),
	}, nil
}

func buildConfig(headerPrefixes []string) (*obi.Config, error) {
	cfg := &obi.Config{}
	// BatchLength also sizes the reader pool; zero deadlocks before the first read.
	cfg.EBPF.BatchLength = 100
	cfg.EBPF.BatchTimeout = time.Second

	cfg.EBPF.BPFFSPath = "/sys/fs/bpf/"
	cfg.EBPF.BufferSizes.HTTP = maxCapturedBytes
	cfg.EBPF.TLSHTTP2Capture = true

	const protocolCacheSize = 1024
	cfg.EBPF.MySQLPreparedStatementsCacheSize = protocolCacheSize
	cfg.EBPF.PostgresPreparedStatementsCacheSize = protocolCacheSize
	cfg.EBPF.MSSQLPreparedStatementsCacheSize = protocolCacheSize
	cfg.EBPF.MongoRequestsCacheSize = protocolCacheSize
	cfg.EBPF.KafkaTopicUUIDCacheSize = protocolCacheSize
	cfg.EBPF.CouchbaseDBCacheSize = protocolCacheSize
	// Observe traffic without injecting headers.
	cfg.EBPF.ContextPropagation = config.ContextPropagationDisabled
	cfg.EBPF.MaxTransactionTime = 2 * time.Minute
	cfg.EBPF.HTTPRequestTimeout = 30 * time.Second
	cfg.EBPF.GoHTTPClientBufferTimeout = 5 * time.Second
	cfg.ShutdownTimeout = 10 * time.Second

	rules, err := headerRules(headerPrefixes)
	if err != nil {
		return nil, err
	}
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment = config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
		},
		Rules: rules,
	}

	return cfg, nil
}

// Exchanges returns the single-consumer stream. Drain it while Run executes.
func (c *Capture) Exchanges() <-chan []Exchange { return c.records }

// Run discovers processes before the tracers initialize their PID filters.
func (c *Capture) Run(ctx context.Context) {
	spans := c.spans.Subscribe()
	forwardCtx, stopForward := context.WithCancel(ctx)
	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		defer close(c.records)
		forwardExchanges(forwardCtx, spans, c.records)
	}()
	defer func() { stopForward(); <-forwardDone }()

	if ctx.Err() == nil {
		c.Scan()
	}
	// Stop discovery before tracer teardown closes maps and executable links.
	tracerCtx, stopTracer := context.WithCancel(context.WithoutCancel(ctx))
	defer stopTracer()
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		defer stopTracer()
		ticker := time.NewTicker(scanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Scan()
			}
		}
	}()
	c.tracer.Run(tracerCtx, c.events, c.spans)
	<-scanDone
}

func (c *Capture) Scan() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid, process := range c.allowed {
		if processStartTime(c.procFS, uint32(pid)) != process.start {
			c.tracer.BlockPID(app.PID(pid), process.ns)
			delete(c.allowed, pid)
		}
	}
	pids, err := c.pids()
	if err != nil {
		slog.Debug("obicapture: cannot read procfs", "error", err)
		return 0
	}

	live := make(map[executableID]struct{})
	attached := 0
	for _, pid := range pids {
		ok, err := c.attachPID(pid, live)
		if err != nil {
			slog.Debug("obicapture: skipping process", "pid", pid, "error", err)
			continue
		}
		if ok {
			attached++
		}
	}
	for id := range c.goTLS {
		if _, ok := live[id]; !ok {
			delete(c.goTLS, id)
		}
	}
	allowedPIDs := len(c.allowed)
	attachedInodes := len(c.seen)
	slog.Debug("obicapture: procfs scan complete", "scanned", len(pids), "newly_attached", attached,
		"allowed_pids", allowedPIDs, "known_inodes", attachedInodes)
	active := make(map[inodeKey]bool, len(c.allowed))
	for _, process := range c.allowed {
		active[process.key] = true
	}
	for key, inst := range c.seen {
		if !active[key] {
			c.tracer.UnlinkExecutable(inst.FileInfo, inst.ExecutableGeneration)
			delete(c.seen, key)
		}
	}
	return attached
}

func (c *Capture) attachPID(pid int32, live map[executableID]struct{}) (bool, error) {
	exePath := filepath.Join(c.procFS, strconv.Itoa(int(pid)), "exe")

	st, err := os.Stat(exePath)
	if err != nil {
		return false, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("unexpected stat type")
	}
	key := inodeKey{dev: uint64(sys.Dev), ino: sys.Ino}
	id := executableIdentity(sys)
	live[id] = struct{}{}

	existing, inodeKnown := c.seen[key]
	process, pidKnown := c.allowed[pid]
	if inodeKnown && pidKnown && process.key == key {
		return false, nil
	}

	flavour := classify(c.procFS, pid, exePath, id, c.goTLS)
	if flavour == tlsNone {
		return false, nil
	}

	elfFile, err := elf.Open(exePath)
	if err != nil {
		return false, nil //nolint:nilerr // not a candidate, not an error
	}
	defer elfFile.Close()

	ns, err := procs.FindNamespace(app.PID(pid))
	if err != nil {
		return false, err
	}

	fileInfo := exec.New(exec.Init{
		CmdExePath:     exePath,
		ProExeLinkPath: exePath,
		ELF:            elfFile,
		Pid:            app.PID(pid),
		Dev:            key.dev,
		Ino:            key.ino,
		Ns:             ns,
	})

	inst := &obiebpf.Instrumentable{
		FileInfo: fileInfo,
		Tracer:   c.tracer,
		Type:     svc.InstrumentableGeneric,
	}

	if flavour == tlsGo {
		var offsets *goexec.Offsets
		var offErr error
		if inodeKnown {
			offsets = existing.Offsets
		} else {
			offsets, offErr = goexec.InspectHTTPOffsets(fileInfo, goFunctions(c.tracer))
		}
		if offErr != nil {
			slog.Debug("obicapture: crypto/tls present but offsets unreadable; skipping", "exe", exePath, "error", offErr)
			return false, nil
		}
		inst.Type = svc.InstrumentableGolang
		inst.Offsets = offsets
	}

	inst.CopyToServiceAttributes()

	if !inodeKnown {
		linkExe, err := link.OpenExecutable(exePath)
		if err != nil {
			return false, fmt.Errorf("opening %s: %w", exePath, err)
		}
		if err := c.tracer.NewExecutable(linkExe, inst); err != nil {
			return false, fmt.Errorf("instrumenting %s: %w", exePath, err)
		}
	}
	if err := c.tracer.NewExecutableInstance(inst); err != nil {
		return false, fmt.Errorf("instrumenting instance of %s: %w", exePath, err)
	}

	c.tracer.AllowPID(app.PID(pid), ns, fileInfo)

	if !inodeKnown {
		c.seen[key] = inst
	}
	c.allowed[pid] = allowedProcess{key: key, ns: ns, start: processStartTime(c.procFS, uint32(pid))}
	return !inodeKnown, nil
}

func goFunctions(tracer *obiebpf.ProcessTracer) []string {
	var funcs []string
	for _, p := range tracer.Programs {
		for name := range p.GoProbes() {
			funcs = append(funcs, name)
		}
	}
	return funcs
}

func (c *Capture) pids() ([]int32, error) {
	entries, err := os.ReadDir(c.procFS)
	if err != nil {
		return nil, err
	}
	pids := make([]int32, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory
		}
		pids = append(pids, int32(n))
	}
	return pids, nil
}

func (c *Capture) Close() {
	c.closeOnce.Do(func() {
		c.spans.Close()
	})
}

func headerRules(prefixes []string) ([]config.HTTPParsingRule, error) {
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("obicapture: no header prefixes configured")
	}
	patterns := make([]services.GlobAttr, 0, len(prefixes))
	for _, p := range prefixes {
		patterns = append(patterns, services.NewGlob(p))
	}
	return []config.HTTPParsingRule{{
		Action: config.HTTPParsingActionInclude,
		Type:   config.HTTPParsingRuleTypeHeaders,
		Scope:  config.HTTPParsingScopeRequest,
		Match:  config.HTTPParsingMatch{Patterns: patterns},
	}}, nil
}
