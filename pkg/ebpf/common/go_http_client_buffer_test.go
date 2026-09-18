// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestPendingGoHTTPClientRequestExpiresAfterIdleTimeout(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	cfg.GoHTTPClientBufferTimeout = 20 * time.Millisecond
	parseCtx, emitted := newGoHTTPClientTestParseContext(t, cfg, 1)

	trace := pendingGoHTTPClientTrace(goHTTPClientTestConnection(), 1, "/idle")
	parseCtx.pendingGoHTTPClientRequests.Add(
		goHTTPClientConnectionKey(trace.Conn, trace.Tp.TraceId),
		&pendingGoHTTPClientRequest{trace: trace, createdAt: time.Now()},
	)

	select {
	case batch := <-emitted:
		require.Len(t, batch, 1)
		assert.Equal(t, "/idle", batch[0].Path)
	case <-time.After(time.Second):
		t.Fatal("pending Go HTTP client request did not expire")
	}
}

func TestPendingGoHTTPClientRequestHonorsMaxTransactionTime(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	cfg.MaxTransactionTime = time.Second
	parseCtx, emitted := newGoHTTPClientTestParseContext(t, cfg, 1)

	trace := pendingGoHTTPClientTrace(goHTTPClientTestConnection(), 1, "/maximum")
	key := goHTTPClientConnectionKey(trace.Conn, trace.Tp.TraceId)
	parseCtx.pendingGoHTTPClientRequests.Add(key, &pendingGoHTTPClientRequest{
		trace:     trace,
		createdAt: time.Now().Add(-2 * cfg.MaxTransactionTime),
	})
	parseCtx.refreshPendingGoHTTPClientRequest(trace.Conn, trace.Tp.TraceId)

	select {
	case batch := <-emitted:
		require.Len(t, batch, 1)
		assert.Equal(t, "/maximum", batch[0].Path)
	case <-time.After(time.Second):
		t.Fatal("maximum pending time did not flush the request")
	}
}

func TestPendingGoHTTPClientRequestsEvictAtCapacity(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	parseCtx, emitted := newGoHTTPClientTestParseContext(t, cfg, 1)

	for i := range maxPendingGoHTTPClientRequests + 1 {
		conn := goHTTPClientTestConnection()
		conn.S_port += uint16(i)
		trace := pendingGoHTTPClientTrace(conn, byte(i), "/capacity")
		trace.Status = uint16(i)
		parseCtx.pendingGoHTTPClientRequests.Add(
			goHTTPClientConnectionKey(conn, trace.Tp.TraceId),
			&pendingGoHTTPClientRequest{trace: trace, createdAt: time.Now()},
		)
	}

	assert.Equal(t, maxPendingGoHTTPClientRequests, parseCtx.pendingGoHTTPClientRequests.Len())
	select {
	case batch := <-emitted:
		require.Len(t, batch, 1)
		assert.Equal(t, 0, batch[0].Status)
	case <-time.After(time.Second):
		t.Fatal("capacity eviction did not flush the oldest request")
	}
}

func TestPendingGoHTTPClientRequestsClosePurgesWithoutFlushing(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	emitted := spans.Subscribe()
	parseCtx := NewEBPFParseContext(&cfg, spans, nil)

	trace := pendingGoHTTPClientTrace(goHTTPClientTestConnection(), 1, "/close")
	parseCtx.pendingGoHTTPClientRequests.Add(
		goHTTPClientConnectionKey(trace.Conn, trace.Tp.TraceId),
		&pendingGoHTTPClientRequest{trace: trace, createdAt: time.Now()},
	)
	parseCtx.Close()

	assert.Zero(t, parseCtx.pendingGoHTTPClientRequests.Len())
	select {
	case <-emitted:
		t.Fatal("closing the parse context flushed a pending request")
	default:
	}
}

func TestGoHTTPClientDeferralGates(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*config.EBPFTracer)
		withEmitter bool
		wantCache   bool
	}{
		{
			name:        "client extraction enabled",
			withEmitter: true,
			wantCache:   true,
		},
		{
			name: "GraphQL only",
			configure: func(cfg *config.EBPFTracer) {
				cfg.PayloadExtraction.HTTP.AWS.Enabled = false
				cfg.PayloadExtraction.HTTP.GraphQL.Enabled = true
			},
			withEmitter: true,
		},
		{
			name: "HTTP buffers disabled",
			configure: func(cfg *config.EBPFTracer) {
				cfg.BufferSizes.HTTP = 0
			},
			withEmitter: true,
		},
		{
			name: "timeout disabled",
			configure: func(cfg *config.EBPFTracer) {
				cfg.GoHTTPClientBufferTimeout = 0
			},
			withEmitter: true,
		},
		{
			name: "emitter missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := goHTTPClientTestConfig()
			if tt.configure != nil {
				tt.configure(&cfg)
			}

			var spans *msg.Queue[[]request.Span]
			if tt.withEmitter {
				spans = msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
			}

			parseCtx := NewEBPFParseContext(&cfg, spans, nil)
			t.Cleanup(parseCtx.Close)
			assert.Equal(t, tt.wantCache, parseCtx.pendingGoHTTPClientRequests != nil)
		})
	}
}

func TestGoHTTPClientEventWaitsForBuffersAndConnectionReuseFlushesIt(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	parseCtx, emitted := newGoHTTPClientTestParseContext(t, cfg, 2)

	conn := goHTTPClientTestConnection()
	first := pendingGoHTTPClientTrace(conn, 1, "/first")
	requestPayload := "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n"
	appendGoHTTPClientBuffer(t, parseCtx, conn, [16]uint8{}, packetTypeRequest, directionSend, requestPayload)

	span, ignore, err := ReadBPFTraceAsSpan(parseCtx, &cfg, goHTTPClientTraceRecord(t, first), nil)
	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Equal(t, request.Span{}, span)

	responsePayload := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	appendGoHTTPClientBuffer(t, parseCtx, conn, [16]uint8{}, packetTypeResponse, directionRecv, responsePayload)

	second := pendingGoHTTPClientTrace(conn, 2, "/second")
	secondSpan, ignore, err := ReadBPFTraceAsSpan(parseCtx, &cfg, goHTTPClientTraceRecord(t, second), nil)
	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, "/second", secondSpan.Path)

	select {
	case batch := <-emitted:
		require.Len(t, batch, 1)
		assert.Equal(t, "/first", batch[0].Path)
		assert.Equal(t, int64(first.StartMonotimeNs), batch[0].Start)
		assert.Equal(t, int64(first.EndMonotimeNs), batch[0].End)
	case <-time.After(time.Second):
		t.Fatal("connection reuse did not flush the previous request")
	}
}

func TestGoHTTP2ClientRequestsOnSameConnectionAreDeferredIndependently(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	parseCtx, emitted := newGoHTTPClientTestParseContext(t, cfg, 1)

	conn := goHTTPClientTestConnection()
	first := pendingGoHTTPClientTrace(conn, 1, "/first")
	second := pendingGoHTTPClientTrace(conn, 2, "/second")

	for _, trace := range []*HTTPRequestTrace{&first, &second} {
		appendGoHTTPClientBuffer(
			t, parseCtx, conn, trace.Tp.TraceId,
			packetTypeRequest, directionSend, "HTTP/2 request payload",
		)

		span, ignore, err := ReadBPFTraceAsSpan(parseCtx, &cfg, goHTTPClientTraceRecord(t, *trace), nil)
		require.NoError(t, err)
		assert.True(t, ignore)
		assert.Equal(t, request.Span{}, span)
	}

	assert.Equal(t, 2, parseCtx.pendingGoHTTPClientRequests.Len())
	select {
	case <-emitted:
		t.Fatal("a concurrent HTTP/2 request flushed another stream")
	default:
	}
}

func TestGoHTTPClientEventWithoutRequestBufferIsImmediate(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	parseCtx, _ := newGoHTTPClientTestParseContext(t, cfg, 1)

	trace := pendingGoHTTPClientTrace(goHTTPClientTestConnection(), 1, "/immediate")
	span, ignore, err := ReadBPFTraceAsSpan(parseCtx, &cfg, goHTTPClientTraceRecord(t, trace), nil)

	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, "/immediate", span.Path)
}

func TestOnlyGoResponseBuffersRefreshPendingHTTPClientRequests(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	cfg.GoHTTPClientBufferTimeout = 200 * time.Millisecond
	parseCtx, _ := newGoHTTPClientTestParseContext(t, cfg, 3)

	tests := []struct {
		name       string
		packetType uint8
		source     uint8
		wantActive bool
	}{
		{name: "kprobe response", packetType: packetTypeResponse, source: largeBufferSourceKProbes},
		{name: "Go request", packetType: packetTypeRequest, source: largeBufferSourceGo},
		{name: "Go response", packetType: packetTypeResponse, source: largeBufferSourceGo, wantActive: true},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := goHTTPClientTestConnection()
			conn.S_port += uint16(i)
			trace := pendingGoHTTPClientTrace(conn, byte(i+1), "/refresh")
			key := goHTTPClientConnectionKey(conn, trace.Tp.TraceId)
			parseCtx.pendingGoHTTPClientRequests.Add(key, &pendingGoHTTPClientRequest{
				trace:     trace,
				createdAt: time.Now(),
			})

			time.Sleep(100 * time.Millisecond)
			appendGoHTTPClientBufferWithSource(
				t, parseCtx, conn, trace.Tp.TraceId, tt.packetType,
				directionByPacketType(tt.packetType, true), tt.source, "buffer",
			)
			time.Sleep(120 * time.Millisecond)

			_, active := parseCtx.pendingGoHTTPClientRequests.Get(key)
			assert.Equal(t, tt.wantActive, active)
		})
	}
}

func newGoHTTPClientTestParseContext(
	t *testing.T,
	cfg config.EBPFTracer,
	queueSize int,
) (*EBPFParseContext, <-chan []request.Span) {
	t.Helper()

	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(queueSize))
	emitted := spans.Subscribe()
	parseCtx := NewEBPFParseContext(&cfg, spans, nil)
	t.Cleanup(parseCtx.Close)
	return parseCtx, emitted
}

func goHTTPClientTestConfig() config.EBPFTracer {
	return config.EBPFTracer{
		BufferSizes:               config.EBPFBufferSizes{HTTP: 1024},
		GoHTTPClientBufferTimeout: time.Hour,
		MaxTransactionTime:        2 * time.Hour,
		PayloadExtraction: config.PayloadExtraction{
			HTTP: config.HTTPConfig{AWS: config.AWSConfig{Enabled: true}},
		},
	}
}

func goHTTPClientTestConnection() BpfConnectionInfoT {
	return BpfConnectionInfoT{
		S_addr: [16]uint8{15: 1},
		D_addr: [16]uint8{15: 2},
		S_port: 40000,
		D_port: 80,
	}
}

func pendingGoHTTPClientTrace(conn BpfConnectionInfoT, id byte, path string) HTTPRequestTrace {
	trace := HTTPRequestTrace{Status: 200, ResponseLength: 2, StartMonotimeNs: 5000000, EndMonotimeNs: 10000000}
	copy(trace.Method[:], "GET")
	copy(trace.Path[:], path)
	trace.Type = EventTypeHTTPClient
	trace.Conn = conn
	trace.Tp.TraceId[15] = id
	trace.Status = uint16(id)
	return trace
}

func goHTTPClientTraceRecord(t *testing.T, trace HTTPRequestTrace) *ringbuf.Record {
	t.Helper()

	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, trace))
	return &ringbuf.Record{RawSample: raw.Bytes()}
}

func appendGoHTTPClientBuffer(
	t *testing.T,
	parseCtx *EBPFParseContext,
	conn BpfConnectionInfoT,
	traceID [16]uint8,
	packetType uint8,
	direction uint8,
	payload string,
) {
	t.Helper()
	appendGoHTTPClientBufferWithSource(t, parseCtx, conn, traceID, packetType, direction, largeBufferSourceGo, payload)
}

func appendGoHTTPClientBufferWithSource(
	t *testing.T,
	parseCtx *EBPFParseContext,
	conn BpfConnectionInfoT,
	traceID [16]uint8,
	packetType uint8,
	direction uint8,
	source uint8,
	payload string,
) {
	t.Helper()

	header := TCPLargeBufferHeader{
		Type:       EventTypeTCPLargeBuffer,
		PacketType: packetType,
		Action:     largeBufferActionInit,
		Direction:  direction,
		Len:        uint32(len(payload)),
		ConnInfo:   conn,
		Kind:       uint8(KindLayerApp),
		Source:     source,
	}
	header.Tp.TraceId = traceID

	_, ignore, err := appendTCPLargeBuffer(parseCtx, toRingbufRecord(t, header, payload))
	require.NoError(t, err)
	assert.True(t, ignore)
}

func TestServerSpanCannotClaimClientPayload(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	ctx, _ := newGoHTTPClientTestParseContext(t, cfg, 2)
	conn := goHTTPClientTestConnection()
	payload := "GET /client HTTP/1.1\r\nHost: example.com\r\nX-Costgraph-Team: client\r\n\r\n"
	appendGoHTTPClientBuffer(t, ctx, conn, [16]uint8{}, packetTypeRequest, directionSend, payload)
	server := pendingGoHTTPClientTrace(conn, 1, "/server")
	server.Type = uint8(request.EventTypeHTTP)
	require.False(t, ctx.deferGoHTTPClientRequest(&server))
	client := pendingGoHTTPClientTrace(conn, 2, "/client")
	require.True(t, ctx.deferGoHTTPClientRequest(&client))
	pending, ok := ctx.pendingGoHTTPClientRequests.Get(goHTTPClientConnectionKey(conn, [16]uint8{}))
	require.True(t, ok)
	require.Equal(t, payload, string(pending.reqBuffer.UnsafeView()))
}

func TestConnectionReusePreservesResponseOwnership(t *testing.T) {
	cfg := goHTTPClientTestConfig()
	ctx, emitted := newGoHTTPClientTestParseContext(t, cfg, 2)
	conn := goHTTPClientTestConnection()
	req1 := "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp1 := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	req2 := "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp2 := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	appendGoHTTPClientBuffer(t, ctx, conn, [16]uint8{}, packetTypeRequest, directionSend, req1)
	first := pendingGoHTTPClientTrace(conn, 1, "/first")
	require.True(t, ctx.deferGoHTTPClientRequest(&first))
	appendGoHTTPClientBuffer(t, ctx, conn, [16]uint8{}, packetTypeResponse, directionRecv, resp1)
	appendGoHTTPClientBuffer(t, ctx, conn, [16]uint8{}, packetTypeRequest, directionSend, req2)
	appendGoHTTPClientBuffer(t, ctx, conn, [16]uint8{}, packetTypeResponse, directionRecv, resp2)
	second := pendingGoHTTPClientTrace(conn, 2, "/second")
	require.True(t, ctx.deferGoHTTPClientRequest(&second))
	select {
	case batch := <-emitted:
		require.Len(t, batch, 1)
		require.Equal(t, "/first", batch[0].Path)
		require.EqualValues(t, len(req1), batch[0].RequestMessageBytes)
		require.EqualValues(t, len(resp1), batch[0].ResponseMessageBytes)
	case <-time.After(time.Second):
		t.Fatal("previous exchange was not emitted")
	}
}
