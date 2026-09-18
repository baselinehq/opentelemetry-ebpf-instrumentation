// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type largeBufferKind uint8

// must match the table large_buf_kind in common.h
const (
	KindLayerWire largeBufferKind = 0
	KindLayerApp  largeBufferKind = 1
)

type largeBufferKey struct {
	traceID               [16]uint8
	packetType, direction uint8
	connInfo              BpfConnectionInfoT
	kind                  largeBufferKind
}

const (
	largeBufferActionInit = iota
	largeBufferActionAppend
)

const (
	largeBufferSourceKProbes = iota
	largeBufferSourceGo
)

func appendTCPLargeBuffer(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Sizeof(TCPLargeBufferHeader{})) - uint32(unsafe.Sizeof(uintptr(0))) // Remove `buf` placeholder

	event, err := ReinterpretCast[TCPLargeBufferHeader](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}
	if uint64(hdrSize)+uint64(event.Len) > uint64(len(record.RawSample)) {
		return request.Span{}, true, fmt.Errorf("invalid large buffer record size: %d-byte payload exceeds %d-byte record", event.Len, len(record.RawSample))
	}

	key := largeBufferKey{
		traceID:    event.Tp.TraceId,
		packetType: event.PacketType,
		direction:  event.Direction,
		connInfo:   event.ConnInfo,
		kind:       largeBufferKind(event.Kind),
	}

	if parseCtx.protocolDebug {
		fmt.Printf(">>> LargeBufferAppend: (packet=%d direction=%d action=%d size=%d kind=%d traceId=%v)\nconnection info %v\n%s\n",
			event.PacketType, event.Direction, event.Action, event.Len, event.Kind, key.traceID, key.connInfo,
			string(record.RawSample[hdrSize:hdrSize+event.Len]))
	}

	// HTTP/1 reuses a zero trace ID. Finish the preceding request before
	// a new exchange can replace its response buffer on this connection.
	if event.Source == largeBufferSourceGo && event.Kind == uint8(KindLayerApp) &&
		event.PacketType == packetTypeRequest && event.Direction == directionSend &&
		event.Action == largeBufferActionInit && event.Tp.TraceId == [16]uint8{} &&
		parseCtx.pendingGoHTTPClientRequests != nil {
		parseCtx.pendingGoHTTPClientRequests.Remove(goHTTPClientConnectionKey(event.ConnInfo, event.Tp.TraceId))
	}

	chunk := record.RawSample[hdrSize : hdrSize+event.Len]

	var lb *largebuf.LargeBuffer
	switch event.Action {
	case largeBufferActionInit:
		lb = largebuf.NewLargeBuffer()
	case largeBufferActionAppend:
		var ok bool
		lb, ok = parseCtx.largeBuffers.Get(key)
		if ok && lb == nil {
			// A nil entry marks an oversized message until the next INIT.
			return request.Span{}, true, nil
		}
		if !ok {
			lb = largebuf.NewLargeBuffer()
		}
	default:
		return request.Span{}, true, fmt.Errorf("invalid large buffer action: %d", event.Action)
	}
	limit := parseCtx.maxHTTPBufferBytes
	if key.kind == KindLayerApp && limit > 0 && lb.Len()+len(chunk) > limit {
		parseCtx.largeBuffers.Add(key, nil)
		return request.Span{}, true, nil
	}
	lb.AppendChunk(chunk)
	parseCtx.largeBuffers.Add(key, lb)

	// Go HTTP responses are the only ones we cannot catch without making the Go uprobe code
	// a lot more complex. The main issue is that in Go you can finish the request and never care
	// about the response, which makes it very hard to reliably complete the Go client http request.
	// This achieves the same thing as the delayed HTTP requests in kprobes, except it's done in
	// userspace.
	if event.Source == largeBufferSourceGo && event.PacketType == packetTypeResponse && event.Direction == directionRecv {
		parseCtx.refreshPendingGoHTTPClientRequest(event.ConnInfo, event.Tp.TraceId)
	}

	return request.Span{}, true, nil
}

func extractLargeBuffer(
	parseCtx *EBPFParseContext,
	traceID [16]uint8,
	packetType, direction uint8,
	connInfo BpfConnectionInfoT,
	kind largeBufferKind,
) (*largebuf.LargeBuffer, bool) {
	// The kind field tells us if we want to extract HTTP or TCP buffers. In normal circumstances
	// there never would be any mixup, it's either TCP or HTTP. However, when decrypt SSL we could
	// see SSL packets on the same connection before we decrypt the first SSL packet. In that instance
	// we may get TCP (SSL junk) and HTTP large buffers on the same connection and we need to
	// be able to tell them apart. For the same reason, we tell apart the special TCP protocols from
	// the generic TCP protocol
	key := largeBufferKey{
		traceID:    traceID,
		packetType: packetType,
		direction:  direction,
		connInfo:   connInfo,
		kind:       kind,
	}

	lb, ok := parseCtx.largeBuffers.Get(key)
	if !ok || lb == nil {
		if parseCtx.protocolDebug {
			fmt.Printf("<<< LargeBufferExtract: not found! (packet=%d direction=%d kind=%d traceId=%v)\nconnection info %v\n", key.packetType, key.direction, int(key.kind), key.traceID, key.connInfo)
		}
		return nil, false
	}

	if parseCtx.protocolDebug {
		fmt.Printf("<<< LargeBufferExtract: (packet=%d direction=%d kind=%d len=%d)\nconnection info %v\n%s\n",
			key.packetType, key.direction, int(key.kind), lb.Len(), key.connInfo, lb.UnsafeView())
	}

	parseCtx.largeBuffers.Remove(key)

	return lb, true
}

// containsTCPLargeBuffer reports whether a large buffer is currently stored for
// the given key, without consuming it (unlike extractTCPLargeBuffer).
func containsTCPLargeBuffer(
	parseCtx *EBPFParseContext,
	traceID [16]uint8,
	packetType, direction uint8,
	connInfo BpfConnectionInfoT,
	protocolType BpfProtocolType,
) bool {
	key := largeBufferKey{
		traceID:    traceID,
		packetType: packetType,
		direction:  direction,
		connInfo:   connInfo,
		kind:       protocolToLargeBufferKind(protocolType),
	}
	lb, ok := parseCtx.largeBuffers.Get(key)
	return ok && lb != nil
}

func protocolToLargeBufferKind(protocolType BpfProtocolType) largeBufferKind {
	switch protocolType {
	case ProtocolTypeKafka, ProtocolTypeMySQL, ProtocolTypePostgres, ProtocolTypeMSSQL, ProtocolTypeHTTP, ProtocolTypeAerospike:
		return KindLayerApp
	}
	// No large buffers for MQTT the rest are generic TCP buffers
	return KindLayerWire
}

func extractTCPLargeBuffer(
	parseCtx *EBPFParseContext,
	traceID [16]uint8,
	packetType, direction uint8,
	connInfo BpfConnectionInfoT,
	protocolType BpfProtocolType,
) (*largebuf.LargeBuffer, bool) {
	return extractLargeBuffer(parseCtx, traceID, packetType, direction, connInfo, protocolToLargeBufferKind(protocolType))
}
