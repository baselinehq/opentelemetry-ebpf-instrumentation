// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package ebpfcommon

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const tlsH2Event = 250 // bpf/common/tls_h2_capture.h; separate from upstream events
const h2CaptureHeaderLimit = 64 << 10
const h2CaptureFrameLimit = 1 << 20
const h2CaptureStreamLimit = 512

// Layout is asserted to be 72 bytes in both the BPF source and Go tests.
type tlsH2Chunk struct {
	Type, Direction             uint8
	Pad                         uint16
	Len                         uint32
	Generation, Offset          uint64
	HostPID, UserPID, Namespace uint32
	Conn                        BpfConnectionInfoT
}
type tlsH2Key struct {
	pid  uint32
	conn BpfConnectionInfoT
}

func tlsH2ConnectionKey(pid uint32, conn BpfConnectionInfoT) tlsH2Key {
	sortConnectionInfo(&conn)
	return tlsH2Key{pid, conn}
}

type tlsH2Direction struct {
	offset       uint64
	buf          []byte
	preface      bool
	decoder      *hpack.Decoder
	continuation uint32
	endStream    bool
	headerBytes  int
	header       http.Header
}
type tlsH2Stream struct {
	reqBytes, respBytes int64
	request, response   bool
	reqEnd, respEnd     bool
	method, path        string
	status              int
	headers             http.Header
}
type tlsH2Capture struct {
	generation uint64
	pid        request.PidInfo
	conn       BpfConnectionInfoT // local client -> remote server, never sorted
	directions [2]tlsH2Direction
	streams    map[uint32]*tlsH2Stream
	bad        bool
}

func newTLSH2Capture(e *tlsH2Chunk) *tlsH2Capture {
	c := &tlsH2Capture{generation: e.Generation, conn: e.Conn, streams: make(map[uint32]*tlsH2Stream),
		pid: request.PidInfo{HostPID: app.PID(e.HostPID), UserPID: app.PID(e.UserPID), Namespace: e.Namespace}}
	for i := range c.directions {
		d := &c.directions[i]
		d.preface = i == int(directionSend)
		d.decoder = hpack.NewDecoder(4096, func(f hpack.HeaderField) {
			d.headerBytes += len(f.Name) + len(f.Value)
			if d.headerBytes <= h2CaptureHeaderLimit {
				d.header.Add(f.Name, f.Value)
			}
		})
		d.decoder.SetMaxStringLength(h2CaptureHeaderLimit)
	}
	return c
}
func (c *tlsH2Capture) invalidate() {
	c.bad = true
	c.streams = nil
	for i := range c.directions {
		c.directions[i].buf = nil
		c.directions[i].header = nil
		c.directions[i].decoder = nil
	}
}

func readTLSH2Capture(ctx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	size := int(unsafe.Sizeof(tlsH2Chunk{}))
	e, err := ReinterpretCast[tlsH2Chunk](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}
	if e.Direction > 2 || uint64(size)+uint64(e.Len) != uint64(len(record.RawSample)) {
		return request.Span{}, true, fmt.Errorf("invalid TLS HTTP2 chunk")
	}
	key := tlsH2ConnectionKey(e.HostPID, e.Conn)
	if e.Direction == 2 {
		if e.Len != 0 {
			return request.Span{}, true, fmt.Errorf("invalid TLS close event")
		}
		if c, ok := ctx.tlsH2Captures.Get(key); ok && c.generation == e.Generation {
			ctx.tlsH2Captures.Remove(key)
		}
		return request.Span{}, true, nil
	}

	c, ok := ctx.tlsH2Captures.Get(key)
	if !ok || c.generation != e.Generation {
		c = newTLSH2Capture(e)
		ctx.tlsH2Captures.Add(key, c)
	}
	if !c.bad && !c.consume(ctx, e.Direction, e.Offset, record.RawSample[size:]) {
		c.invalidate()
	}
	return request.Span{}, true, nil
}

func (c *tlsH2Capture) consume(ctx *EBPFParseContext, direction uint8, offset uint64, data []byte) bool {
	d := &c.directions[direction]
	if offset != d.offset {
		return false
	}
	d.offset += uint64(len(data))
	d.buf = append(d.buf, data...)
	if d.preface {
		n := min(len(d.buf), len(http2.ClientPreface))
		if !bytes.Equal(d.buf[:n], []byte(http2.ClientPreface)[:n]) {
			return false
		}
		if n < len(http2.ClientPreface) {
			return true
		}
		d.buf = d.buf[n:]
		d.preface = false
	}
	for len(d.buf) >= 9 {
		n := int(d.buf[0])<<16 | int(d.buf[1])<<8 | int(d.buf[2])
		if n > h2CaptureFrameLimit {
			return false
		}
		if len(d.buf) < n+9 {
			break
		}
		fr := http2.NewFramer(io.Discard, bytes.NewReader(d.buf[:n+9]))
		fr.SetMaxReadFrameSize(h2CaptureFrameLimit)
		// Continuations belong to the persistent direction state, not this reader.
		fr.AllowIllegalReads = true
		f, err := fr.ReadFrame()
		if err != nil || !c.frame(ctx, direction, f, int64(n+9)) {
			return false
		}
		d.buf = d.buf[n+9:]
	}
	if len(d.buf) == 0 {
		d.buf = nil
	}
	return true
}
func (c *tlsH2Capture) frame(ctx *EBPFParseContext, direction uint8, f http2.Frame, size int64) bool {
	d := &c.directions[direction]
	id := f.Header().StreamID
	if d.continuation != 0 {
		if _, ok := f.(*http2.ContinuationFrame); !ok || id != d.continuation {
			return false
		}
	}
	switch f := f.(type) {
	case *http2.HeadersFrame:
		if id == 0 || id&1 == 0 {
			return false
		}
		s := c.streams[id]
		if s == nil {
			if len(c.streams) >= h2CaptureStreamLimit {
				return false
			}
			s = &tlsH2Stream{}
			c.streams[id] = s
		}
		if direction == directionSend {
			s.reqBytes += size
		} else {
			s.respBytes += size
		}
		d.header = make(http.Header)
		d.headerBytes = 0
		d.continuation = id
		d.endStream = f.StreamEnded()
		return c.header(ctx, direction, id, f.HeaderBlockFragment(), f.HeadersEnded())
	case *http2.ContinuationFrame:
		if d.continuation == 0 || id != d.continuation {
			return false
		}
		s := c.streams[id]
		if direction == directionSend {
			s.reqBytes += size
		} else {
			s.respBytes += size
		}
		return c.header(ctx, direction, id, f.HeaderBlockFragment(), f.HeadersEnded())
	case *http2.DataFrame:
		s := c.streams[id]
		if s == nil {
			return false
		}
		if direction == directionSend {
			if !s.request || s.reqEnd {
				return false
			}
			s.reqBytes += size
			s.reqEnd = f.StreamEnded()
		} else {
			if !s.response || s.respEnd {
				return false
			}
			s.respBytes += size
			s.respEnd = f.StreamEnded()
		}
		c.complete(ctx, id, s)
	case *http2.RSTStreamFrame:
		delete(c.streams, id)
	case *http2.SettingsFrame:
		valid := true
		if err := f.ForeachSetting(func(s http2.Setting) error {
			if s.ID == http2.SettingHeaderTableSize {
				if s.Val > h2CaptureHeaderLimit {
					valid = false
				} else {
					c.directions[1-direction].decoder.SetAllowedMaxDynamicTableSize(s.Val)
				}
			}
			return nil
		}); err != nil {
			return false
		}
		return valid
	case *http2.GoAwayFrame:
		for id := range c.streams {
			if id > f.LastStreamID {
				delete(c.streams, id)
			}
		}
	case *http2.PushPromiseFrame:
		// Its HPACK block changes connection state; do not guess past an unsupported push.
		return false
	}
	return true
}
func (c *tlsH2Capture) header(ctx *EBPFParseContext, direction uint8, id uint32, fragment []byte, end bool) bool {
	d := &c.directions[direction]
	if _, err := d.decoder.Write(fragment); err != nil || d.headerBytes > h2CaptureHeaderLimit {
		return false
	}
	if !end {
		return true
	}
	if err := d.decoder.Close(); err != nil {
		return false
	}
	s := c.streams[id]
	if direction == directionSend {
		if s.reqEnd {
			return false
		}
		if !s.request {
			s.method, s.path = d.header.Get(":method"), d.header.Get(":path")
			if s.method == "" {
				return false
			}
			span := request.Span{Type: request.EventTypeHTTPClient}
			if ctx.httpEnricher != nil {
				ctx.httpEnricher.EnrichRequestOnly(&span, &http.Request{Header: d.header})
			}
			s.headers = span.RequestHeaders
			s.request = true
		}
		s.reqEnd = d.endStream
	} else {
		if s.respEnd {
			return false
		}
		if status := d.header.Get(":status"); status != "" {
			n, err := strconv.Atoi(status)
			if err != nil || n < 100 || n > 599 || s.response {
				return false
			}
			if n >= 200 {
				s.status = n
				s.response = true
			}
		} else if !s.response {
			return false
		}
		if d.endStream && !s.response {
			return false
		}
		s.respEnd = d.endStream
	}
	d.continuation = 0
	d.header = nil
	c.complete(ctx, id, s)
	return true
}
func (c *tlsH2Capture) complete(ctx *EBPFParseContext, id uint32, s *tlsH2Stream) {
	if !s.request || !s.response || !s.reqEnd || !s.respEnd {
		return
	}
	delete(c.streams, id)
	if len(s.headers) == 0 {
		return
	}
	ctx.emitExtraSpans(request.Span{
		Type: request.EventTypeHTTPClient, ProtoVersion: request.ProtoVersionHTTP2,
		Pid: c.pid, Method: s.method, Path: s.path, Status: s.status,
		Peer: net.IP(c.conn.S_addr[:]).String(), Host: net.IP(c.conn.D_addr[:]).String(),
		PeerPort: int(c.conn.S_port), HostPort: int(c.conn.D_port),
		RequestHeaders: s.headers, RequestMessageBytes: s.reqBytes, ResponseMessageBytes: s.respBytes,
	})
}
