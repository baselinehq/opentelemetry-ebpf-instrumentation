package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"testing"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func h2CaptureContext(t *testing.T) (*EBPFParseContext, *[]request.Span) {
	ctx := NewEBPFParseContext(nil, nil, nil)
	t.Cleanup(ctx.Close)
	var spans []request.Span
	ctx.emitSpans = func(s []request.Span) { spans = append(spans, s...) }
	ctx.httpEnricher = ebpfhttp.NewHTTPEnricher(config.EnrichmentConfig{Enabled: true,
		Policy: config.HTTPParsingPolicy{DefaultAction: config.HTTPParsingDefaultAction{Headers: config.HTTPParsingActionExclude}},
		Rules:  []config.HTTPParsingRule{{Action: config.HTTPParsingActionInclude, Type: config.HTTPParsingRuleTypeHeaders, Scope: config.HTTPParsingScopeRequest, Match: config.HTTPParsingMatch{Patterns: []services.GlobAttr{services.NewGlob("x-costgraph-*")}}}}})
	return ctx, &spans
}

type h2Writer struct {
	wire, block bytes.Buffer
	fr          *http2.Framer
	enc         *hpack.Encoder
}

func newH2Writer() *h2Writer {
	w := &h2Writer{}
	w.fr = http2.NewFramer(&w.wire, nil)
	w.enc = hpack.NewEncoder(&w.block)
	return w
}
func (w *h2Writer) headers(t *testing.T, id uint32, end, split bool, fields ...string) int64 {
	before := w.wire.Len()
	w.block.Reset()
	for i := 0; i < len(fields); i += 2 {
		require.NoError(t, w.enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]}))
	}
	b := bytes.Clone(w.block.Bytes())
	if split {
		n := len(b) / 2
		require.NoError(t, w.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndStream: end, BlockFragment: b[:n]}))
		require.NoError(t, w.fr.WriteContinuation(id, true, b[n:]))
	} else {
		require.NoError(t, w.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndStream: end, EndHeaders: true, BlockFragment: b}))
	}
	return int64(w.wire.Len() - before)
}
func feedH2(t *testing.T, ctx *EBPFParseContext, c *tlsH2Capture, dir uint8, data []byte, fragment int) {
	for len(data) > 0 {
		n := min(fragment, len(data))
		require.True(t, c.consume(ctx, dir, c.directions[dir].offset, data[:n]))
		data = data[n:]
	}
}
func TestTLSH2MultiplexingCompressionContinuationAndPadding(t *testing.T) {
	ctx, spans := h2CaptureContext(t)
	c := newTLSH2Capture(&tlsH2Chunk{Generation: 1, HostPID: 77, Conn: goHTTPClientTestConnection()})
	send, recv := newH2Writer(), newH2Writer()
	send.wire.WriteString(http2.ClientPreface)
	require.NoError(t, send.fr.WriteSettings())
	req1 := send.headers(t, 1, false, true, ":method", "POST", ":path", "/one", "x-costgraph-case", "alpha", "x-costgraph-team", "shared")
	req3 := send.headers(t, 3, true, false, ":method", "POST", ":path", "/two", "x-costgraph-case", "beta", "x-costgraph-team", "shared")
	before := send.wire.Len()
	require.NoError(t, send.fr.WriteDataPadded(1, true, []byte("abc"), make([]byte, 7)))
	req1 += int64(send.wire.Len() - before)
	// Connection controls are excluded; the empty response finishes before stream 1.
	require.NoError(t, recv.fr.WriteSettings())
	resp3 := recv.headers(t, 3, true, false, ":status", "204")
	resp1 := recv.headers(t, 1, false, true, ":status", "200", "content-type", "text/plain")
	before = recv.wire.Len()
	require.NoError(t, recv.fr.WriteData(1, false, []byte("reply")))
	resp1 += int64(recv.wire.Len() - before)
	resp1 += recv.headers(t, 1, true, false, "x-trailer", "done")
	feedH2(t, ctx, c, directionSend, send.wire.Bytes(), 1)
	feedH2(t, ctx, c, directionRecv, recv.wire.Bytes(), 3)
	require.Len(t, *spans, 2)
	for _, s := range *spans {
		switch http.Header(s.RequestHeaders).Get("X-Costgraph-Case") {
		case "alpha":
			require.Equal(t, req1, s.RequestMessageBytes)
			require.Equal(t, resp1, s.ResponseMessageBytes)
		case "beta":
			require.Equal(t, req3, s.RequestMessageBytes)
			require.Equal(t, resp3, s.ResponseMessageBytes)
		default:
			t.Fatal(s.RequestHeaders)
		}
		require.Equal(t, "shared", http.Header(s.RequestHeaders).Get("X-Costgraph-Team"))
	}
	require.Empty(t, c.streams)
}
func h2Record(t *testing.T, e tlsH2Chunk, data []byte) *ringbuf.Record {
	e.Type = tlsH2Event
	e.Len = uint32(len(data))
	var b bytes.Buffer
	require.NoError(t, binary.Write(&b, binary.LittleEndian, e))
	b.Write(data)
	return &ringbuf.Record{RawSample: b.Bytes()}
}
func TestTLSH2LossGenerationAndProcessIsolation(t *testing.T) {
	require.Equal(t, uintptr(72), unsafe.Sizeof(tlsH2Chunk{}))
	ctx, _ := h2CaptureContext(t)
	e := tlsH2Chunk{Generation: 1, HostPID: 10, Direction: directionSend, Conn: goHTTPClientTestConnection()}
	_, _, err := readTLSH2Capture(ctx, h2Record(t, e, []byte(http2.ClientPreface)))
	require.NoError(t, err)
	e.Offset = 100 // lost bytes must poison this connection, not shift stream tags.
	_, _, err = readTLSH2Capture(ctx, h2Record(t, e, []byte{0}))
	require.NoError(t, err)
	c, _ := ctx.tlsH2Captures.Get(tlsH2ConnectionKey(e.HostPID, e.Conn))
	require.True(t, c.bad)
	e.HostPID = 11
	e.Offset = 0
	_, _, err = readTLSH2Capture(ctx, h2Record(t, e, []byte(http2.ClientPreface)))
	require.NoError(t, err)
	other, _ := ctx.tlsH2Captures.Get(tlsH2ConnectionKey(e.HostPID, e.Conn))
	require.False(t, other.bad)
	e.HostPID = 10
	e.Generation = 2
	_, _, err = readTLSH2Capture(ctx, h2Record(t, e, []byte(http2.ClientPreface)))
	require.NoError(t, err)
	recovered, _ := ctx.tlsH2Captures.Get(tlsH2ConnectionKey(e.HostPID, e.Conn))
	require.False(t, recovered.bad)
	e.Direction = 2
	e.Generation = 1 // an old close must not remove a reused connection
	_, _, err = readTLSH2Capture(ctx, h2Record(t, e, nil))
	require.NoError(t, err)
	require.True(t, ctx.tlsH2Captures.Contains(tlsH2ConnectionKey(e.HostPID, e.Conn)))
	e.Generation = 2
	_, _, err = readTLSH2Capture(ctx, h2Record(t, e, nil))
	require.NoError(t, err)
	require.False(t, ctx.tlsH2Captures.Contains(tlsH2ConnectionKey(e.HostPID, e.Conn)))

}
func TestTLSH2RejectsUnknownHPACKAndIncompleteStreams(t *testing.T) {
	ctx, spans := h2CaptureContext(t)
	c := newTLSH2Capture(&tlsH2Chunk{Generation: 1})
	w := newH2Writer()
	w.wire.WriteString(http2.ClientPreface)
	require.NoError(t, w.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true, BlockFragment: []byte{0xff, 0x01}}))
	require.False(t, c.consume(ctx, directionSend, 0, w.wire.Bytes()))
	require.Empty(t, *spans)
	c = newTLSH2Capture(&tlsH2Chunk{Generation: 2})
	w = newH2Writer()
	w.wire.WriteString(http2.ClientPreface)
	w.headers(t, 1, true, false, ":method", "GET", ":path", "/", "x-costgraph-case", "incomplete")
	feedH2(t, ctx, c, directionSend, w.wire.Bytes(), 1000)
	recv := newH2Writer()
	recv.headers(t, 1, false, false, ":status", "200")
	require.NoError(t, recv.fr.WriteData(1, false, []byte("unfinished")))
	feedH2(t, ctx, c, directionRecv, recv.wire.Bytes(), 1000)
	require.Empty(t, *spans)
	reset := newH2Writer()
	require.NoError(t, reset.fr.WriteRSTStream(1, http2.ErrCodeCancel))
	feedH2(t, ctx, c, directionRecv, reset.wire.Bytes(), 1000)
	require.Empty(t, c.streams)
	require.Empty(t, *spans)
}
