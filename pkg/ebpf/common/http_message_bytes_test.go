package ebpfcommon

import (
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"net/http"
	"testing"
)

func TestCompleteHTTPMessageBytes(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		request    *http.Request
		complete   bool
	}{
		{"request", "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc", nil, true},
		{"truncated request", "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\na", nil, false},
		{"response", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", &http.Request{Method: "GET"}, true},
		{"truncated response", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na", &http.Request{Method: "GET"}, false},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", &http.Request{Method: "GET"}, true},
		{"truncated chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n", &http.Request{Method: "GET"}, false},
		{"head", "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", &http.Request{Method: "HEAD"}, true},
		{"missing framing", "HTTP/1.1 200 OK\r\n\r\nabc", &http.Request{Method: "GET"}, false},
		{"concatenated", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", &http.Request{Method: "GET"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := largebuf.NewLargeBuffer()
			for i := 0; i < len(tc.wire); i += 3 {
				end := min(i+3, len(tc.wire))
				buf.AppendChunk([]byte(tc.wire[i:end]))
			}
			want := int64(0)
			if tc.complete {
				want = int64(len(tc.wire))
			}
			if got := completeHTTPMessageBytes(buf, tc.request); got != want {
				t.Fatalf("bytes=%d, want %d", got, want)
			}
			if buf.Len() != len(tc.wire) {
				t.Fatal("measurement mutated payload")
			}
		})
	}
}
