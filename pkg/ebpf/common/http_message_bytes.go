// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"io"
	"net/http"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// completeHTTPMessageBytes accepts exactly one complete, framed HTTP/1 message.
// Truncated captures, concatenated exchanges and HTTP/2 are not full measurements.
// A non-nil request selects response parsing, including HEAD response semantics.
func completeHTTPMessageBytes(buffer *largebuf.LargeBuffer, request *http.Request) int64 {
	if buffer == nil {
		return 0
	}
	r := buffer.NewReader()
	reader := bufio.NewReader(&r)
	var body io.ReadCloser
	if request == nil {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return 0
		}
		body = req.Body
	} else {
		resp, err := http.ReadResponse(reader, request)
		if err != nil {
			return 0
		}
		// Without framing, EOF of a bounded capture cannot establish completion.
		if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 {
			resp.Body.Close()
			return 0
		}
		body = resp.Body
	}
	defer body.Close()
	if _, err := io.Copy(io.Discard, body); err != nil {
		return 0
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return 0
	}
	return int64(buffer.Len())
}
