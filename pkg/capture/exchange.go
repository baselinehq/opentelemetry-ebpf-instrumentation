// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"context"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// Exchange is an observed HTTP exchange. Headers follow Options.HeaderPrefixes.
// Message bytes include HTTP framing and headers, excluding TLS overhead and
// HTTP/2 connection-control frames. Zero means a complete size was not measured.
// An exchange may be incomplete; consumers must check both sizes.
type Exchange struct {
	Client               bool
	HostPID              uint32
	SrcIP                string
	DstIP                string
	DstPort              int
	RequestHeaders       map[string][]string
	RequestMessageBytes  int64
	ResponseMessageBytes int64
}

func exchangeFromSpan(s *request.Span) Exchange {
	return Exchange{
		Client: s.IsClientSpan(), HostPID: uint32(s.Pid.HostPID),
		SrcIP: s.Peer, DstIP: s.Host, DstPort: s.HostPort,
		RequestHeaders:       s.RequestHeaders,
		RequestMessageBytes:  s.RequestMessageBytes,
		ResponseMessageBytes: s.ResponseMessageBytes,
	}
}

func forwardExchanges(ctx context.Context, spans <-chan []request.Span, out chan<- []Exchange) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-spans:
			if !ok {
				return
			}
			exchanges := make([]Exchange, len(batch))
			for i := range batch {
				exchanges[i] = exchangeFromSpan(&batch[i])
			}
			select {
			case out <- exchanges:
			case <-ctx.Done():
				return
			}
		}
	}
}
