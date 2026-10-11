// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture // import "go.opentelemetry.io/obi/pkg/capture"

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
)

type ExchangeKind uint8

const (
	ExchangeHTTP ExchangeKind = iota
	ExchangeDNS
)

// Exchange is an observed HTTP exchange. Headers follow Options.HeaderPrefixes.
// Message bytes include HTTP framing and headers, excluding TLS overhead and
// HTTP/2 connection-control frames. Zero means a complete size was not measured.
// An exchange may be incomplete; consumers must check both sizes.
type Exchange struct {
	Kind                 ExchangeKind
	Client               bool
	HostPID              uint32
	SrcIP                string
	DstIP                string
	DstPort              int
	ServerAddress        string
	RequestHeaders       map[string][]string
	RequestMessageBytes  int64
	ResponseMessageBytes int64
	QueryName            string
	Answers              []netip.Addr
}

func exchangeFromSpan(s *request.Span) (Exchange, bool) {
	if s.Type == request.EventTypeDNS {
		return dnsExchange(s)
	}
	return Exchange{
		Kind: ExchangeHTTP, Client: s.IsClientSpan(), HostPID: uint32(s.Pid.HostPID),
		SrcIP: s.Peer, DstIP: s.Host, DstPort: s.HostPort,
		ServerAddress:        serverAddress(s.Statement),
		RequestHeaders:       s.RequestHeaders,
		RequestMessageBytes:  s.RequestMessageBytes,
		ResponseMessageBytes: s.ResponseMessageBytes,
	}, true
}

func dnsExchange(s *request.Span) (Exchange, bool) {
	if s.Status != int(dnsparser.RCodeSuccess) || s.Path == "" {
		return Exchange{}, false
	}
	var answers []netip.Addr
	for raw := range strings.SplitSeq(s.Statement, ",") {
		if addr, err := netip.ParseAddr(raw); err == nil {
			answers = append(answers, addr.Unmap())
		}
	}
	if len(answers) == 0 {
		return Exchange{}, false
	}
	return Exchange{Kind: ExchangeDNS, Client: true, HostPID: uint32(s.Pid.HostPID), QueryName: s.Path, Answers: answers}, true
}

func serverAddress(statement string) string {
	_, host, ok := strings.Cut(statement, request.SchemeHostSeparator)
	if !ok || host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
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
			exchanges := make([]Exchange, 0, len(batch))
			for i := range batch {
				if exchange, ok := exchangeFromSpan(&batch[i]); ok {
					exchanges = append(exchanges, exchange)
				}
			}
			if len(exchanges) == 0 {
				continue
			}
			select {
			case out <- exchanges:
			case <-ctx.Done():
				return
			}
		}
	}
}
