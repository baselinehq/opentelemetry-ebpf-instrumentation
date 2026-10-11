// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
)

func mustExchange(t *testing.T, s *request.Span) Exchange {
	t.Helper()
	got, ok := exchangeFromSpan(s)
	if !ok {
		t.Fatalf("span %+v produced no exchange", s)
	}
	return got
}

func TestExchangePreservesIdentityHeadersAndMeasuredBytes(t *testing.T) {
	s := request.Span{
		Type: request.EventTypeHTTPClient, Peer: "10.0.0.1", Host: "10.0.0.2", HostPort: 443,
		RequestHeaders:      map[string][]string{"x-example-owner": {"team"}},
		RequestMessageBytes: 215, ResponseMessageBytes: 245, ContentLength: 32, ResponseLength: 64,
	}
	s.Pid.HostPID = 42
	got := mustExchange(t, &s)
	if got.Kind != ExchangeHTTP || !got.Client || got.HostPID != 42 || got.SrcIP != s.Peer || got.DstIP != s.Host || got.DstPort != 443 ||
		got.RequestMessageBytes != 215 || got.ResponseMessageBytes != 245 || got.RequestHeaders["x-example-owner"][0] != "team" {
		t.Fatalf("exchange lost attribution inputs: %+v", got)
	}
	s.Type = request.EventTypeHTTP
	if mustExchange(t, &s).Client {
		t.Fatal("server observation became a client")
	}
	s.RequestMessageBytes = 0
	if mustExchange(t, &s).RequestMessageBytes != 0 {
		t.Fatal("missing measured bytes must not fall back to body length")
	}
}

func TestExchangeServerAddress(t *testing.T) {
	for _, tc := range []struct {
		name, statement, want string
	}{
		{name: "host header with port", statement: "https;api.openai.com:443", want: "api.openai.com"},
		{name: "host header without port", statement: "http;billing.internal", want: "billing.internal"},
		{name: "scheme only", statement: "https;", want: ""},
		{name: "no statement", statement: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := request.Span{Type: request.EventTypeHTTPClient, Statement: tc.statement}
			if got := mustExchange(t, &s).ServerAddress; got != tc.want {
				t.Fatalf("ServerAddress = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDNSExchange(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		statement   string
		wantOK      bool
		wantAnswers []netip.Addr
	}{
		{
			name: "answered", status: int(dnsparser.RCodeSuccess), statement: "104.18.32.47,2606:4700::6812:202f", wantOK: true,
			wantAnswers: []netip.Addr{netip.MustParseAddr("104.18.32.47"), netip.MustParseAddr("2606:4700::6812:202f")},
		},
		{name: "nxdomain", status: int(dnsparser.RCodeNameError)},
		{name: "answered without addresses", status: int(dnsparser.RCodeSuccess)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := request.Span{Type: request.EventTypeDNS, Path: "api.openai.com.", Statement: tc.statement, Status: tc.status}
			s.Pid.HostPID = 42
			got, ok := exchangeFromSpan(&s)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.Kind != ExchangeDNS || got.HostPID != 42 || got.QueryName != "api.openai.com." || !slices.Equal(got.Answers, tc.wantAnswers) {
				t.Fatalf("dns exchange = %+v", got)
			}
		})
	}
}

func TestForwardExchangesStopsWithBlockedConsumer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan []request.Span)
	out := make(chan []Exchange)
	done := make(chan struct{})
	go func() { defer close(done); forwardExchanges(ctx, in, out) }()
	in <- []request.Span{{}}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked consumer prevented shutdown")
	}
}
