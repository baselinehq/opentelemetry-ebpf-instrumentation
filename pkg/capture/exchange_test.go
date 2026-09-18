// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestExchangePreservesIdentityHeadersAndMeasuredBytes(t *testing.T) {
	s := request.Span{Type: request.EventTypeHTTPClient, Peer: "10.0.0.1", Host: "10.0.0.2", HostPort: 443,
		RequestHeaders:      map[string][]string{"x-example-owner": {"team"}},
		RequestMessageBytes: 215, ResponseMessageBytes: 245, ContentLength: 32, ResponseLength: 64}
	s.Pid.HostPID = 42
	got := exchangeFromSpan(&s)
	if !got.Client || got.HostPID != 42 || got.SrcIP != s.Peer || got.DstIP != s.Host || got.DstPort != 443 ||
		got.RequestMessageBytes != 215 || got.ResponseMessageBytes != 245 || got.RequestHeaders["x-example-owner"][0] != "team" {
		t.Fatalf("exchange lost attribution inputs: %+v", got)
	}
	s.Type = request.EventTypeHTTP
	if exchangeFromSpan(&s).Client {
		t.Fatal("server observation became a client")
	}
	s.RequestMessageBytes = 0
	if exchangeFromSpan(&s).RequestMessageBytes != 0 {
		t.Fatal("missing measured bytes must not fall back to body length")
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
