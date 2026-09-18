// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
)

func headerEnrichmentContext(status *int) *EBPFParseContext {
	ctx := NewEBPFParseContext(nil, nil, nil)
	ctx.httpEnricher = ebpfhttp.NewHTTPEnricher(config.EnrichmentConfig{
		Policy: config.HTTPParsingPolicy{DefaultAction: config.HTTPParsingDefaultAction{Headers: config.HTTPParsingActionExclude, Body: config.HTTPParsingActionExclude}},
		Rules: []config.HTTPParsingRule{{Action: config.HTTPParsingActionInclude, Type: config.HTTPParsingRuleTypeHeaders, Scope: config.HTTPParsingScopeRequest, Match: config.HTTPParsingMatch{
			Patterns: []services.GlobAttr{services.NewGlob("x-tenant-id")}, ResponseStatusCode: &config.NumericRange{Equals: status},
		}}},
	})
	return ctx
}

func TestHTTP2HeaderEnrichmentKeepsStreamIdentity(t *testing.T) {
	status := 200
	ctx := headerEnrichmentContext(&status)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)
	responseEnc := &h2ConnEncoder{}
	responseEnc.enc = hpack.NewEncoder(&responseEnc.buf)
	events := make([]BPFHTTP2Info, 3)
	tenants := []string{"alpha", "beta", "alpha"}
	for i, tenant := range tenants {
		fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/empty"}, {Name: "x-tenant-id", Value: tenant}, {Name: "authorization", Value: "secret"}}
		events[i] = h2Event(enc.frame(t, fields), responseEnc.frame(t, []hpack.HeaderField{{Name: ":status", Value: "200"}}), 900, uint32(1+2*i))
		events[i].Ssl = 1
		observeH2Headers(t, ctx, events[i], EventTypeKHTTP2RequestHeaders)
	}
	// Response order differs from HPACK capture order; no DATA body is needed.
	for _, i := range []int{2, 0, 1} {
		observeH2Headers(t, ctx, events[i], EventTypeKHTTP2ResponseHeaders)
		span := completeH2(t, ctx, events[i])
		require.Equal(t, map[string][]string{"X-Tenant-Id": {tenants[i]}}, span.RequestHeaders)
	}
}

func TestHTTP2HeaderEnrichmentUsesFinalStatus(t *testing.T) {
	status := 201
	ctx := headerEnrichmentContext(&status)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)
	responseEnc := &h2ConnEncoder{}
	responseEnc.enc = hpack.NewEncoder(&responseEnc.buf)
	event := h2Event(enc.frame(t, []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/empty"}, {Name: "x-tenant-id", Value: "alpha"}}), responseEnc.frame(t, []hpack.HeaderField{{Name: ":status", Value: "200"}}), 901, 1)
	event.Ssl = 1
	observeH2Headers(t, ctx, event, EventTypeKHTTP2RequestHeaders)
	observeH2Headers(t, ctx, event, EventTypeKHTTP2ResponseHeaders)
	require.Empty(t, completeH2(t, ctx, event).RequestHeaders)
}

func TestHTTP2HeaderEnrichmentDisabled(t *testing.T) {
	ctx := NewEBPFParseContext(nil, nil, nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)
	event := h2Event(enc.frame(t, []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/empty"}, {Name: "x-tenant-id", Value: "alpha"}}), nil, 902, 1)
	observeH2Headers(t, ctx, event, EventTypeKHTTP2RequestHeaders)
	require.Nil(t, getOrInitH2Conn(ctx.h2c, 902).streams[1].request.headers)
	require.Empty(t, completeH2(t, ctx, event).RequestHeaders)
}

func TestHTTP2HeaderEnrichmentRejectsUntrustedTable(t *testing.T) {
	ctx := headerEnrichmentContext(nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)
	fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/empty"}, {Name: "x-tenant-id", Value: "alpha"}}
	_ = enc.frame(t, fields) // missed first block
	event := h2Event(enc.frame(t, fields), nil, 903, 3)
	event.HpackFlags = h2HpackRequestUnreliable
	observeH2Headers(t, ctx, event, EventTypeKHTTP2RequestHeaders)
	require.Empty(t, completeH2(t, ctx, event).RequestHeaders)
}

func TestHTTP2HeaderEnrichmentDoesNotUseTrailers(t *testing.T) {
	ctx := headerEnrichmentContext(nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)
	event := h2Event(enc.frame(t, []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/empty"}, {Name: "x-tenant-id", Value: "original"}}), nil, 904, 1)
	observeH2Headers(t, ctx, event, EventTypeKHTTP2RequestHeaders)
	trailers := h2Event(enc.frame(t, []hpack.HeaderField{{Name: "x-tenant-id", Value: "trailer"}}), nil, 904, 1)
	observeH2Headers(t, ctx, trailers, EventTypeKHTTP2RequestHeaders)
	span := completeH2(t, ctx, event)
	require.Equal(t, "original", http.Header(span.RequestHeaders).Get("x-tenant-id"))
}

func TestHTTP2HeaderEnrichmentContinuationAndTruncation(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "continuation", true: "truncated"}[truncated], func(t *testing.T) {
			ctx := headerEnrichmentContext(nil)
			enc := &h2ConnEncoder{}
			enc.enc = hpack.NewEncoder(&enc.buf)
			fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/empty"}, {Name: "x-tenant-id", Value: "alpha"}}
			if truncated {
				fields = append(fields, hpack.HeaderField{Name: "x-padding", Value: strings.Repeat("x", 1200)})
			}
			full := enc.frame(t, fields)
			frame := makeSplitHeadersFrame(t, full[frameHeaderLen:])
			event := h2Event(frame, nil, 905, 1)
			observeH2Headers(t, ctx, event, EventTypeKHTTP2RequestHeaders)
			span := completeH2(t, ctx, event)
			if truncated {
				require.Empty(t, span.RequestHeaders)
			} else {
				require.Equal(t, "alpha", http.Header(span.RequestHeaders).Get("x-tenant-id"))
			}
		})
	}
}
