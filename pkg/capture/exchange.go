// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture // import "go.opentelemetry.io/obi/pkg/capture"

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
)

type ExchangeKind uint8

const (
	ExchangeRequest ExchangeKind = iota
	ExchangeDNS
)

type Protocol string

const (
	ProtocolHTTP       Protocol = "http"
	ProtocolGRPC       Protocol = "grpc"
	ProtocolPostgreSQL Protocol = "postgresql"
	ProtocolMySQL      Protocol = "mysql"
	ProtocolMSSQL      Protocol = "mssql"
	ProtocolSQL        Protocol = "sql"
	ProtocolRedis      Protocol = "redis"
	ProtocolKafka      Protocol = "kafka"
	ProtocolMongoDB    Protocol = "mongodb"
)

// Exchange is an observed request or DNS answer. Headers follow Options.HeaderPrefixes.
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
	Protocol             Protocol
	Operation            string
	RequestHeaders       map[string][]string
	RequestMessageBytes  int64
	ResponseMessageBytes int64
	Duration             time.Duration
	Status               int
	QueryName            string
	Answers              []netip.Addr
}

func exchangeFromSpan(s *request.Span) (Exchange, bool) {
	switch s.Type {
	case request.EventTypeDNS:
		return dnsExchange(s)
	case request.EventTypeHTTP, request.EventTypeHTTPClient:
		return httpExchange(s, ProtocolHTTP, s.Method), true
	case request.EventTypeGRPC, request.EventTypeGRPCClient:
		return httpExchange(s, ProtocolGRPC, ""), true
	case request.EventTypeSQLClient, request.EventTypeSQLServer:
		return requestExchange(s, sqlProtocol(s.SubType), s.Method), true
	case request.EventTypeRedisClient, request.EventTypeRedisServer:
		return requestExchange(s, ProtocolRedis, s.Method), true
	case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
		return requestExchange(s, ProtocolKafka, kafkaOperation(s.Method)), true
	case request.EventTypeMongoClient:
		return requestExchange(s, ProtocolMongoDB, s.Method), true
	}
	return Exchange{}, false
}

func kafkaOperation(method string) string {
	switch method {
	case request.MessagingSend, request.MessagingPublish:
		return "produce"
	case request.MessagingProcess:
		return "fetch"
	}
	return method
}

func sqlProtocol(kind int) Protocol {
	switch request.SQLKind(kind) {
	case request.DBPostgres:
		return ProtocolPostgreSQL
	case request.DBMySQL:
		return ProtocolMySQL
	case request.DBMSSQL:
		return ProtocolMSSQL
	}
	return ProtocolSQL
}

func httpExchange(s *request.Span, protocol Protocol, operation string) Exchange {
	exchange := requestExchange(s, protocol, operation)
	exchange.ServerAddress = serverAddress(s.Statement)
	return exchange
}

func requestExchange(s *request.Span, protocol Protocol, operation string) Exchange {
	return Exchange{
		Kind: ExchangeRequest, Protocol: protocol, Operation: operation, Client: s.IsClientSpan(), HostPID: uint32(s.Pid.HostPID),
		SrcIP: s.Peer, DstIP: s.Host, DstPort: s.HostPort,
		RequestHeaders:       s.RequestHeaders,
		RequestMessageBytes:  s.RequestMessageBytes,
		ResponseMessageBytes: s.ResponseMessageBytes,
		Duration:             time.Duration(s.End - s.RequestStart),
		Status:               s.Status,
	}
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
