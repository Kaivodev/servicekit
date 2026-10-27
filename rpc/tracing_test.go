package rpc

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/observability/requestmeta"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestAuthenticatedGRPCSpansPreserveParentAndLogContext(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	clientProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer clientProvider.Shutdown(context.Background())
	serverProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer serverProvider.Shutdown(context.Background())
	certs := materials(t, "iam", "backend")
	options := runtimePolicy(t, serverOptions(), certs["iam"])
	options.TracerProvider = serverProvider
	var access synchronizedBuffer
	server, err := NewServer(options, certs["iam"], logging.New(&access, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, registerTest(handlerFunc(func(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
		if requestmeta.From(ctx).TraceID != trace.SpanContextFromContext(ctx).TraceID().String() {
			t.Error("server log trace differs from span")
		}
		return &emptypb.Empty{}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	connectionCtx, stop := context.WithTimeout(ctx, options.RPC.CallTimeout*5)
	defer stop()
	conn, err := Connect(connectionCtx, certs["backend"], ClientOptions{Address: server.Address(), ServerName: "iam", ExpectedService: "iam", CallTimeout: options.RPC.CallTimeout, MaxMessageBytes: 1024, TracerProvider: clientProvider})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitReady(t, server, true)
	origin, span := clientProvider.Tracer("test").Start(context.Background(), "HTTP origin")
	origin = requestmeta.Ensure(origin)
	if err = conn.Invoke(origin, "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	span.End()
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	spans := recorder.Ended()
	if len(spans) != 3 {
		t.Fatalf("expected HTTP/client/server spans, got %d", len(spans))
	}
	var clientSpan, serverSpan sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.SpanContext().TraceID() != span.SpanContext().TraceID() {
			t.Fatal("gRPC trace was split")
		}
		switch s.SpanKind() {
		case trace.SpanKindClient:
			clientSpan = s
		case trace.SpanKindServer:
			serverSpan = s
		}
	}
	if clientSpan == nil || serverSpan == nil || clientSpan.Parent().SpanID() != span.SpanContext().SpanID() || serverSpan.Parent().SpanID() != clientSpan.SpanContext().SpanID() {
		t.Fatal("gRPC parent chain is incorrect")
	}
}
