//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/observability/tracing"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/devcert"
	"github.com/aipay-dev/servicekit/mtls"
	"github.com/aipay-dev/servicekit/rpc"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type traceBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *traceBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *traceBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

type traceSink struct {
	collector.UnimplementedTraceServiceServer
	mu        sync.Mutex
	resources []*tracepb.ResourceSpans
	forward   collector.TraceServiceClient
}

func (s *traceSink) Export(ctx context.Context, req *collector.ExportTraceServiceRequest) (*collector.ExportTraceServiceResponse, error) {
	s.mu.Lock()
	for _, r := range req.ResourceSpans {
		s.resources = append(s.resources, proto.Clone(r).(*tracepb.ResourceSpans))
	}
	s.mu.Unlock()
	if s.forward != nil {
		return s.forward.Export(ctx, req)
	}
	return &collector.ExportTraceServiceResponse{}, nil
}
func (s *traceSink) snapshot() []*tracepb.ResourceSpans {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*tracepb.ResourceSpans(nil), s.resources...)
}
func startSink(t *testing.T) (*traceSink, string) {
	t.Helper()
	sink := new(traceSink)
	if target := os.Getenv("AIPAY_TEST_OTLP_TARGET"); target != "" {
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		sink.forward = collector.NewTraceServiceClient(conn)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	collector.RegisterTraceServiceServer(server, sink)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return sink, "http://" + listener.Addr().String()
}
func traceRuntime(t *testing.T, endpoint, name string, logs *traceBuffer) *tracing.Runtime {
	t.Helper()
	cfg := tracing.DefaultConfig()
	cfg.Endpoint = endpoint
	cfg.BatchInterval = 50 * time.Millisecond
	rt, err := tracing.Open(context.Background(), tracing.Options{Config: cfg, Service: name, Version: "integration", Instance: name + "-test"}, logging.New(logs, slog.LevelInfo))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(context.Background()) })
	return rt
}
func traceMaterials(t *testing.T) map[string]*mtls.Material {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"backend", "iam", "ledger"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	result := map[string]*mtls.Material{}
	for _, name := range []string{"backend", "iam", "ledger"} {
		m, err := mtls.Load(config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, name, "tls.crt"), KeyFile: filepath.Join(dir, name, "tls.key"), TrustDomain: "aipay.test"}, name)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = m
	}
	return result
}

// Only this test binary registers the fixture RPC; it is not a product contract.
type fixtureRPC interface {
	Call(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}
type fixtureCall func(context.Context, *emptypb.Empty) (*emptypb.Empty, error)

func (f fixtureCall) Call(ctx context.Context, p *emptypb.Empty) (*emptypb.Empty, error) {
	return f(ctx, p)
}
func fixtureRegister(f fixtureCall) rpc.Register {
	return func(r grpc.ServiceRegistrar) {
		r.RegisterService(&grpc.ServiceDesc{ServiceName: "test.Trace", HandlerType: (*fixtureRPC)(nil), Methods: []grpc.MethodDesc{{MethodName: "Call", Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			p := new(emptypb.Empty)
			if err := decode(p); err != nil {
				return nil, err
			}
			call := func(ctx context.Context, p any) (any, error) { return srv.(fixtureRPC).Call(ctx, p.(*emptypb.Empty)) }
			return interceptor(ctx, p, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/test.Trace/Call"}, call)
		}}}}, f)
	}
}
func startFixtureRPC(t *testing.T, name, peer string, material *mtls.Material, rt *tracing.Runtime, logs *traceBuffer, handler fixtureCall) *rpc.Server {
	t.Helper()
	log := logging.New(logs, slog.LevelInfo)
	server, err := rpc.NewServer(rpc.ServerOptions{RPC: config.RPC{Address: "127.0.0.1:0", ServerName: name, AllowedPeers: []string{peer}, CallTimeout: 3 * time.Second, MaxMessageBytes: 4096, MaxConcurrentStreams: 16}, HealthTimeout: time.Second, HealthInterval: 20 * time.Millisecond, ShutdownTimeout: 2 * time.Second, TracerProvider: rt.Provider()}, material, log, log, nil, fixtureRegister(handler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("RPC cleanup timeout")
		}
	})
	eventually(t, 3*time.Second, "RPC readiness", func() bool { return server.Ready() })
	return server
}
func traceConnect(t *testing.T, server *rpc.Server, name string, material *mtls.Material, rt *tracing.Runtime) *grpc.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := rpc.Connect(ctx, material, rpc.ClientOptions{Address: server.Address(), ServerName: name, ExpectedService: name, CallTimeout: 2 * time.Second, MaxMessageBytes: 4096, TracerProvider: rt.Provider()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func eventually(t *testing.T, budget time.Duration, label string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal(fmt.Sprintf("timed out waiting for %s", label))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
