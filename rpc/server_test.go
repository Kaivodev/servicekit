package rpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/observability/requestmeta"
	"github.com/aipay-dev/servicekit/authz"
	"github.com/aipay-dev/servicekit/authz/authztest"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/devcert"
	"github.com/aipay-dev/servicekit/mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *synchronizedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

func materials(t *testing.T, names ...string) map[string]*mtls.Material {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", names, time.Hour); err != nil {
		t.Fatal(err)
	}
	result := map[string]*mtls.Material{}
	for _, name := range names {
		material, err := mtls.Load(config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, name, "tls.crt"), KeyFile: filepath.Join(dir, name, "tls.key"), TrustDomain: "aipay.test"}, name)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = material
	}
	return result
}

func serverOptions() ServerOptions {
	return ServerOptions{RPC: config.RPC{Address: "127.0.0.1:0", ServerName: "iam", AllowedPeers: []string{"backend"}, CallTimeout: 200 * time.Millisecond, MaxMessageBytes: 1024, MaxConcurrentStreams: 16}, HealthTimeout: 50 * time.Millisecond, HealthInterval: 10 * time.Millisecond, ShutdownTimeout: 200 * time.Millisecond}
}

func connect(t *testing.T, server *Server, material *mtls.Material, expected, hostname string) (*grpc.ClientConn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	return Connect(ctx, material, ClientOptions{Address: server.Address(), ServerName: hostname, ExpectedService: expected, CallTimeout: time.Second, MaxMessageBytes: 4096})
}

func waitReady(t *testing.T, server *Server, expected bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for server.Ready() != expected {
		if time.Now().After(deadline) {
			t.Fatal("readiness did not converge")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTLSHealthReadinessWatchAndUnknownService(t *testing.T) {
	certs := materials(t, "iam", "backend", "outsider")
	var access synchronizedBuffer
	var dependencyBroken atomic.Bool
	server, err := NewServer(serverOptions(), certs["iam"], logging.New(&access, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), map[string]Check{"database": func(context.Context) error {
		if dependencyBroken.Load() {
			return errors.New("private database details")
		}
		return nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	t.Cleanup(func() { cancel() })
	conn, err := connect(t, server, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitReady(t, server, true)
	ids := requestmeta.New()
	callctx, callcancel := context.WithTimeout(requestmeta.With(context.Background(), ids), time.Second)
	defer callcancel()
	health := healthpb.NewHealthClient(conn)
	result, err := health.Check(callctx, &healthpb.HealthCheckRequest{})
	if err != nil || result.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health=%v err=%v", result, err)
	}
	_, err = health.Check(callctx, &healthpb.HealthCheckRequest{Service: "aipay.iam.v1.IdentityService"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unregistered business service reported healthy: %v", err)
	}
	err = conn.Invoke(callctx, "/aipay.iam.v1.IdentityService/Authenticate", &emptypb.Empty{}, &emptypb.Empty{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("business placeholder returned %v", err)
	}
	watchctx, watchcancel := context.WithTimeout(requestmeta.With(context.Background(), ids), 5*time.Second)
	watch, err := health.Watch(watchctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if update, err := watch.Recv(); err != nil || update.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("watch=%v err=%v", update, err)
	}
	dependencyBroken.Store(true)
	waitReady(t, server, false)
	if update, err := watch.Recv(); err != nil || update.Status != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("watch=%v err=%v", update, err)
	}
	watchcancel()
	_, _ = watch.Recv()
	for _, tc := range []struct{ peer, expected, hostname string }{{"outsider", "iam", "iam"}, {"backend", "ledger", "iam"}, {"backend", "iam", "wrong-host"}} {
		if conn, err := connect(t, server, certs[tc.peer], tc.expected, tc.hostname); err == nil {
			conn.Close()
			t.Fatalf("untrusted connection accepted: %+v", tc)
		}
	}
	other := materials(t, "backend")
	if conn, err := connect(t, server, other["backend"], "iam", "iam"); err == nil {
		conn.Close()
		t.Fatal("foreign CA accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown hung")
	}
	if !bytes.Contains([]byte(access.String()), []byte(ids.TraceID)) || bytes.Contains([]byte(access.String()), []byte("private database details")) {
		t.Fatal("correlation lost or dependency error leaked")
	}
}

// A test-only standard protobuf payload and service descriptor keep all product
// .proto files in their owning repository; no fake business API is shipped.
type testHandler interface {
	Call(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}
type handlerFunc func(context.Context, *emptypb.Empty) (*emptypb.Empty, error)

func (f handlerFunc) Call(ctx context.Context, request *emptypb.Empty) (*emptypb.Empty, error) {
	return f(ctx, request)
}

// runtimePolicy admits backend to the test-only /test.Runtime/Call as a
// service call; without it the server denies the undeclared method.
func runtimePolicy(t *testing.T, options ServerOptions, material *mtls.Material) ServerOptions {
	t.Helper()
	service, err := authztest.Service("test.Runtime", map[string]*descriptorpb.MethodOptions{"Call": authztest.Options(authztest.Rule{Callers: []string{"backend"}, Requirement: authztest.NotRequired})})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := authz.LoadPolicies(service)
	if err != nil {
		t.Fatal(err)
	}
	options.Authorizer, err = authz.New(authz.Options{Service: options.RPC.ServerName, Policies: policies, Peer: material.Peer, Log: logging.New(io.Discard, slog.LevelInfo)})
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func registerTest(handler testHandler) Register {
	return func(registrar grpc.ServiceRegistrar) {
		registrar.RegisterService(&grpc.ServiceDesc{
			ServiceName: "test.Runtime",
			HandlerType: (*testHandler)(nil),
			Methods: []grpc.MethodDesc{{
				MethodName: "Call",
				Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					request := new(emptypb.Empty)
					if err := decode(request); err != nil {
						return nil, err
					}
					call := func(ctx context.Context, request any) (any, error) {
						return srv.(testHandler).Call(ctx, request.(*emptypb.Empty))
					}
					return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/test.Runtime/Call"}, call)
				},
			}},
		}, handler)
	}
}

func TestUnaryDeadlineAndBoundedForcedShutdown(t *testing.T) {
	certs := materials(t, "iam", "backend")
	var ignoreCancel atomic.Bool
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	server, err := NewServer(runtimePolicy(t, serverOptions(), certs["iam"]), certs["iam"], logging.New(io.Discard, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, registerTest(handlerFunc(func(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
		started <- struct{}{}
		if ignoreCancel.Load() {
			<-release
			return &emptypb.Empty{}, nil
		}
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	})))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	conn, err := connect(t, server, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitReady(t, server, true)
	err = conn.Invoke(context.Background(), "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("server deadline was not enforced: %v", err)
	}
	<-started
	ignoreCancel.Store(true)
	go func() {
		_ = conn.Invoke(context.Background(), "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("expected forced drain: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("uncooperative handler bypassed shutdown bound")
	}
}

func TestMessageLimitsCancellationAndGracefulDrain(t *testing.T) {
	certs := materials(t, "iam", "backend")
	started := make(chan context.Context, 4)
	release := make(chan struct{})
	var mode atomic.Int32
	server, err := NewServer(runtimePolicy(t, serverOptions(), certs["iam"]), certs["iam"], logging.New(io.Discard, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, registerTest(handlerFunc(func(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
		switch mode.Load() {
		case 1:
			message := &emptypb.Empty{}
			message.ProtoReflect().SetUnknown(append([]byte{0x0a, 0x80, 0x10}, make([]byte, 2048)...))
			return message, nil
		case 2:
			started <- ctx
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		case 3:
			started <- ctx
			<-release
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
	conn, err := connect(t, server, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitReady(t, server, true)
	large := &emptypb.Empty{}
	large.ProtoReflect().SetUnknown(append([]byte{0x0a, 0x80, 0x10}, make([]byte, 2048)...))
	err = conn.Invoke(context.Background(), "/test.Runtime/Call", large, &emptypb.Empty{})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("receive limit: %v", err)
	}
	mode.Store(1)
	err = conn.Invoke(context.Background(), "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("send limit: %v", err)
	}
	mode.Store(2)
	callctx, stop := context.WithCancel(context.Background())
	callDone := make(chan error, 1)
	go func() { callDone <- conn.Invoke(callctx, "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{}) }()
	serverctx := <-started
	stop()
	select {
	case <-serverctx.Done():
	case <-time.After(time.Second):
		t.Fatal("caller cancellation not propagated")
	}
	if err = <-callDone; status.Code(err) != codes.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
	mode.Store(3)
	go func() {
		callDone <- conn.Invoke(context.Background(), "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
	}()
	<-started
	cancel()
	waitReady(t, server, false)
	select {
	case <-done:
		t.Fatal("shutdown did not drain active RPC")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err = <-callDone; err != nil {
		t.Fatal("in-flight call lost during graceful drain:", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
