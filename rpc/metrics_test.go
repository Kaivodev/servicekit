package rpc

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kaivodev/observability/logging"
	"github.com/Kaivodev/servicekit/authz"
	"github.com/Kaivodev/servicekit/authz/authztest"
	"github.com/Kaivodev/servicekit/signing"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func collected(t *testing.T, r *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var data metricdata.ResourceMetrics
	if err := r.Collect(t.Context(), &data); err != nil {
		t.Fatal(err)
	}
	out := map[string]metricdata.Metrics{}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func TestRPCMetricsOverTLS(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	certs := materials(t, "iam", "backend")
	log := logging.New(io.Discard, slog.LevelInfo)
	opts := serverOptions()
	opts.MeterProvider = mp
	var available atomic.Bool
	checks := map[string]Check{"db": func(context.Context) error {
		if available.Load() {
			return nil
		}
		return errors.New("unavailable")
	}}
	const full = "/test.Runtime/Call"
	server, err := NewServer(opts, certs["iam"], log, log, checks, func(r grpc.ServiceRegistrar) {
		registerTest(handlerFunc(func(context.Context, *emptypb.Empty) (*emptypb.Empty, error) { panic("unreachable") }))(r)
		r.RegisterService(&grpc.ServiceDesc{ServiceName: "test.Stream", HandlerType: (*testHandler)(nil), Streams: []grpc.StreamDesc{{StreamName: "Watch", ServerStreams: true, Handler: func(any, grpc.ServerStream) error { panic("unreachable") }}}}, handlerFunc(nil))
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	dial, stopDial := context.WithTimeout(ctx, 2*time.Second)
	defer stopDial()
	conn, err := Connect(dial, certs["backend"], ClientOptions{MeterProvider: mp, Address: server.Address(), ExpectedService: "iam", ServerName: "iam", CallTimeout: time.Second, MaxMessageBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	invoke := func(method string, want codes.Code) {
		t.Helper()
		err := conn.Invoke(ctx, method, &emptypb.Empty{}, &emptypb.Empty{})
		if status.Code(err) != want {
			t.Fatalf("%s: %v", method, err)
		}
	}
	invoke(full, codes.Unavailable)
	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	watchCtx, stopWatch := context.WithTimeout(ctx, time.Second)
	watch, err := healthpb.NewHealthClient(conn).Watch(watchCtx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := watch.Recv(); err != nil {
		t.Fatal(err)
	}
	stopWatch()
	_, _ = watch.Recv()
	before := collected(t, reader)
	if before["kaivo.service.ready"].Data.(metricdata.Gauge[int64]).DataPoints[0].Value != 0 {
		t.Fatal("already ready")
	}
	available.Store(true)
	waitReady(t, server, true)
	invoke(full, codes.PermissionDenied)
	invoke("/bad!service/Unknown", codes.Unimplemented)
	invoke("/test.Runtime/Absent", codes.Unimplemented)
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/test.Stream/Watch")
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.CloseSend()
	if err := stream.RecvMsg(&emptypb.Empty{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	metrics := collected(t, reader)
	attrs := func(service, method, code string) attribute.Set {
		return attribute.NewSet(attribute.String("rpc_service", service), attribute.String("rpc_method", method), attribute.String("grpc_code", code))
	}
	if len(metrics) != 7 {
		t.Fatalf("unexpected instrument set: %v", metrics)
	}
	for _, name := range []string{"kaivo.rpc.server.duration", "kaivo.rpc.client.duration"} {
		m := metrics[name]
		want := map[attribute.Set]uint64{attrs("test.Runtime", "Call", "PermissionDenied"): 1, attrs("test.Runtime", "Call", "Unavailable"): 1, attrs("other", "other", "Unimplemented"): 1}
		if name == "kaivo.rpc.client.duration" {
			want[attrs("test.Runtime", "Absent", "Unimplemented")] = 1
		} else {
			want[attrs("other", "other", "Unimplemented")] = 2
		}
		for _, p := range m.Data.(metricdata.Histogram[float64]).DataPoints {
			if m.Unit != "s" || want[p.Attributes] != p.Count || p.Count == 0 || !slices.Equal(p.Bounds, []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}) {
				t.Fatalf("%s: %v", name, p)
			}
			delete(want, p.Attributes)
		}
		if len(want) != 0 {
			t.Fatal(name, want)
		}
	}
	for n, m := range metrics {
		if n != "kaivo.rpc.server.duration" && n != "kaivo.rpc.client.duration" && m.Unit != "" {
			t.Fatal(n, m.Unit)
		}
	}
	streams := metrics["kaivo.rpc.server.streams"].Data.(metricdata.Sum[int64])
	if !streams.IsMonotonic || len(streams.DataPoints) != 1 || streams.DataPoints[0].Value != 1 || streams.DataPoints[0].Attributes != attrs("test.Stream", "Watch", "PermissionDenied") {
		t.Fatal(streams)
	}
	denied := metrics["kaivo.authz.denied"].Data.(metricdata.Sum[int64])
	if !denied.IsMonotonic || len(denied.DataPoints) != 2 {
		t.Fatal(denied)
	}
	for _, p := range denied.DataPoints {
		service, _ := p.Attributes.Value("rpc_service")
		method := map[string]string{"test.Stream": "Watch", "test.Runtime": "Call"}[service.AsString()]
		want := attribute.NewSet(attribute.String("rpc_service", service.AsString()), attribute.String("rpc_method", method), attribute.String("peer_service", "backend"), attribute.String("reason", "undeclared"))
		if method == "" || p.Value != 1 || p.Attributes != want {
			t.Fatal(p)
		}
	}
	active := metrics["kaivo.rpc.server.active"].Data.(metricdata.Sum[int64])
	if active.IsMonotonic {
		t.Fatal(active)
	}
	for _, p := range active.DataPoints {
		v, ok := p.Attributes.Value("rpc_service")
		if !ok || v.AsString() == "grpc.health.v1.Health" || p.Attributes.Len() != 1 || p.Value != 0 {
			t.Fatal(p)
		}
	}
	ready := metrics["kaivo.service.ready"].Data.(metricdata.Gauge[int64]).DataPoints
	dep := metrics["kaivo.service.dependency.ready"].Data.(metricdata.Gauge[int64]).DataPoints
	if len(ready) != 1 || ready[0].Value != 1 || ready[0].Attributes.Len() != 0 || len(dep) != 1 || dep[0].Value != 1 || dep[0].Attributes != attribute.NewSet(attribute.String("dependency", "db")) {
		t.Fatal(ready, dep)
	}
}

func TestAuthorizerDenialMetrics(t *testing.T) {
	certs := materials(t, "iam", "backend")
	log := logging.New(io.Discard, slog.LevelInfo)
	desc, err := authztest.Service("test.Runtime", map[string]*descriptorpb.MethodOptions{"Call": authztest.Options(authztest.Rule{Callers: []string{"ledger"}, Requirement: authztest.NotRequired})})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := authz.LoadPolicies(desc)
	if err != nil {
		t.Fatal(err)
	}
	var verified atomic.Bool
	a, err := authz.New(authz.Options{Service: "iam", Policies: policies, Peer: func(ctx context.Context) (string, error) {
		if !verified.Load() {
			return "must-not-be-reported", errors.New("unverified")
		}
		return certs["iam"].Peer(ctx)
	}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	opts := serverOptions()
	opts.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	opts.Authorizer = a
	server, err := NewServer(opts, certs["iam"], log, log, nil, registerTest(handlerFunc(nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	defer func() { cancel(); <-done }()
	conn, err := connect(t, server, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitReady(t, server, true)
	for _, ok := range []bool{false, true} {
		verified.Store(ok)
		err = conn.Invoke(ctx, "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
		want := codes.Unauthenticated
		if ok {
			want = codes.PermissionDenied
		}
		if status.Code(err) != want {
			t.Fatal(err)
		}
	}
	points := collected(t, reader)["kaivo.authz.denied"].Data.(metricdata.Sum[int64]).DataPoints
	if len(points) != 2 {
		t.Fatal(points)
	}
	for _, p := range points {
		peer, _ := p.Attributes.Value("peer_service")
		reason := map[string]string{"backend": "caller_not_allowed", "unverified": "peer_unverified"}[peer.AsString()]
		want := attribute.NewSet(attribute.String("rpc_method", "Call"), attribute.String("rpc_service", "test.Runtime"), attribute.String("peer_service", peer.AsString()), attribute.String("reason", reason))
		if reason == "" || p.Attributes != want || p.Value != 1 {
			t.Fatal(p)
		}
	}
}

func TestActiveRPCWhileDraining(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	certs := materials(t, "iam", "backend")
	opts := runtimePolicy(t, serverOptions(), certs["iam"])
	opts.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	opts.ShutdownTimeout = 3 * time.Second
	entered, release := make(chan struct{}), make(chan struct{})
	handler := handlerFunc(func(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
		close(entered)
		<-release
		return &emptypb.Empty{}, nil
	})
	log := logging.New(io.Discard, slog.LevelInfo)
	srv, err := NewServer(opts, certs["iam"], log, log, nil, registerTest(handler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	defer func() {
		close(release)
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	conn, err := connect(t, srv, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitReady(t, srv, true)
	go conn.Invoke(ctx, "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("call did not start")
	}
	cancel()
	<-srv.drainStarted
	ms := collected(t, reader)
	active := ms["kaivo.rpc.server.active"].Data.(metricdata.Sum[int64]).DataPoints
	if len(active) != 1 || active[0].Attributes != attribute.NewSet(attribute.String("rpc_service", "test.Runtime")) || active[0].Value != 1 {
		t.Fatal(active)
	}
	if p := ms["kaivo.service.ready"].Data.(metricdata.Gauge[int64]).DataPoints[0]; p.Value != 0 || srv.Ready() {
		t.Fatal("draining server still ready")
	}
}

func TestAssertionReasonMetric(t *testing.T) {
	certs := materials(t, "iam", "backend")
	desc, err := authztest.Service("test.Runtime", map[string]*descriptorpb.MethodOptions{
		"Call": authztest.Options(authztest.Rule{Callers: []string{"backend"}, Requirement: authztest.Required, Permissions: []string{"test.read"}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := authz.LoadPolicies(desc)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := signing.NewPublicKeys(map[string]*ecdsa.PublicKey{"iam": &newAuthority(t).key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authz.NewAssertionVerifier(authz.VerifierConfig{Issuer: "iam", Audience: "iam", Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	opts := serverOptions()
	opts.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	opts.Authorizer, err = authz.New(authz.Options{Service: "iam", Policies: policies, Peer: certs["iam"].Peer, Assertions: verifier, Log: logging.New(io.Discard, slog.LevelInfo)})
	if err != nil {
		t.Fatal(err)
	}
	srv := runServer(t, opts, certs["iam"], registerTest(handlerFunc(nil)))
	conn, err := connect(t, srv, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := metadata.AppendToOutgoingContext(t.Context(), authz.MetadataKey, "malformed-assertion")
	if err := conn.Invoke(ctx, "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	points := collected(t, reader)["kaivo.authz.denied"].Data.(metricdata.Sum[int64]).DataPoints
	want := attribute.NewSet(attribute.String("rpc_service", "test.Runtime"), attribute.String("rpc_method", "Call"), attribute.String("peer_service", "backend"), attribute.String("reason", "assertion_malformed"))
	if len(points) != 1 || points[0].Attributes != want || points[0].Value != 1 {
		t.Fatal(points)
	}
}
