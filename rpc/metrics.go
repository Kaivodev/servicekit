package rpc

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Kaivodev/servicekit/internal/instruments"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

const healthPrefix = "/grpc.health.v1.Health/"

var rpcBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
var clientMethod = regexp.MustCompile(`^/[A-Za-z0-9_.]+/[A-Za-z0-9_]+$`)

type methodName struct{ service, method string }

var other = methodName{"other", "other"}

func (n methodName) result(err error) metric.MeasurementOption {
	st, ok := status.FromError(err)
	if !ok {
		st = status.FromContextError(err)
	}
	return n.attributes(st.Code())
}
func (n methodName) attributes(code codes.Code) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("rpc_service", n.service), attribute.String("rpc_method", n.method), attribute.String("grpc_code", code.String()))
}

func duration(m metric.Meter, name string) metric.Float64Histogram {
	h, _ := m.Float64Histogram(name, metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(rpcBuckets...))
	return h
}

func clientMetrics(provider metric.MeterProvider) grpc.UnaryClientInterceptor {
	h := duration(instruments.Meter(provider, "rpc"), "kaivo.rpc.client.duration")
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if provider == nil || strings.HasPrefix(method, healthPrefix) {
			return invoke(ctx, method, req, reply, cc, opts...)
		}
		n := other
		if clientMethod.MatchString(method) {
			n.service, n.method, _ = strings.Cut(method[1:], "/")
		}
		start := time.Now()
		err := invoke(ctx, method, req, reply, cc, opts...)
		h.Record(ctx, time.Since(start).Seconds(), n.result(err))
		return err
	}
}

type serverMetrics struct {
	meter      metric.Meter
	readyReg   metric.Registration
	methods    map[string]methodName
	duration   metric.Float64Histogram
	streams    metric.Int64Counter
	active     metric.Int64UpDownCounter
	denied     metric.Int64Counter
	dependency metric.Int64Gauge
}

func newServerMetrics(provider metric.MeterProvider) *serverMetrics {
	m := instruments.Meter(provider, "rpc")
	streams, _ := m.Int64Counter("kaivo.rpc.server.streams")
	active, _ := m.Int64UpDownCounter("kaivo.rpc.server.active")
	denied, _ := m.Int64Counter("kaivo.authz.denied")
	dependency, _ := m.Int64Gauge("kaivo.service.dependency.ready")
	return &serverMetrics{
		meter: m, methods: make(map[string]methodName),
		duration: duration(m, "kaivo.rpc.server.duration"), streams: streams,
		active: active, denied: denied, dependency: dependency,
	}
}

func (m *serverMetrics) observeServer(s *Server) {
	for svc, info := range s.grpc.GetServiceInfo() {
		for _, method := range info.Methods {
			m.methods["/"+svc+"/"+method.Name] = methodName{svc, method.Name}
		}
	}
	gauge, _ := m.meter.Int64ObservableGauge("kaivo.service.ready")
	m.readyReg, _ = m.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(gauge, boolValue(s.Ready()))
		return nil
	}, gauge)
}

func (m *serverMetrics) close() {
	if m != nil && m.readyReg != nil {
		_ = m.readyReg.Unregister()
	}
}

func boolValue(ready bool) int64 {
	if ready {
		return 1
	}
	return 0
}

func (m *serverMetrics) recordDependencies(ctx context.Context, checks map[string]Check, failed []string) {
	for name := range checks {
		_, unready := slices.BinarySearch(failed, name)
		m.dependency.Record(ctx, boolValue(!unready), metric.WithAttributes(attribute.String("dependency", name)))
	}
}

func (m *serverMetrics) denials(peer func(context.Context) (string, error)) func(context.Context, string, string, string) {
	return func(ctx context.Context, full, caller, reason string) {
		if strings.HasPrefix(full, healthPrefix) {
			return
		}
		// The fallback has no Authorizer to verify the peer. Read the same verified
		// transport identity here without changing its original decision.
		if reason == "undeclared" {
			if identity, err := peer(ctx); err == nil {
				caller = identity
			}
		}
		if caller == "" {
			caller = "unverified"
		}
		n := m.registered(full)
		m.denied.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_service", n.service), attribute.String("rpc_method", n.method),
			attribute.String("peer_service", caller), attribute.String("reason", reason),
		))
	}
}

func (m *serverMetrics) registered(full string) methodName {
	if n, ok := m.methods[full]; ok {
		return n
	}
	return other
}

func (m *serverMetrics) admitted(ctx context.Context, n methodName) func() {
	opts := metric.WithAttributes(attribute.String("rpc_service", n.service))
	m.active.Add(ctx, 1, opts)
	return func() { m.active.Add(ctx, -1, opts) }
}

func (m *serverMetrics) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if strings.HasPrefix(info.FullMethod, healthPrefix) {
		return handler(ctx, req)
	}
	n := m.registered(info.FullMethod)
	defer m.admitted(ctx, n)()
	start := time.Now()
	resp, err := handler(ctx, req)
	m.duration.Record(ctx, time.Since(start).Seconds(), n.result(err))
	return resp, err
}

func (m *serverMetrics) stream(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if strings.HasPrefix(info.FullMethod, healthPrefix) {
		return handler(server, stream)
	}
	ctx := stream.Context()
	n := m.registered(info.FullMethod)
	defer m.admitted(ctx, n)()
	err := handler(server, stream)
	m.streams.Add(ctx, 1, n.result(err))
	return err
}

// grpc-go rejects an unknown method before dispatching any interceptor. Its
// wire request has no method descriptor or streaming flags. Measure this short
// rejection in the duration histogram and leave grpc-go's response untouched.
type unknownRPCStats struct{ m *serverMetrics }
type unknownStart struct{}

func (h unknownRPCStats) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	if _, ok := h.m.methods[info.FullMethodName]; ok || strings.HasPrefix(info.FullMethodName, healthPrefix) {
		return ctx
	}
	// The transport cancels ctx on both a successful trailer and a socket failure.
	context.AfterFunc(ctx, h.m.admitted(ctx, other))
	return context.WithValue(ctx, unknownStart{}, time.Now())
}
func (h unknownRPCStats) HandleRPC(ctx context.Context, event stats.RPCStats) {
	if _, ok := event.(*stats.OutTrailer); !ok {
		return
	}
	if start, ok := ctx.Value(unknownStart{}).(time.Time); ok {
		h.m.duration.Record(ctx, time.Since(start).Seconds(), other.attributes(codes.Unimplemented))
	}
}
func (unknownRPCStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }
func (unknownRPCStats) HandleConn(context.Context, stats.ConnStats)                       {}
