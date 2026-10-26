// Package rpc owns authenticated grpc-go transport lifecycles, not business authorization.
package rpc

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aipay-dev/observability/grpcobs"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/mtls"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

var ErrShutdownTimeout = errors.New("RPC shutdown exceeded drain deadline")

type Check func(context.Context) error

type ServerOptions struct {
	TracerProvider  trace.TracerProvider
	RPC             config.RPC
	HealthTimeout   time.Duration
	HealthInterval  time.Duration
	ShutdownTimeout time.Duration
}

type Server struct {
	grpc         *grpc.Server
	listener     net.Listener
	health       *health.Server
	checks       map[string]Check
	log          *slog.Logger
	options      ServerOptions
	started      atomic.Bool
	draining     atomic.Bool
	ready        atomic.Bool
	drainOnce    sync.Once
	drainStarted chan struct{}
	deadline     atomic.Pointer[time.Time]
}

// Register is called only by a service's composition root. Handlers must still
// enforce application permissions and data ownership; peer identity is not RBAC.
type Register func(grpc.ServiceRegistrar)

func NewServer(options ServerOptions, material *mtls.Material, access, runtime *slog.Logger, checks map[string]Check, register Register) (*Server, error) {
	if access == nil || runtime == nil || options.RPC.CallTimeout <= 0 || options.RPC.MaxMessageBytes < 1 || options.RPC.MaxConcurrentStreams < 1 || options.HealthTimeout <= 0 || options.HealthInterval <= 0 || options.ShutdownTimeout <= 0 {
		return nil, errors.New("invalid RPC server options")
	}
	tlsConfig, err := material.Server(options.RPC.AllowedPeers)
	if err != nil {
		return nil, err
	}
	observer, err := grpcobs.NewServer(access, runtime, material.Peer)
	if err != nil {
		return nil, err
	}
	s := &Server{options: options, log: runtime, health: health.NewServer(), checks: make(map[string]Check), drainStarted: make(chan struct{})}
	for name, check := range checks {
		if check == nil || !config.ValidService(name) {
			return nil, errors.New("invalid readiness check")
		}
		s.checks[name] = check
	}
	s.health.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	grpcOptions := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ConnectionTimeout(options.RPC.CallTimeout), grpc.MaxRecvMsgSize(options.RPC.MaxMessageBytes), grpc.MaxSendMsgSize(options.RPC.MaxMessageBytes), grpc.MaxConcurrentStreams(options.RPC.MaxConcurrentStreams),
		grpc.ChainUnaryInterceptor(observer.Unary(), s.unaryGuard()), grpc.StreamInterceptor(s.streamGuard(access, material.Peer)),
	}
	if options.TracerProvider != nil {
		grpcOptions = append(grpcOptions, grpc.StatsHandler(otelgrpc.NewServerHandler(otelgrpc.WithTracerProvider(options.TracerProvider), otelgrpc.WithPropagators(propagation.TraceContext{}))))
	}
	s.grpc = grpc.NewServer(grpcOptions...)
	healthpb.RegisterHealthServer(s.grpc, s.health)
	if register != nil {
		register(s.grpc)
	}
	s.listener, err = net.Listen("tcp", options.RPC.Address)
	if err != nil {
		s.grpc.Stop()
		return nil, errors.New("bind RPC listener failed; check address and port availability")
	}
	return s, nil
}

func (s *Server) Address() string { return s.listener.Addr().String() }
func (s *Server) Ready() bool     { return s.ready.Load() && !s.draining.Load() }

func (s *Server) ShutdownDeadline() time.Time {
	if value := s.deadline.Load(); value != nil {
		return *value
	}
	return time.Now().Add(s.options.ShutdownTimeout)
}

// Close releases a server that was constructed but not run, for startup cleanup.
func (s *Server) Close() {
	s.beginDrain()
	s.grpc.Stop()
	_ = s.listener.Close()
}

func (s *Server) Run(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("RPC server can only run once")
	}
	defer s.listener.Close()
	if ctx.Err() != nil {
		s.Close()
		return nil
	}
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); s.monitor(monitorCtx) }()
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.grpc.Serve(s.listener) }()
	s.log.Info("rpc listener started", "address", s.Address())
	var serveErr error
	select {
	case serveErr = <-serveDone:
	case <-ctx.Done():
	}
	s.beginDrain()
	stopMonitor()
	// The monitor owns only context-aware checks and is bounded by HealthTimeout.
	<-monitorDone
	drained := make(chan struct{})
	go func() { s.grpc.GracefulStop(); close(drained) }()
	timer := time.NewTimer(time.Until(s.ShutdownDeadline()))
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		// A misbehaving handler may ignore cancellation; grpc-go's GracefulStop
		// waits for handlers. Never extend the process deadline waiting for it.
		go s.grpc.Stop()
		s.log.Warn("rpc shutdown forced after drain deadline")
		return ErrShutdownTimeout
	}
	if serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) && !errors.Is(serveErr, net.ErrClosed) {
		return errors.New("RPC listener stopped unexpectedly")
	}
	s.log.Info("rpc listener stopped")
	return nil
}

func (s *Server) beginDrain() {
	s.drainOnce.Do(func() {
		deadline := time.Now().Add(s.options.ShutdownTimeout)
		s.deadline.Store(&deadline)
		s.draining.Store(true)
		s.ready.Store(false)
		s.health.Shutdown()
		close(s.drainStarted)
	})
}

func (s *Server) monitor(ctx context.Context) {
	ticker := time.NewTicker(s.options.HealthInterval)
	defer ticker.Stop()
	last := "initial"
	for {
		failed := s.check(ctx)
		if ctx.Err() != nil || s.draining.Load() {
			return
		}
		ready := len(failed) == 0
		s.ready.Store(ready)
		value := healthpb.HealthCheckResponse_NOT_SERVING
		if ready {
			value = healthpb.HealthCheckResponse_SERVING
		}
		s.health.SetServingStatus("", value)
		state := strings.Join(failed, ",")
		if state != last {
			s.log.Info("rpc readiness changed", "ready", ready, "failed_dependencies", failed)
			last = state
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) check(parent context.Context) []string {
	ctx, cancel := context.WithTimeout(parent, s.options.HealthTimeout)
	defer cancel()
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(s.checks))
	pending := make(map[string]bool, len(s.checks))
	for name, check := range s.checks {
		pending[name] = true
		go func() { results <- result{name, check(ctx)} }()
	}
	var failed []string
	for len(pending) > 0 {
		select {
		case item := <-results:
			delete(pending, item.name)
			if item.err != nil {
				failed = append(failed, item.name)
			}
		case <-ctx.Done():
			for name := range pending {
				failed = append(failed, name)
			}
			sort.Strings(failed)
			return failed
		}
	}
	sort.Strings(failed)
	return failed
}

func (s *Server) unaryGuard() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") && !s.Ready() {
			return nil, status.Error(codes.Unavailable, "Service is not ready")
		}
		ctx, cancel := context.WithTimeout(ctx, s.options.RPC.CallTimeout)
		defer cancel()
		return handler(ctx, req)
	}
}
