package rpc

import (
	"context"
	"errors"
	"time"

	"github.com/Kaivodev/observability/grpcobs"
	"github.com/Kaivodev/observability/requestmeta"
	"github.com/Kaivodev/servicekit/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
)

type ClientOptions struct {
	MeterProvider   metric.MeterProvider
	TracerProvider  trace.TracerProvider
	Address         string
	ServerName      string
	ExpectedService string
	CallTimeout     time.Duration
	MaxMessageBytes int
}

// Connect establishes a connection within ctx's deadline. Plaintext calls authenticate per RPC.
// The returned connection belongs to the caller and must be closed on shutdown.
func Connect(ctx context.Context, transport Transport, options ClientOptions) (*grpc.ClientConn, error) {
	if transport == nil || options.Address == "" || options.CallTimeout <= 0 || options.MaxMessageBytes < 1 {
		return nil, errors.New("invalid RPC client options")
	}
	if err := config.ValidateAddress(options.Address); err != nil {
		return nil, errors.New("RPC target must be a host and port")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("RPC connection requires a startup deadline")
	}
	dialOptions, err := transport.DialOptions(options.ServerName, options.ExpectedService)
	if err != nil {
		return nil, err
	}
	dialOptions = append(dialOptions, grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(options.MaxMessageBytes), grpc.MaxCallSendMsgSize(options.MaxMessageBytes)),
		grpc.WithChainUnaryInterceptor(clientMetrics(options.MeterProvider), clientDeadline(options.CallTimeout), grpcobs.UnaryClient()),
		grpc.WithChainStreamInterceptor(streamClientCorrelation()),
	)
	if options.TracerProvider != nil {
		dialOptions = append(dialOptions, grpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithMeterProvider(noop.NewMeterProvider()), otelgrpc.WithTracerProvider(options.TracerProvider), otelgrpc.WithPropagators(propagation.TraceContext{}))))
	}
	connection, err := grpc.NewClient("passthrough:///"+options.Address, dialOptions...)
	if err != nil {
		return nil, errors.New("create RPC connection failed")
	}
	connection.Connect()
	for {
		state := connection.GetState()
		if state == connectivity.Ready {
			return connection, nil
		}
		if state == connectivity.Shutdown || !connection.WaitForStateChange(ctx, state) {
			_ = connection.Close()
			return nil, errors.New("RPC connection was not ready before the startup deadline")
		}
	}
}

func clientDeadline(limit time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, options ...grpc.CallOption) error {
		ctx, cancel := context.WithTimeout(ctx, limit)
		defer cancel()
		return invoke(ctx, method, req, reply, cc, options...)
	}
}

// Stream lifetime remains caller-controlled (health Watch is intentionally long
// lived); cancellation and connection shutdown terminate the stream.
func streamClientCorrelation() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, options ...grpc.CallOption) (grpc.ClientStream, error) {
		ids := requestmeta.From(ctx)
		if !ids.Valid() {
			ids = requestmeta.New()
			ctx = requestmeta.With(ctx, ids)
		}
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(grpcobs.RequestIDHeader, ids.RequestID)
		md.Set(grpcobs.TraceIDHeader, ids.TraceID)
		return streamer(metadata.NewOutgoingContext(ctx, md), desc, cc, method, options...)
	}
}
