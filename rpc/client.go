package rpc

import (
	"context"
	"errors"
	"time"

	"github.com/aipay-dev/observability/grpcobs"
	"github.com/aipay-dev/observability/requestmeta"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type ClientOptions struct {
	Address         string
	ServerName      string
	ExpectedService string
	CallTimeout     time.Duration
	MaxMessageBytes int
}

// Connect establishes a real authenticated connection within ctx's deadline.
// The returned connection belongs to the caller and must be closed on shutdown.
func Connect(ctx context.Context, material *mtls.Material, options ClientOptions) (*grpc.ClientConn, error) {
	if options.Address == "" || options.CallTimeout <= 0 || options.MaxMessageBytes < 1 {
		return nil, errors.New("invalid RPC client options")
	}
	if err := config.ValidateAddress(options.Address); err != nil {
		return nil, errors.New("RPC target must be a host and port")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("RPC connection requires a startup deadline")
	}
	tlsConfig, err := material.Client(options.ServerName, options.ExpectedService)
	if err != nil {
		return nil, err
	}
	connection, err := grpc.NewClient("passthrough:///"+options.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(options.MaxMessageBytes), grpc.MaxCallSendMsgSize(options.MaxMessageBytes)),
		grpc.WithChainUnaryInterceptor(clientDeadline(options.CallTimeout), grpcobs.UnaryClient()),
		grpc.WithStreamInterceptor(streamClientCorrelation()),
	)
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
