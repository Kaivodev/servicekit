package rpc

import (
	"context"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Kaivodev/observability/grpcobs"
	"github.com/Kaivodev/observability/requestmeta"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextStream) Context() context.Context { return s.ctx }

// Health Watch is a streaming RPC too: it must not bypass peer identity checks
// or panic recovery simply because the shared unary observer is not invoked.
func (s *Server) streamGuard(access *slog.Logger, authenticate grpcobs.Authenticate) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		ctx := requestmeta.With(stream.Context(), requestmeta.New())
		started := time.Now()
		peerService := ""
		defer func() {
			if recover() != nil {
				s.log.ErrorContext(ctx, "rpc stream panic", "method", info.FullMethod, "stack", string(debug.Stack()))
				err = status.Error(codes.Internal, "Internal Server Error")
			}
			code := status.Code(err)
			if err == context.Canceled {
				code = codes.Canceled
			}
			if err == context.DeadlineExceeded {
				code = codes.DeadlineExceeded
			}
			level := slog.LevelInfo
			if code != codes.OK {
				level = slog.LevelWarn
			}
			access.Log(ctx, level, "rpc stream", "protocol", "grpc", "direction", "inbound", "method", info.FullMethod, "peer_service", peerService, "code", code.String(), "failed", code != codes.OK, "duration_ms", time.Since(started).Milliseconds())
		}()
		peer, authErr := authenticate(ctx)
		if authErr != nil {
			return status.Error(codes.Unauthenticated, "Service authentication required")
		}
		peerService = peer
		md, _ := metadata.FromIncomingContext(ctx)
		requests, traces := md.Get(grpcobs.RequestIDHeader), md.Get(grpcobs.TraceIDHeader)
		if len(requests) != 0 || len(traces) != 0 {
			if len(requests) != 1 || len(traces) != 1 {
				return status.Error(codes.InvalidArgument, "Invalid correlation metadata")
			}
			ids := requestmeta.Info{RequestID: requests[0], TraceID: traces[0]}
			if !ids.Valid() {
				return status.Error(codes.InvalidArgument, "Invalid correlation metadata")
			}
			ctx = requestmeta.With(ctx, ids)
		}
		if !strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") && !s.Ready() {
			return status.Error(codes.Unavailable, "Service is not ready")
		}
		// A health watch is an open-ended control stream, not business work.
		// Close it when draining so a well-behaved watcher cannot force every
		// graceful shutdown to exhaust its deadline.
		if info.FullMethod == "/grpc.health.v1.Health/Watch" {
			watchctx, cancel := context.WithCancel(ctx)
			defer cancel()
			go func() {
				select {
				case <-s.drainStarted:
					cancel()
				case <-watchctx.Done():
				}
			}()
			ctx = watchctx
		}
		ids := requestmeta.From(ctx)
		_ = stream.SetHeader(metadata.Pairs(grpcobs.RequestIDHeader, ids.RequestID, grpcobs.TraceIDHeader, ids.TraceID))
		return handler(server, &contextStream{ServerStream: stream, ctx: ctx})
	}
}
