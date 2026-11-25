package servicetoken

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const header = "x-kaivo-service-token"
const maxTokenBytes = 64 << 10
const healthPrefix = "/grpc.health.v1.Health/"

// ErrHealthProbe indicates that an anonymous health call has no service identity.
var ErrHealthProbe = errors.New("anonymous health probe")
var unauthenticated = status.Error(codes.Unauthenticated, "Service authentication required")

type snapshot struct {
	keys keySet
	hash [sha256.Size]byte
}

type Transport struct {
	service  string
	options  config.Transport
	server   bool
	keys     atomic.Pointer[snapshot]
	reloadMu sync.Mutex
}

func Load(options config.Transport, service string, server bool) (*Transport, error) {
	if !config.ValidService(service) {
		return nil, errors.New("invalid local service identity")
	}
	options.ServiceNamespaces = maps.Clone(options.ServiceNamespaces)
	t := &Transport{service: service, options: options, server: server}
	if err := t.Check(context.Background()); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) reload() error {
	t.reloadMu.Lock()
	defer t.reloadMu.Unlock()
	data, err := os.ReadFile(t.options.JWKSFile)
	if err != nil {
		return errKeys
	}
	hash := sha256.Sum256(data)
	if previous := t.keys.Load(); previous != nil && previous.hash == hash {
		return nil
	}
	keys, err := parseJWKS(data)
	if err != nil {
		return err
	}
	t.keys.Store(&snapshot{keys, hash})
	return nil
}

func (t *Transport) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := os.Open(t.options.TokenDir)
	if err == nil {
		_, err = dir.ReadDir(1)
		dir.Close()
	}
	if err != nil && err != io.EOF {
		return errors.New("service token directory is unavailable")
	}
	if t.server {
		return t.reload()
	}
	return nil
}

func (t *Transport) Watch(ctx context.Context, interval time.Duration, log *slog.Logger) {
	if !t.server || interval <= 0 || log == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := t.reload(); err != nil {
				log.WarnContext(ctx, "service token public key reload failed")
			}
		}
	}
}

// Bind the verified identity to the transport (including its issuer and audience).
type peerKey struct{ transport *Transport }

func (t *Transport) Peer(ctx context.Context) (string, error) {
	name, ok := ctx.Value(peerKey{t}).(string)
	if !ok {
		return "", unauthenticated
	}
	if name == "" {
		return "", ErrHealthProbe
	}
	return name, nil
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s serverStream) Context() context.Context { return s.ctx }

func (t *Transport) ServerOptions(allowed []string, denied func(context.Context, string, string, string)) ([]grpc.ServerOption, error) {
	if !t.server || len(allowed) == 0 {
		return nil, errors.New("plaintext server requires verification keys and an explicit allowlist")
	}
	peers := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		if !config.ValidService(name) || peers[name] {
			return nil, errors.New("invalid or duplicate allowed service")
		}
		peers[name] = true
	}
	authenticate := func(ctx context.Context, method string) (context.Context, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		values := md.Get(header)
		md.Delete(header)
		if strings.HasPrefix(method, healthPrefix) {
			// Anonymous probes cannot supply trusted correlation IDs.
			md.Delete("x-request-id")
			md.Delete("x-trace-id")
			return context.WithValue(metadata.NewIncomingContext(ctx, md), peerKey{t}, ""), nil
		}
		ctx = metadata.NewIncomingContext(ctx, md)
		var name, reason string
		switch len(values) {
		case 0:
			reason = "token_missing"
		case 1:
			name, reason = t.verify(values[0], time.Now())
		default:
			reason = "token_malformed"
		}
		if reason == "" && !peers[name] {
			reason = "caller_not_allowed"
		}
		if reason != "" {
			if denied != nil {
				denied(ctx, method, name, reason)
			}
			return nil, unauthenticated
		}
		return context.WithValue(ctx, peerKey{t}, name), nil
	}
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		ctx, err := authenticate(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		ctx, err := authenticate(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return next(srv, serverStream{ss, ctx})
	}
	return []grpc.ServerOption{grpc.ChainUnaryInterceptor(unary), grpc.ChainStreamInterceptor(stream)}, nil
}

type tokenFile struct {
	path  string
	mu    sync.Mutex
	info  os.FileInfo
	value string
}

func (f *tokenFile) read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, err := os.Open(f.path)
	if err != nil {
		return "", unauthenticated
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxTokenBytes {
		return "", unauthenticated
	}
	if f.info != nil && info.Size() == f.info.Size() && info.ModTime().Equal(f.info.ModTime()) && os.SameFile(info, f.info) {
		return f.value, nil
	}
	data, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	token := strings.TrimSpace(string(data))
	if err != nil || int64(len(data)) != info.Size() || token == "" || strings.IndexFunc(token, func(r rune) bool { return r < '!' || r > '~' }) >= 0 {
		return "", unauthenticated
	}
	f.info, f.value = info, token
	return token, nil
}

func (t *Transport) DialOptions(_ string, target string) ([]grpc.DialOption, error) {
	if !config.ValidService(target) {
		return nil, errors.New("invalid target service")
	}
	file := tokenFile{path: filepath.Join(t.options.TokenDir, target)}
	outgoing := func(ctx context.Context, method string) (context.Context, error) {
		md, _ := metadata.FromOutgoingContext(ctx)
		if md == nil {
			md = metadata.MD{}
		}
		md.Delete(header)
		if !strings.HasPrefix(method, healthPrefix) {
			value, err := file.read()
			if err != nil {
				return nil, err
			}
			md.Set(header, value)
		}
		return metadata.NewOutgoingContext(ctx, md), nil
	}
	unary := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, next grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, err := outgoing(ctx, method)
		if err != nil {
			return err
		}
		return next(ctx, method, req, reply, cc, opts...)
	}
	stream := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, next grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx, err := outgoing(ctx, method)
		if err != nil {
			return nil, err
		}
		return next(ctx, desc, cc, method, opts...)
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(unary), grpc.WithChainStreamInterceptor(stream)}, nil
}
