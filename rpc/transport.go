package rpc

import (
	"context"
	"log/slog"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/internal/servicetoken"
	"github.com/Kaivodev/servicekit/mtls"
	"google.golang.org/grpc"
)

// Transport provides connection options and the verified per-call identity.
// ServerOptions installs authentication before the RPC server interceptors.
// The optional denial observer receives method, verified peer and bounded reason.
type Transport interface {
	ServerOptions(allowed []string, denied func(context.Context, string, string, string)) ([]grpc.ServerOption, error)
	DialOptions(serverName, expectedService string) ([]grpc.DialOption, error)
	Peer(context.Context) (string, error)
	Check(context.Context) error
	Watch(context.Context, time.Duration, *slog.Logger)
}

var _ Transport = (*mtls.Material)(nil)

// LoadTransport opens the configured identity for serving and dialing.
func LoadTransport(cfg config.Config, service string) (Transport, error) {
	if err := cfg.Transport.Validate(cfg.TLS, true); err != nil {
		return nil, err
	}
	return openTransport(cfg.Transport, cfg.TLS, service, true)
}

// LoadClientTransport opens a transport for a client process from environment settings.
func LoadClientTransport(service string, get func(string) string) (Transport, error) {
	t, tls, err := config.LoadClientTransport(get)
	if err != nil {
		return nil, err
	}
	return openTransport(t, tls, service, false)
}

func openTransport(t config.Transport, tls config.TLS, service string, server bool) (Transport, error) {
	var transport Transport
	var err error
	if t.Mode == config.Plaintext {
		transport, err = servicetoken.Load(t, service, server)
	} else {
		transport, err = mtls.Load(tls, service)
	}
	if err != nil {
		return nil, err
	}
	return transport, nil
}
