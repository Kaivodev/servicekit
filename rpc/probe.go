package rpc

import (
	"context"
	"errors"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/mtls"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func Probe(ctx context.Context, localService, expectedService string, options config.Probe) error {
	material, err := mtls.Load(options.TLS, localService)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	connection, err := Connect(ctx, material, ClientOptions{Address: options.Address, ServerName: options.ServerName, ExpectedService: expectedService, CallTimeout: options.Timeout, MaxMessageBytes: 1 << 20})
	if err != nil {
		return err
	}
	defer connection.Close()
	response, err := healthpb.NewHealthClient(connection).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return errors.New("RPC health check failed")
	}
	if response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		return errors.New("service is not ready")
	}
	return nil
}
