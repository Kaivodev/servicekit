package rpc

import (
	"context"
	"errors"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func Probe(ctx context.Context, localService, expectedService string, options config.Probe) error {
	var transport Transport
	var err error
	switch options.Transport {
	case config.Plaintext:
		tls := options.TLS
		if tls.CAFile != "" || tls.CertFile != "" || tls.KeyFile != "" || tls.TrustDomain != "" || config.ValidateAddress(options.Address) != nil {
			return errors.New("invalid plaintext probe configuration")
		}
	case "", config.MTLS:
		transport, err = mtls.Load(options.TLS, localService)
		if err != nil {
			return err
		}
	default:
		return errors.New("unknown probe transport")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	var connection *grpc.ClientConn
	if options.Transport == config.Plaintext {
		connection, err = grpc.NewClient("passthrough:///"+options.Address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.WaitForReady(true)))
	} else {
		connection, err = Connect(ctx, transport, ClientOptions{Address: options.Address, ServerName: options.ServerName, ExpectedService: expectedService, CallTimeout: options.Timeout, MaxMessageBytes: 1 << 20})
	}
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
