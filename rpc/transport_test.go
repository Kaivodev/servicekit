package rpc

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aipay-dev/observability/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestPlaintextAndMissingClientCertificateRejected(t *testing.T) {
	certs := materials(t, "iam", "backend")
	server, err := NewServer(serverOptions(), certs["iam"], logging.New(io.Discard, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	defer func() { cancel(); <-done }()
	trusted, err := certs["backend"].Client("iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	noCertificate := trusted.Clone()
	noCertificate.Certificates = nil
	for name, creds := range map[string]credentials.TransportCredentials{"plaintext": insecure.NewCredentials(), "no-client-certificate": credentials.NewTLS(noCertificate)} {
		t.Run(name, func(t *testing.T) {
			conn, err := grpc.NewClient(server.Address(), grpc.WithTransportCredentials(creds))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if _, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err == nil {
				t.Fatal("unauthenticated transport accepted")
			}
		})
	}
	if trusted.MinVersion != tls.VersionTLS13 || trusted.InsecureSkipVerify {
		t.Fatal("weak TLS defaults")
	}
}

func TestHealthWatchDoesNotConsumeDrainBudget(t *testing.T) {
	certs := materials(t, "iam", "backend")
	server, err := NewServer(serverOptions(), certs["iam"], logging.New(io.Discard, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	conn, err := connect(t, server, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitReady(t, server, true)
	watchctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	watch, err := healthpb.NewHealthClient(conn).Watch(watchctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = watch.Recv(); err != nil {
		t.Fatal(err)
	}
	// The client keeps its long-lived watch open while the server stops.
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal("health watch forced an otherwise idle server to time out:", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown hung")
	}
}
