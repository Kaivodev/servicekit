package rpc

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kaivodev/observability/logging"
	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/devcert"
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

func TestDefaultTransportLoadersAndProbe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"iam", "backend"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	identity := func(name string) config.TLS {
		return config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, name, "tls.crt"), KeyFile: filepath.Join(dir, name, "tls.key"), TrustDomain: "aipay.test"}
	}
	serverTransport, err := LoadTransport(config.Config{TLS: identity("iam")}, "iam")
	if err != nil {
		t.Fatal(err)
	}
	client := identity("backend")
	settings := map[string]string{"AIPAY_TLS_CA_FILE": client.CAFile, "AIPAY_TLS_CERT_FILE": client.CertFile, "AIPAY_TLS_KEY_FILE": client.KeyFile, "AIPAY_TLS_TRUST_DOMAIN": client.TrustDomain, "AIPAY_GRPC_SERVER_NAME": "iam"}
	get := func(k string) string { return settings[k] }
	clientTransport, err := LoadClientTransport("backend", get)
	if err != nil {
		t.Fatal(err)
	}
	opts := serverOptions()
	log := logging.New(io.Discard, slog.LevelInfo)
	server, err := NewServer(opts, serverTransport, log, log, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	waitReady(t, server, true)
	settings["AIPAY_GRPC_TARGET"] = server.Address()
	probe, err := config.LoadProbe("iam", "localhost:9101", get)
	if err != nil {
		t.Fatal(err)
	}
	if err = Probe(ctx, "backend", "iam", probe); err != nil {
		t.Fatal(err)
	}
	dial, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	conn, err := Connect(dial, clientTransport, ClientOptions{Address: server.Address(), ServerName: "iam", ExpectedService: "iam", CallTimeout: time.Second, MaxMessageBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = healthpb.NewHealthClient(conn).Check(dial, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
}
