package rpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/devcert"
	"github.com/aipay-dev/servicekit/mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func runServer(t *testing.T, options ServerOptions, material *mtls.Material, register Register) *Server {
	t.Helper()
	server, err := NewServer(options, material, logging.New(io.Discard, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, register)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitReady(t, server, true)
	return server
}

func TestUndeclaredMethodsAreDenied(t *testing.T) {
	certs := materials(t, "iam", "backend")
	ok := handlerFunc(func(context.Context, *emptypb.Empty) (*emptypb.Empty, error) { return &emptypb.Empty{}, nil })
	// Without an authorizer every registered business method is denied.
	server := runServer(t, serverOptions(), certs["iam"], registerTest(ok))
	conn, err := connect(t, server, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = conn.Invoke(context.Background(), "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("undeclared method returned %v", err)
	}
	if _, err = healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal("health check denied:", err)
	}
	// A policy for one caller does not admit another allowed TLS peer.
	certs = materials(t, "iam", "backend", "ledger")
	options := serverOptions()
	options.RPC.AllowedPeers = []string{"backend", "ledger"}
	options = runtimePolicy(t, options, certs["iam"])
	server = runServer(t, options, certs["iam"], registerTest(ok))
	ledger, err := connect(t, server, certs["ledger"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err = ledger.Invoke(context.Background(), "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("caller outside the policy returned %v", err)
	}
	backend, err := connect(t, server, certs["backend"], "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err = backend.Invoke(context.Background(), "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
}

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "rotation test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue writes a fresh leaf for service into dir/service, replacing the files
// with renames as a certificate agent would.
func (a authority) issue(t *testing.T, dir, service string, serial int64) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: service}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, DNSNames: []string{service},
		URIs: []*url.URL{{Scheme: "spiffe", Host: "aipay.test", Path: "/service/" + service}}}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	replace(t, filepath.Join(dir, service, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	replace(t, filepath.Join(dir, service, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func replace(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

// devAuthority reopens the CA that devcert.Generate wrote into dir.
func devAuthority(t *testing.T, dir string) authority {
	t.Helper()
	ca, err := tls.LoadX509KeyPair(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(ca.Certificate[0])
	encoded, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	return authority{cert: cert, key: ca.PrivateKey.(*ecdsa.PrivateKey), pem: encoded}
}

func connSerial(t *testing.T, conn *grpc.ClientConn) int64 {
	t.Helper()
	var p peer.Peer
	if _, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{}, grpc.Peer(&p)); err != nil {
		t.Fatal(err)
	}
	return p.AuthInfo.(credentials.TLSInfo).State.PeerCertificates[0].SerialNumber.Int64()
}

func serverSerial(t *testing.T, server *Server, client *mtls.Material) int64 {
	t.Helper()
	conn, err := connect(t, server, client, "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return connSerial(t, conn)
}

// The server ends every connection after MaxConnectionAge; the same client
// connection then handshakes again and sees the reloaded certificate.
func TestConnectionMaxAgeForcesNewHandshake(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"iam", "backend"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	load := func(service string) *mtls.Material {
		material, err := mtls.Load(config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, service, "tls.crt"), KeyFile: filepath.Join(dir, service, "tls.key"), TrustDomain: "aipay.test"}, service)
		if err != nil {
			t.Fatal(err)
		}
		return material
	}
	iam, backend := load("iam"), load("backend")
	options := serverOptions()
	options.RPC.MaxConnectionAge, options.RPC.MaxConnectionAgeGrace = 200*time.Millisecond, 50*time.Millisecond
	server := runServer(t, options, iam, nil)
	conn, err := connect(t, server, backend, "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	original := connSerial(t, conn)
	devAuthority(t, dir).issue(t, dir, "iam", 4001)
	if _, err = iam.Reload(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		serial := connSerial(t, conn)
		if serial == 4001 {
			break
		}
		if serial != original || time.Now().After(deadline) {
			t.Fatalf("connection still uses serial %d after its maximum age", serial)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, invalid := range []config.RPC{{MaxConnectionAge: 2 * time.Hour}, {MaxConnectionAge: time.Minute, MaxConnectionAgeGrace: 2 * time.Minute}, {MaxConnectionAge: -time.Second}} {
		bad := serverOptions()
		bad.RPC.MaxConnectionAge, bad.RPC.MaxConnectionAgeGrace = invalid.MaxConnectionAge, invalid.MaxConnectionAgeGrace
		if _, err := NewServer(bad, iam, logging.New(io.Discard, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, nil); err == nil {
			t.Fatalf("accepted connection age %v grace %v", invalid.MaxConnectionAge, invalid.MaxConnectionAgeGrace)
		}
	}
}

func TestCertificateHotReload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"iam", "backend"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	load := func(service string) *mtls.Material {
		material, err := mtls.Load(config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, service, "tls.crt"), KeyFile: filepath.Join(dir, service, "tls.key"), TrustDomain: "aipay.test"}, service)
		if err != nil {
			t.Fatal(err)
		}
		return material
	}
	iam, backend := load("iam"), load("backend")
	server := runServer(t, serverOptions(), iam, nil)
	original := serverSerial(t, server, backend)
	held, err := connect(t, server, backend, "iam", "iam")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	first := devAuthority(t, dir)

	// A renewed leaf from the same CA is picked up by the next handshake.
	first.issue(t, dir, "iam", 1001)
	if changed, err := iam.Reload(); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if serial := serverSerial(t, server, backend); serial != 1001 || serial == original {
		t.Fatalf("server still presents serial %d", serial)
	}
	// An established connection keeps its handshake-time identity until the
	// server's maximum connection age (54m by default) ends it.
	if serial := connSerial(t, held); serial != original {
		t.Fatalf("established connection changed identity to %d", serial)
	}
	if changed, err := iam.Reload(); err != nil || changed {
		t.Fatal("unchanged files reported a reload")
	}

	// CA rotation: both sides trust old and new CAs, then switch leaves.
	second := newAuthority(t)
	replace(t, filepath.Join(dir, "ca.crt"), append(append([]byte{}, first.pem...), second.pem...))
	second.issue(t, dir, "iam", 2001)
	second.issue(t, dir, "backend", 2002)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go iam.Watch(ctx, 10*time.Millisecond, logging.New(io.Discard, slog.LevelInfo))
	go backend.Watch(ctx, 10*time.Millisecond, logging.New(io.Discard, slog.LevelInfo))
	deadline := time.Now().Add(3 * time.Second)
	for serverSerial(t, server, backend) != 2001 {
		if time.Now().After(deadline) {
			t.Fatal("watch did not apply the rotated certificate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Drop the old CA; new connections keep working on the new chain only.
	replace(t, filepath.Join(dir, "ca.crt"), second.pem)
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, err := iam.Reload(); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.Reload(); err != nil {
			t.Fatal(err)
		}
		if serverSerial(t, server, backend) == 2001 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old CA removal broke the server")
		}
	}
	cancel()

	// An invalid update (key not matching the certificate) is refused and the
	// working material stays in place.
	keyPath := filepath.Join(dir, "iam", "tls.key")
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	replace(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}))
	if _, err := iam.Reload(); err == nil {
		t.Fatal("mismatched key accepted")
	}
	// A certificate for another service is refused as well.
	second.issue(t, dir, "iam", 3001)
	if err := os.Rename(filepath.Join(dir, "backend", "tls.crt"), filepath.Join(dir, "iam", "tls.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "backend", "tls.key"), filepath.Join(dir, "iam", "tls.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := iam.Reload(); err == nil {
		t.Fatal("certificate of another service accepted")
	}
	if serial := serverSerial(t, server, backend); serial != 2001 {
		t.Fatalf("failed reload replaced the working certificate: serial %d", serial)
	}
	if err := iam.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}
