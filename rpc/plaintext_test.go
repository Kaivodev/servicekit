package rpc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/servicekit/authz"
	"github.com/Kaivodev/servicekit/authz/authztest"
	"github.com/Kaivodev/servicekit/cli"
	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/mtls"
	"github.com/Kaivodev/servicekit/signing"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Compile the original call sites, including callers that hold a concrete
// *mtls.Material. The function is never executed.
var _ = func(m *mtls.Material) {
	_, _ = NewServer(ServerOptions{}, m, nil, nil, nil, nil)
	_, _ = Connect(context.Background(), m, ClientOptions{})
}

const childState = "KAIVO_TEST_PLAINTEXT_SERVER"
const tokenHeader = "x-kaivo-service-token"

func TestPlaintextRPCProcess(t *testing.T) {
	if dir := os.Getenv(childState); dir != "" {
		plaintextServer(t, dir)
		return
	}
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := signing.MarshalJWKS(map[string]*ecdsa.PublicKey{"test": &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "jwks"), jwks, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPlaintextRPCProcess$")
	cmd.Env = append(os.Environ(), childState+"="+dir)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		input.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("server process: %v\n%s", err, output.String())
		}
	}()
	var address string
	for address == "" {
		if data, err := os.ReadFile(filepath.Join(dir, "address")); err == nil && len(data) > 0 {
			address = string(data)
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("child did not start")
		case <-time.After(10 * time.Millisecond):
		}
	}

	settings := map[string]string{"AIPAY_RPC_TRANSPORT": "plaintext", "AIPAY_RPC_TOKEN_DIR": dir, "AIPAY_RPC_SERVICE_NAMESPACES": "backend=local"}
	tr, err := LoadClientTransport("backend", func(k string) string { return settings[k] })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.ServerOptions([]string{"backend"}, nil); err == nil {
		t.Fatal("client-only verifier accepted server role")
	}
	conn, err := Connect(ctx, tr, ClientOptions{Address: address, ExpectedService: "iam", CallTimeout: time.Second, MaxMessageBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	probe := func(ctx context.Context) error {
		options, err := config.LoadProbe("iam", address, func(k string) string {
			if k == "AIPAY_RPC_TRANSPORT" {
				return "plaintext"
			}
			return ""
		})
		if err != nil {
			return err
		}
		return Probe(ctx, "probe", "iam", options)
	}
	if err := cli.Run([]string{"healthcheck"}, cli.Commands{Healthcheck: probe}, io.Discard); err != nil {
		t.Fatal(err)
	}
	wctx, stop := context.WithCancel(ctx)
	watch, err := healthpb.NewHealthClient(conn).Watch(wctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	update, err := watch.Recv()
	stop()
	if err != nil || update.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatal("anonymous Watch failed", err)
	}

	raw, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	invoke := func(ctx context.Context, cc *grpc.ClientConn, want codes.Code) {
		t.Helper()
		err := cc.Invoke(ctx, "/test.Runtime/Call", &emptypb.Empty{}, &emptypb.Empty{})
		if status.Code(err) != want {
			t.Fatalf("unary: got %v, want %v", err, want)
		}
		if want == codes.Unauthenticated && status.Convert(err).Message() != "Service authentication required" {
			t.Fatal("unsafe authentication response")
		}
	}
	stream := func(want codes.Code) {
		t.Helper()
		s, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/test.Stream/Watch")
		if err == nil {
			_ = s.CloseSend()
			err = s.RecvMsg(&emptypb.Empty{})
		}
		if status.Code(err) != want {
			t.Fatalf("stream: got %v, want %v", err, want)
		}
	}
	invoke(ctx, raw, codes.Unauthenticated)
	invoke(metadata.AppendToOutgoingContext(ctx, tokenHeader, "one", tokenHeader, "two"), raw, codes.Unauthenticated)
	invoke(ctx, conn, codes.Unauthenticated) // No target file, fails before dispatch.
	path := filepath.Join(dir, "iam")
	publish := func(subject, aud string, override ...map[string]any) {
		t.Helper()
		now := time.Now()
		values := map[string]any{"iss": "test", "sub": "system:serviceaccount:local:" + subject, "aud": aud, "exp": now.Add(10 * time.Minute).Unix(), "nbf": now.Unix(), "iat": now.Unix()}
		for _, changes := range override {
			for k, v := range changes {
				values[k] = v
			}
		}
		claims, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		enc := base64.RawURLEncoding
		message := enc.EncodeToString([]byte(`{"alg":"ES256","kid":"test"}`)) + "." + enc.EncodeToString(claims)
		hash := sha256.Sum256([]byte(message))
		r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		var sig [64]byte
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		if err = os.WriteFile(path+".next", []byte(message+"."+enc.EncodeToString(sig[:])), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(path+".next", path); err != nil {
			t.Fatal(err)
		}
	}
	publish("backend", "kaivo:iam")
	invoke(metadata.AppendToOutgoingContext(ctx, tokenHeader, "stale"), conn, codes.OK)
	stream(codes.OK)
	publish("backend", "kaivo:other")
	invoke(ctx, conn, codes.Unauthenticated)
	stream(codes.Unauthenticated)
	for _, changes := range []map[string]any{
		{"iss": "wrong"}, {"exp": time.Now().Add(-time.Minute).Unix()}, {"sub": "bad"},
		{"sub": "system:serviceaccount:other:backend"},
	} {
		publish("backend", "kaivo:iam", changes)
		invoke(ctx, conn, codes.Unauthenticated)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	message, _, _ := strings.Cut(string(data), ".")
	badSignature := message + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	invoke(metadata.AppendToOutgoingContext(ctx, tokenHeader, badSignature), raw, codes.Unauthenticated)
	publish("notifier", "kaivo:iam") // signed and mapped, outside listener allowlist
	invoke(ctx, conn, codes.Unauthenticated)
	publish("ledger", "kaivo:iam") // listener admits ledger, method policy does not
	invoke(ctx, conn, codes.PermissionDenied)
	publish("backend", "kaivo:iam")
	invoke(ctx, conn, codes.OK)
	if err = os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	invoke(ctx, conn, codes.Unauthenticated)
}

func plaintextServer(t *testing.T, dir string) {
	tr, err := LoadTransport(config.Config{Transport: config.Transport{Mode: config.Plaintext, TokenDir: dir, JWKSFile: filepath.Join(dir, "jwks"), Issuer: "test", ServiceNamespaces: map[string]string{"backend": "local", "ledger": "local", "notifier": "local"}}}, "iam")
	if err != nil {
		t.Fatal(err)
	}
	opts := serverOptions()
	opts.RPC.AllowedPeers = []string{"backend", "ledger"}
	rule := authztest.Options(authztest.Rule{Callers: []string{"backend"}, Requirement: authztest.NotRequired})
	u, err := authztest.Service("test.Runtime", map[string]*descriptorpb.MethodOptions{"Call": rule})
	if err != nil {
		t.Fatal(err)
	}
	s, err := authztest.Service("test.Stream", map[string]*descriptorpb.MethodOptions{"Watch": rule})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := authz.LoadPolicies(u, s)
	if err != nil {
		t.Fatal(err)
	}
	var logs synchronizedBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	opts.Authorizer, err = authz.New(authz.Options{Service: "iam", Policies: policies, Peer: tr.Peer, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	opts.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	verify := func(ctx context.Context) error {
		call, ok := authz.FromContext(ctx)
		peer, err := tr.Peer(ctx)
		if !ok || err != nil || peer != "backend" || peer != call.Caller() || len(metadata.ValueFromIncomingContext(ctx, tokenHeader)) != 0 {
			return status.Error(codes.Internal, "invalid handler context")
		}
		return nil
	}
	server, err := NewServer(opts, tr, log, log, map[string]Check{"transport": tr.Check}, func(r grpc.ServiceRegistrar) {
		registerTest(handlerFunc(func(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
			return &emptypb.Empty{}, verify(ctx)
		}))(r)
		r.RegisterService(&grpc.ServiceDesc{ServiceName: "test.Stream", HandlerType: (*testHandler)(nil), Streams: []grpc.StreamDesc{{StreamName: "Watch", ServerStreams: true, Handler: func(_ any, ss grpc.ServerStream) error {
			if err := verify(ss.Context()); err != nil {
				return err
			}
			return ss.SendMsg(&emptypb.Empty{})
		}}}}, handlerFunc(nil))
	})
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
	if err = os.WriteFile(filepath.Join(dir, "address"), []byte(server.Address()), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	denied := collected(t, reader)["kaivo.authz.denied"].Data.(metricdata.Sum[int64])
	seen := map[string]int64{}
	for _, point := range denied.DataPoints {
		reason, _ := point.Attributes.Value("reason")
		peer, _ := point.Attributes.Value("peer_service")
		method, _ := point.Attributes.Value("rpc_method")
		seen[fmt.Sprintf("%s/%s/%s", method.AsString(), peer.AsString(), reason.AsString())] += point.Value
	}
	want := map[string]int64{
		"Call/unverified/token_missing": 1, "Call/unverified/token_malformed": 1, "Call/unverified/token_signature": 1,
		"Call/unverified/token_issuer": 1, "Call/unverified/token_audience": 1, "Call/unverified/token_expired": 1,
		"Call/unverified/token_subject": 1, "Call/unverified/token_namespace": 1, "Watch/unverified/token_audience": 1,
		"Call/notifier/caller_not_allowed": 1, "Call/ledger/caller_not_allowed": 1,
	}
	if strings.Contains(logs.String(), base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"test"}`))) || strings.Contains(logs.String(), tokenHeader) {
		t.Fatal("service token material in access or runtime logs")
	}
	for k, n := range want {
		if seen[k] != n {
			t.Errorf("%s = %d, want %d", k, seen[k], n)
		}
	}
	if len(seen) != len(want) {
		t.Fatal("unexpected denial series", seen)
	}
}
