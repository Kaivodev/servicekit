package tools_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	collectionv1 "github.com/Kaivodev/protobuf/gen/go/aipay/collection/v1"
	eventsv1 "github.com/Kaivodev/protobuf/gen/go/aipay/events/v1"
	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/dev/tools/internal/collection"
	"github.com/Kaivodev/servicekit/devcert"
	"github.com/Kaivodev/servicekit/eventstream"
	"github.com/Kaivodev/servicekit/mtls"
	"github.com/Kaivodev/servicekit/rpc"
	"github.com/Kaivodev/servicekit/signing"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fixtures(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "deposits")
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-B", "../deposit_scenario.py", "--seller-account-id", id.String(), "--out", out)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate fixtures: %s %v", data, err)
	}
	return out
}

func keyFiles(t *testing.T) map[string]string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	registry, err := signing.MarshalJWKS(map[string]*ecdsa.PublicKey{"collection-dev": &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"signing.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "collection.jwks": registry} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]string{"AIPAY_SIGNING_BACKEND": "file", "AIPAY_ENVIRONMENT": "development", "AIPAY_SIGNING_KEY_ID": "collection-dev", "AIPAY_SIGNING_KEY_FILE": filepath.Join(dir, "signing.pem"), "AIPAY_DEVCOLLECTION_JWKS_FILE": filepath.Join(dir, "collection.jwks")}
}

func openKey(t *testing.T, env map[string]string) signing.Signer {
	t.Helper()
	signer, err := collection.FileSigner(t.Context(), func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func verifier(t *testing.T, env map[string]string) eventstream.Verifier {
	t.Helper()
	keys, err := signing.LoadJWKS(env["AIPAY_DEVCOLLECTION_JWKS_FILE"])
	if err != nil {
		t.Fatal(err)
	}
	return eventstream.Verifier{Producer: "collection", Stream: collection.Stream, Keys: keys, Known: func(name string, v uint32) bool { return name == "ReceiptConfirmed" && v == 1 }}
}

func TestReceiptAndPersistentSignature(t *testing.T) {
	dir := fixtures(t)
	env := keyFiles(t)
	verify := verifier(t, env)
	var cursor eventstream.Cursor
	for _, key := range []string{"normal", "unfinalized"} {
		claim, err := collection.ReadReceipt(filepath.Join(dir, "scenario.json"), key)
		if err != nil {
			t.Fatal(err)
		}
		if key == "normal" && claim.Asset.Amount.Units != 1000000000 || key == "unfinalized" && claim.Asset.Amount.Units != 1 {
			t.Fatal("incorrect ledger units")
		}
		id, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		claim.ReceiptId = id.String()
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(claim)
		if err != nil {
			t.Fatal(err)
		}
		e := &eventsv1.SignedEvent{Stream: collection.Stream, Producer: "collection", EventId: uuid.Must(uuid.NewV7()).String(), Sequence: cursor.Sequence + 1, PrevDigest: bytes.Clone(cursor.Digest[:]), EventType: "ReceiptConfirmed", SchemaVersion: 1, OccurredAt: claim.ConfirmedAt, RecordedAt: timestamppb.New(time.Now().Truncate(time.Microsecond)), Payload: payload}
		sealed, digest, err := eventstream.Seal(t.Context(), openKey(t, env), e)
		if err != nil {
			t.Fatal(err)
		}
		cursor, err = verify.Next(cursor, sealed)
		if err != nil || cursor.Digest != digest {
			t.Fatal("consumer verification failed", err)
		}
	}
	wrong := keyFiles(t)
	env["AIPAY_DEVCOLLECTION_JWKS_FILE"] = wrong["AIPAY_DEVCOLLECTION_JWKS_FILE"]
	get := func(k string) string { return env[k] }
	if _, err := collection.FileSigner(t.Context(), get); err == nil {
		t.Fatal("accepted wrong pinned key")
	}
	env["AIPAY_SIGNING_BACKEND"] = "memory"
	if _, err := collection.FileSigner(t.Context(), get); err == nil {
		t.Fatal("accepted memory signer")
	}
}

// startReader uses the production server, protobuf method policy and stream ACL.
func startReader(t *testing.T, db eventstream.DB) func(string) (eventsv1.EventStreamServiceClient, error) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"collection", "ledger", "payment", "reconciliation"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	material := func(name string) *mtls.Material {
		m, err := mtls.Load(config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, name, "tls.crt"), KeyFile: filepath.Join(dir, name, "tls.key"), TrustDomain: "aipay.test"}, name)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	cfg := config.Config{RPC: config.RPC{Address: "127.0.0.1:0", AllowedPeers: []string{"ledger", "reconciliation"}, MaxMessageBytes: 1 << 20, MaxConcurrentStreams: 16, CallTimeout: time.Second}, HealthInterval: time.Second, HealthTimeout: time.Second, ShutdownTimeout: time.Second}
	reader, err := collection.NewReader(db)
	if err != nil {
		t.Fatal(err)
	}
	server, err := collection.NewServer(cfg, material("collection"), reader, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	for deadline := time.Now().Add(3 * time.Second); !server.Ready(); {
		if time.Now().After(deadline) {
			t.Fatal("server did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	return func(name string) (eventsv1.EventStreamServiceClient, error) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		conn, err := rpc.Connect(ctx, material(name), rpc.ClientOptions{Address: server.Address(), ServerName: "collection", ExpectedService: "collection", CallTimeout: time.Second, MaxMessageBytes: 1 << 20})
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = conn.Close() })
		return eventsv1.NewEventStreamServiceClient(conn), nil
	}
}

// These requests finish at the policy/argument checks, before any database access.
type unusedDB struct{ eventstream.DB }

func TestRealMTLSPeersAndPolicy(t *testing.T) {
	connect := startReader(t, unusedDB{})
	for _, name := range []string{"ledger", "reconciliation"} {
		client, err := connect(name)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.ListEvents(t.Context(), &eventsv1.ListEventsRequest{Stream: collection.Stream, Limit: 0})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = client.GetStreamHead(t.Context(), &eventsv1.GetStreamHeadRequest{Stream: "collection.sweeps"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("undeclared stream: %v", err)
		}
	}
	if _, err := connect("payment"); err == nil {
		t.Fatal("payment passed collection mTLS allowlist")
	}
}

func readClaim(t *testing.T, path, key string) *collectionv1.ReceiptConfirmed {
	t.Helper()
	m, err := collection.ReadReceipt(path, key)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
