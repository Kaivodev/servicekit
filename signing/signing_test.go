package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kaivodev/servicekit/config"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestMemorySignerRefusedOutsideDevelopment(t *testing.T) {
	for _, environment := range []string{"", "production", "staging"} {
		cfg, err := Load(env(map[string]string{"AIPAY_ENVIRONMENT": environment, "AIPAY_SIGNING_BACKEND": "memory", "AIPAY_SIGNING_KEY_ID": "payment-dev"}))
		if err == nil {
			t.Fatalf("memory signer configuration accepted for %q", environment)
		}
		// Open re-validates even when the caller skips Load's error.
		if _, err = Open(context.Background(), cfg, nil); err == nil {
			t.Fatalf("memory signer opened for %q", environment)
		}
	}
	if _, err := Open(context.Background(), Config{Environment: config.Production, Backend: BackendMemory, KeyID: "payment-dev"}, nil); err == nil {
		t.Fatal("memory signer opened from a production Config literal")
	}
	cfg, err := Load(env(map[string]string{"AIPAY_ENVIRONMENT": "development", "AIPAY_SIGNING_BACKEND": "memory", "AIPAY_SIGNING_KEY_ID": "payment-dev"}))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := Open(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewPublicKeys(map[string]*ecdsa.PublicKey{signer.KeyID(): signer.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Verify("payment-dev", []byte("message"), signature); err != nil {
		t.Fatal(err)
	}
	if err = keys.Verify("payment-dev", []byte("messagf"), signature); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered message: %v", err)
	}
	if err = keys.Verify("payment-old", []byte("message"), signature); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestDefaultBackendIsKMS(t *testing.T) {
	cfg, err := Load(env(map[string]string{"AIPAY_SIGNING_KEY_ID": "payment-events-1"}))
	if err != nil || cfg.Backend != BackendKMS || cfg.Environment != config.Production {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	if _, err = Open(context.Background(), cfg, nil); err == nil {
		t.Fatal("KMS backend opened without a key")
	}
	for _, bad := range []map[string]string{{}, {"AIPAY_SIGNING_KEY_ID": "bad key"}, {"AIPAY_SIGNING_KEY_ID": "k", "AIPAY_SIGNING_BACKEND": "file"}, {"AIPAY_SIGNING_KEY_ID": "k", "AIPAY_SIGNING_BACKEND": "file", "AIPAY_SIGNING_KEY_FILE": "key.pem"}, {"AIPAY_SIGNING_KEY_ID": "k", "AIPAY_ENVIRONMENT": "prod"}} {
		if _, err = Load(env(bad)); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestDevelopmentFileSignerSurvivesReopen(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "event-signing.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(env(map[string]string{"AIPAY_ENVIRONMENT": "development", "AIPAY_SIGNING_BACKEND": "file", "AIPAY_SIGNING_KEY_ID": "collection-dev-1", "AIPAY_SIGNING_KEY_FILE": path}))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Open(t.Context(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := first.Sign(t.Context(), []byte("persisted event"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(t.Context(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.PublicKey().Equal(second.PublicKey()) {
		t.Fatal("reopened file signer changed public key")
	}
	keys, err := NewPublicKeys(map[string]*ecdsa.PublicKey{second.KeyID(): second.PublicKey()})
	if err != nil || keys.Verify(second.KeyID(), []byte("persisted event"), signature) != nil {
		t.Fatal("reopened signer did not verify the prior signature", err)
	}

	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(t.Context(), cfg, nil); err == nil {
		t.Fatal("world-readable development signing key accepted")
	}
}

func TestDevelopmentFileSignerRejectsWrongKeyMaterial(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"wrong curve":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}),
		"wrong block":   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}),
		"trailing data": append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), []byte("extra")...),
		"not PEM":       []byte("synthetic invalid key material"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "event-signing.pem")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := Config{Environment: config.Development, Backend: BackendFile, KeyID: "collection-dev-1", KeyFile: path}
			if _, err := Open(t.Context(), cfg, nil); err == nil {
				t.Fatal("invalid development signing key accepted")
			}
		})
	}
}

type fakeKMS struct {
	key    *ecdsa.PrivateKey
	public crypto.PublicKey
	other  *ecdsa.PrivateKey
}

func (f fakeKMS) PublicKey(context.Context) (crypto.PublicKey, error) { return f.public, nil }
func (f fakeKMS) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	key := f.key
	if f.other != nil {
		key = f.other
	}
	return ecdsa.SignASN1(rand.Reader, key, digest)
}

func TestKMSSigner(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ctx := context.Background()
	signer, err := Open(ctx, Config{Environment: config.Production, Backend: BackendKMS, KeyID: "ledger-checkpoints-1"}, fakeKMS{key: key, public: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(ctx, []byte("checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := NewPublicKeys(map[string]*ecdsa.PublicKey{"ledger-checkpoints-1": &key.PublicKey})
	if err = keys.Verify("ledger-checkpoints-1", []byte("checkpoint"), signature); err != nil {
		t.Fatal(err)
	}
	if _, err = NewKMS(ctx, "k", fakeKMS{key: p384, public: &p384.PublicKey}); err == nil {
		t.Fatal("P-384 KMS key accepted")
	}
	wrong, err := NewKMS(ctx, "k", fakeKMS{key: key, public: &key.PublicKey, other: other})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.Sign(ctx, []byte("checkpoint")); err == nil {
		t.Fatal("signature from a different KMS key accepted")
	}
}

func TestJWKS(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data, err := MarshalJWKS(map[string]*ecdsa.PublicKey{"iam-2026-10": &a.PublicKey, "iam-2026-11": &b.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(data)
	if err != nil || keys.Len() != 2 {
		t.Fatalf("keys=%d err=%v", keys.Len(), err)
	}
	if found, ok := keys.Lookup("iam-2026-11"); !ok || !found.Equal(&b.PublicKey) {
		t.Fatal("lookup returned a different key")
	}
	document := string(data)
	firstX := document[strings.Index(document, `"x": "`)+6:]
	firstX = firstX[:strings.Index(firstX, `"`)]
	for name, bad := range map[string]string{
		"private":   strings.Replace(document, `"kty"`, `"d": "AAAA", "kty"`, 1),
		"curve":     strings.Replace(document, `"P-256"`, `"P-384"`, 1),
		"alg":       strings.Replace(document, `"ES256"`, `"RS256"`, 1),
		"use":       strings.Replace(document, `"sig"`, `"enc"`, 1),
		"duplicate": strings.Replace(document, "iam-2026-11", "iam-2026-10", 1),
		"off-curve": strings.Replace(document, firstX, strings.Repeat("A", len(firstX)-1)+"E", 1),
		"empty":     `{"keys": []}`,
		"not-json":  `keys`,
	} {
		if _, err := ParseJWKS([]byte(bad)); err == nil {
			t.Fatalf("%s key set accepted", name)
		}
	}
}
