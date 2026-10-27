package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/aipay-dev/servicekit/config"
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
	for _, bad := range []map[string]string{{}, {"AIPAY_SIGNING_KEY_ID": "bad key"}, {"AIPAY_SIGNING_KEY_ID": "k", "AIPAY_SIGNING_BACKEND": "file"}, {"AIPAY_SIGNING_KEY_ID": "k", "AIPAY_ENVIRONMENT": "prod"}} {
		if _, err = Load(env(bad)); err == nil {
			t.Fatalf("accepted %v", bad)
		}
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
