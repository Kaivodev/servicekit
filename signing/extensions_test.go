package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kaivodev/servicekit/config"
)

func TestLoadPrefixed(t *testing.T) {
	values := map[string]string{
		"AIPAY_ENVIRONMENT": "development", "AIPAY_SIGNING_BACKEND": "memory", "AIPAY_SIGNING_KEY_ID": "events",
		"AIPAY_SECOND_SIGNING_KEY_ID": "assertions", "AIPAY_SECOND_SIGNING_KEY_FILE": "file.pem",
	}
	cfg, err := Load(env(values))
	if err != nil || cfg.Backend != BackendMemory || cfg.KeyID != "events" {
		t.Fatal("wrong default signer", err)
	}
	for _, size := range []int{0, 1, 512, 513} {
		resource := strings.Repeat("a", size)
		values["AIPAY_SECOND_SIGNING_KMS_KEY"] = resource
		cfg, err := LoadPrefixed(env(values), "AIPAY_SECOND_SIGNING")
		if (err == nil) != (size >= 1 && size <= 512) {
			t.Fatalf("resource length %d: %v", size, err)
		}
		if cfg.Backend != BackendKMS || cfg.KeyID != "assertions" || cfg.KMSKey != resource || cfg.KeyFile != "file.pem" || cfg.Environment != config.Development {
			t.Fatal("signer configurations crossed")
		}
	}
}

func TestCheckRegistered(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &memorySigner{id: "event", key: key}
	registry, err := NewPublicKeys(map[string]*ecdsa.PublicKey{"event": &key.PublicKey, "other": &other.PublicKey})
	if err != nil || CheckRegistered(s, &registry) != nil {
		t.Fatal("registered key rejected", err)
	}
	s.id = "other"
	if CheckRegistered(s, &registry) == nil {
		t.Fatal("mismatched key accepted")
	}
	s.id = "unknown"
	if !errors.Is(CheckRegistered(s, &registry), ErrUnknownKey) || CheckRegistered(s, nil) == nil {
		t.Fatal("missing registration accepted")
	}
}

type rsaProvider struct {
	public   crypto.PublicKey
	signWith *rsa.PrivateKey
}

func (p rsaProvider) PublicKey(context.Context) (crypto.PublicKey, error) { return p.public, nil }
func (p rsaProvider) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, p.signWith, crypto.SHA256, digest)
}

func TestRSASigners(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRSAKMS(t.Context(), "k", rsaProvider{public: &small.PublicKey}); err == nil {
		t.Fatal("undersized public key accepted")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := NewRSAKMS(t.Context(), "k", rsaProvider{public: &ec.PublicKey}); err == nil {
		t.Fatal("EC key accepted for RSA")
	}
	wrong, err := NewRSAKMS(t.Context(), "k", rsaProvider{&key.PublicKey, small})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Sign(t.Context(), []byte("sample")); err == nil {
		t.Fatal("provider signature from a different key accepted")
	}
	kms, err := NewRSAKMS(t.Context(), "k", rsaProvider{&key.PublicKey, key})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("sample")
	signature, err := kms.Sign(t.Context(), message)
	digest := sha256.Sum256(message)
	if err != nil || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("KMS signature failed", err)
	}
	path := filepath.Join(t.TempDir(), "key")
	cfg := Config{Environment: config.Development, Backend: BackendFile, KeyID: "k", KeyFile: path}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{der, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := OpenRSAFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := file.Sign(t.Context(), message)
		if err != nil || !bytes.Equal(sig, signature) || !file.PublicKey().Equal(kms.PublicKey()) || file.KeyID() != kms.KeyID() {
			t.Fatal("file/KMS signature mismatch", err)
		}
	}
	cfg.Environment = config.Production
	if _, err := OpenRSAFile(cfg); err == nil {
		t.Fatal("RSA file opened in production")
	}
	cfg.Environment = config.Development
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRSAFile(cfg); err == nil {
		t.Fatal("group-readable key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []any{small, ec} {
		der, err := x509.MarshalPKCS8PrivateKey(bad)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, der, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRSAFile(cfg); err == nil {
			t.Fatal("invalid RSA file key accepted")
		}
	}
}
