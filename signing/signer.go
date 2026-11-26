// Package signing provides business signers and public key registries for
// cross-domain assertions. Signer uses DER-encoded ECDSA P-256 signatures and
// RSASigner uses PKCS#1 v1.5. Both hash messages with SHA-256. Production
// keys stay in a KMS or HSM.
package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"regexp"
	"unicode/utf8"

	"github.com/Kaivodev/servicekit/config"
)

const (
	BackendKMS    = "kms"
	BackendMemory = "memory"
	BackendFile   = "file"
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidKeyID reports whether id can name a key in envelopes and registries.
func ValidKeyID(id string) bool { return keyIDPattern.MatchString(id) }

// Signer signs SHA-256(message) with a non-exportable P-256 key and returns an
// ASN.1 DER signature. KeyID names the key in receivers' public key registries.
type Signer interface {
	KeyID() string
	PublicKey() *ecdsa.PublicKey
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// KMSKey binds one provider key to a SHA-256 digest signing operation. It
// returns DER for P-256 or PKCS#1 v1.5 signature bytes for RSA.
type KMSKey interface {
	PublicKey(ctx context.Context) (crypto.PublicKey, error)
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}

type Config struct {
	Environment config.Environment
	Backend     string
	KeyID       string
	KeyFile     string
	KMSKey      string
}

// Load reads the default AIPAY_SIGNING configuration.
func Load(get func(string) string) (Config, error) {
	return LoadPrefixed(get, "AIPAY_SIGNING")
}

// LoadPrefixed reads AIPAY_ENVIRONMENT and the signing backend, key ID, key
// file and KMS key under prefix. The default backend is kms.
func LoadPrefixed(get func(string) string, prefix string) (Config, error) {
	environment, err := config.LoadEnvironment(get)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Environment: environment,
		Backend:     get(prefix + "_BACKEND"),
		KeyID:       get(prefix + "_KEY_ID"),
		KeyFile:     get(prefix + "_KEY_FILE"),
		KMSKey:      get(prefix + "_KMS_KEY"),
	}
	if cfg.Backend == "" {
		cfg.Backend = BackendKMS
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if !ValidKeyID(c.KeyID) {
		return errors.New("a valid signing key ID is required")
	}
	switch c.Backend {
	case BackendKMS:
		if c.KMSKey == "" || utf8.RuneCountInString(c.KMSKey) > 512 {
			return errors.New("a KMS key resource of at most 512 characters is required")
		}
		return nil
	case BackendMemory:
		if !c.Environment.IsDevelopment() {
			return errors.New("the in-memory signer is only allowed when AIPAY_ENVIRONMENT=development")
		}
		return nil
	case BackendFile:
		if !c.Environment.IsDevelopment() || c.KeyFile == "" {
			return errors.New("the file signer requires AIPAY_ENVIRONMENT=development and a key file")
		}
		return nil
	default:
		return errors.New("signing backend must be kms, memory or file")
	}
}

// Open creates a signer only from an explicitly selected backend. Development
// backends are refused outside development; key is required for KMS.
func Open(ctx context.Context, cfg Config, key KMSKey) (Signer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Backend == BackendMemory {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.New("generate development signing key failed")
		}
		return &memorySigner{id: cfg.KeyID, key: private}, nil
	}
	if cfg.Backend == BackendFile {
		return openDevelopmentFile(cfg.KeyID, cfg.KeyFile)
	}
	return NewKMS(ctx, cfg.KeyID, key)
}

func openDevelopmentFile(keyID, path string) (Signer, error) {
	parsed, err := readDevelopmentKey(path, false)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || private.Curve != elliptic.P256() {
		return nil, errors.New("development signing key must be ECDSA P-256")
	}
	return &memorySigner{id: keyID, key: private}, nil
}

// readDevelopmentKey accepts one PKCS#8 PEM block, or binary DER when enabled.
func readDevelopmentKey(path string, allowDER bool) (any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open development signing key failed")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("development signing key must be a private regular file")
	}
	limit := 4096
	if allowDER {
		limit = 64 << 10
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	defer clear(data)
	if err != nil || len(data) > limit {
		return nil, errors.New("read development signing key failed")
	}
	der := data
	if !allowDER || bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("development signing key must be one PKCS#8 PEM block")
		}
		der = block.Bytes
		defer clear(der)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("parse development signing key failed")
	}
	return parsed, nil
}

// NewKMS checks that the KMS key is P-256 before any signature is requested.
func NewKMS(ctx context.Context, keyID string, key KMSKey) (Signer, error) {
	if !ValidKeyID(keyID) || key == nil {
		return nil, errors.New("KMS signer requires a key ID and key")
	}
	public, err := key.PublicKey(ctx)
	if err != nil {
		return nil, errors.New("read KMS public key failed")
	}
	ec, ok := public.(*ecdsa.PublicKey)
	if !ok || ec == nil || ec.Curve != elliptic.P256() {
		return nil, errors.New("KMS key must be ECDSA P-256")
	}
	return &kmsSigner{id: keyID, key: key, public: ec}, nil
}

type kmsSigner struct {
	id     string
	key    KMSKey
	public *ecdsa.PublicKey
}

func (s *kmsSigner) KeyID() string               { return s.id }
func (s *kmsSigner) PublicKey() *ecdsa.PublicKey { return s.public }

// Sign verifies the provider's answer, so a misconfigured or misbehaving KMS
// can never publish an envelope that receivers would reject.
func (s *kmsSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	signature, err := s.key.SignDigest(ctx, digest[:])
	if err != nil {
		return nil, errors.New("KMS signing failed")
	}
	if !ecdsa.VerifyASN1(s.public, digest[:], signature) {
		return nil, errors.New("KMS returned a signature that does not verify")
	}
	return signature, nil
}

type memorySigner struct {
	id  string
	key *ecdsa.PrivateKey
}

func (s *memorySigner) KeyID() string               { return s.id }
func (s *memorySigner) PublicKey() *ecdsa.PublicKey { return &s.key.PublicKey }

func (s *memorySigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}
