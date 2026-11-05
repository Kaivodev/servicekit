// Package signing provides business signers and public key registries for
// cross-domain assertions such as signed events. Every signature is ECDSA P-256
// over SHA-256 of the message, ASN.1 DER encoded. Production keys stay in a
// KMS/HSM; the in-memory signer exists only for local development.
package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"regexp"

	"github.com/Kaivodev/servicekit/config"
)

const (
	BackendKMS    = "kms"
	BackendMemory = "memory"
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

// KMSKey is one asymmetric ECDSA P-256 key held by a cloud KMS or HSM. The
// adapter binds the provider's key resource and returns DER signatures; the
// private key never leaves the provider.
type KMSKey interface {
	PublicKey(ctx context.Context) (crypto.PublicKey, error)
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}

type Config struct {
	Environment config.Environment
	Backend     string
	KeyID       string
}

// Load reads AIPAY_ENVIRONMENT, AIPAY_SIGNING_BACKEND (default kms) and
// AIPAY_SIGNING_KEY_ID. It does not open the key.
func Load(get func(string) string) (Config, error) {
	environment, err := config.LoadEnvironment(get)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{Environment: environment, Backend: get("AIPAY_SIGNING_BACKEND"), KeyID: get("AIPAY_SIGNING_KEY_ID")}
	if cfg.Backend == "" {
		cfg.Backend = BackendKMS
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if !ValidKeyID(c.KeyID) {
		return errors.New("AIPAY_SIGNING_KEY_ID must name the signing key")
	}
	switch c.Backend {
	case BackendKMS:
		return nil
	case BackendMemory:
		if c.Environment != config.Development {
			return errors.New("the in-memory signer is only allowed when AIPAY_ENVIRONMENT=development")
		}
		return nil
	default:
		return errors.New("AIPAY_SIGNING_BACKEND must be kms or memory")
	}
}

// Open is the only way to obtain the in-memory signer, and refuses it outside
// development. key is required for the KMS backend and ignored otherwise.
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
	return NewKMS(ctx, cfg.KeyID, key)
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
	if !ok || ec.Curve != elliptic.P256() {
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
