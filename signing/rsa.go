package signing

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// RSASigner produces PKCS#1 v1.5 signatures over SHA-256(message).
type RSASigner interface {
	KeyID() string
	PublicKey() *rsa.PublicKey
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

type rsaSigner struct {
	id         string
	public     *rsa.PublicKey
	signDigest func(context.Context, []byte) ([]byte, error)
}

// NewRSAKMS opens an RSA signing key of at least 2048 bits.
func NewRSAKMS(ctx context.Context, keyID string, key KMSKey) (RSASigner, error) {
	if !ValidKeyID(keyID) || key == nil {
		return nil, errors.New("KMS signer requires a key ID and key")
	}
	public, err := key.PublicKey(ctx)
	if err != nil {
		return nil, errors.New("read KMS public key failed")
	}
	rk, ok := public.(*rsa.PublicKey)
	if !ok || rk == nil || rk.N == nil || rk.N.BitLen() < 2048 {
		return nil, errors.New("KMS key must be RSA of at least 2048 bits")
	}
	return &rsaSigner{id: keyID, public: rk, signDigest: key.SignDigest}, nil
}

// OpenRSAFile opens a private PKCS#8 DER or PEM file in development.
func OpenRSAFile(cfg Config) (RSASigner, error) {
	if cfg.Backend != BackendFile {
		return nil, errors.New("RSA file signer requires the file backend")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key, err := readDevelopmentKey(cfg.KeyFile, true)
	if err != nil {
		return nil, err
	}
	rk, ok := key.(*rsa.PrivateKey)
	if !ok || rk.N.BitLen() < 2048 {
		return nil, errors.New("development key must be RSA of at least 2048 bits")
	}
	return &rsaSigner{id: cfg.KeyID, public: &rk.PublicKey, signDigest: func(_ context.Context, digest []byte) ([]byte, error) {
		return rsa.SignPKCS1v15(nil, rk, crypto.SHA256, digest)
	}}, nil
}

func (s *rsaSigner) KeyID() string             { return s.id }
func (s *rsaSigner) PublicKey() *rsa.PublicKey { return s.public }
func (s *rsaSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	signature, err := s.signDigest(ctx, digest[:])
	if err != nil {
		return nil, errors.New("RSA signing failed")
	}
	if rsa.VerifyPKCS1v15(s.public, crypto.SHA256, digest[:], signature) != nil {
		return nil, errors.New("RSA signature does not verify")
	}
	return signature, nil
}
