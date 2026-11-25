package gcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kaivodev/servicekit/signing"
)

const keyPath = `projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+`

var (
	keyName     = regexp.MustCompile("^" + keyPath + "$")
	versionName = regexp.MustCompile("^" + keyPath + "/cryptoKeyVersions/[0-9]+$")
	crcTable    = crc32.MakeTable(crc32.Castagnoli)
)

func checksum(data []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(data, crcTable)), 10)
}

// SigningKey binds a single version and caches its verified PKIX public key.
type SigningKey struct {
	client *Client
	name   string
	gate   chan struct{}
	der    []byte
}

var _ signing.KMSKey = (*SigningKey)(nil)

// SigningKey validates a full CryptoKeyVersion name without contacting KMS.
func (c *Client) SigningKey(name string) (*SigningKey, error) {
	if !versionName.MatchString(name) {
		return nil, errors.New("invalid KMS signing key version")
	}
	return &SigningKey{client: c, name: name, gate: make(chan struct{}, 1)}, nil
}

// PublicKey returns a fresh copy of the public key. Only successful reads are cached.
func (k *SigningKey) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	const op = "publicKey"
	select {
	case k.gate <- struct{}{}:
		defer func() { <-k.gate }()
	case <-ctx.Done():
		return nil, callError{op: op, cause: ctx.Err()}
	}
	if k.der != nil {
		return x509.ParsePKIXPublicKey(k.der)
	}
	var response struct {
		Name      string
		PEM       string
		PemCrc32c string
		Algorithm string
	}
	if err := k.client.call(ctx, op, k.name+"/publicKey", nil, &response); err != nil {
		return nil, err
	}
	failure := callError{op: op, status: http.StatusOK}
	if response.Name != k.name || checksum([]byte(response.PEM)) != response.PemCrc32c {
		return nil, failure
	}
	block, rest := pem.Decode([]byte(response.PEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, failure
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, failure
	}
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() || response.Algorithm != "EC_SIGN_P256_SHA256" {
			return nil, failure
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || response.Algorithm != fmt.Sprintf("RSA_SIGN_PKCS1_%d_SHA256", key.N.BitLen()) {
			return nil, failure
		}
	default:
		return nil, failure
	}
	k.der = block.Bytes
	return public, nil
}

// SignDigest signs exactly one SHA-256 digest and returns the provider's bytes.
func (k *SigningKey) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	const op = "asymmetricSign"
	if len(digest) != sha256.Size {
		return nil, callError{op: op}
	}
	type hashes struct {
		SHA256 []byte `json:"sha256"`
	}
	request := struct {
		Digest hashes `json:"digest"`
		CRC    string `json:"digestCrc32c"`
	}{hashes{digest}, checksum(digest)}
	var response struct {
		Name                 string
		Signature            []byte
		SignatureCrc32c      string
		VerifiedDigestCrc32c bool
	}
	if err := k.client.call(ctx, op, k.name+":"+op, request, &response); err != nil {
		return nil, err
	}
	if response.Name != k.name || !response.VerifiedDigestCrc32c || len(response.Signature) == 0 || checksum(response.Signature) != response.SignatureCrc32c {
		return nil, callError{op: op, status: http.StatusOK}
	}
	return response.Signature, nil
}

// SymmetricKey uses a CryptoKey name so that KMS can rotate its primary version.
type SymmetricKey struct {
	client *Client
	name   string
}

// SymmetricKey validates an unversioned CryptoKey name without contacting KMS.
func (c *Client) SymmetricKey(name string) (*SymmetricKey, error) {
	if !keyName.MatchString(name) {
		return nil, errors.New("invalid KMS symmetric key name")
	}
	return &SymmetricKey{client: c, name: name}, nil
}

// Encrypt wraps up to 64 KiB of plaintext with caller-supplied AAD.
func (k *SymmetricKey) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	const op = "encrypt"
	if len(plaintext) > 64<<10 {
		return nil, callError{op: op}
	}
	request := struct {
		Plaintext []byte `json:"plaintext"`
		AAD       []byte `json:"additionalAuthenticatedData"`
		CRC       string `json:"plaintextCrc32c"`
		AADCRC    string `json:"additionalAuthenticatedDataCrc32c"`
	}{nonNil(plaintext), nonNil(aad), checksum(plaintext), checksum(aad)}
	var response struct {
		Name                                      string
		Ciphertext                                []byte
		CiphertextCrc32c                          string
		VerifiedPlaintextCrc32c                   bool
		VerifiedAdditionalAuthenticatedDataCrc32c bool
	}
	if err := k.client.call(ctx, op, k.name+":"+op, request, &response); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(response.Name, k.name+"/cryptoKeyVersions/") || !versionName.MatchString(response.Name) ||
		!response.VerifiedPlaintextCrc32c || !response.VerifiedAdditionalAuthenticatedDataCrc32c ||
		len(response.Ciphertext) == 0 || checksum(response.Ciphertext) != response.CiphertextCrc32c {
		return nil, callError{op: op, status: http.StatusOK}
	}
	return response.Ciphertext, nil
}

// Decrypt unwraps a ciphertext and checks the plaintext checksum.
func (k *SymmetricKey) Decrypt(ctx context.Context, ciphertext, aad []byte) ([]byte, error) {
	const op = "decrypt"
	request := struct {
		Ciphertext []byte `json:"ciphertext"`
		AAD        []byte `json:"additionalAuthenticatedData"`
		CRC        string `json:"ciphertextCrc32c"`
		AADCRC     string `json:"additionalAuthenticatedDataCrc32c"`
	}{nonNil(ciphertext), nonNil(aad), checksum(ciphertext), checksum(aad)}
	var response struct {
		Plaintext       []byte
		PlaintextCrc32c string
	}
	if err := k.client.call(ctx, op, k.name+":"+op, request, &response); err != nil {
		clear(response.Plaintext)
		return nil, err
	}
	if len(response.Plaintext) > 64<<10 || checksum(response.Plaintext) != response.PlaintextCrc32c {
		clear(response.Plaintext)
		return nil, callError{op: op, status: http.StatusOK}
	}
	return response.Plaintext, nil
}

// ProtoJSON bytes use a base64 string even for an empty input.
func nonNil(data []byte) []byte {
	if data == nil {
		return []byte{}
	}
	return data
}

// OpenSigner opens the configured P-256 signer. Only KMS requires a client.
func OpenSigner(ctx context.Context, client *Client, cfg signing.Config) (signing.Signer, error) {
	if cfg.Backend != signing.BackendKMS {
		return signing.Open(ctx, cfg, nil)
	}
	if client == nil {
		return nil, errors.New("KMS signer requires a client")
	}
	key, err := client.SigningKey(cfg.KMSKey)
	if err != nil {
		return nil, err
	}
	return signing.Open(ctx, cfg, key)
}
