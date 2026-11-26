// Package sealing unwraps versioned service data keys at startup. Local seals
// use AES-256-GCM with a one-byte format (1), a big-endian uint32 key version,
// a random 12-byte nonce and the ciphertext with its 16-byte tag. The five-byte
// header followed by the caller's AAD is authenticated.
//
// A wrapped key file is a JSON object of at most 64 KiB, for example:
//
//	{"format":"kaivo.sealing.v1","service":"sample","purpose":"data","current":1,
//	 "keys":[{"version":1,"wrapped":"YQ=="}]}
//
// Replace the example entry with the result of NewWrappedKey. Each version
// uses the UTF-8 bytes of kaivo:<service>:<purpose>:v<version> as wrapping AAD.
package sealing

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/Kaivodev/servicekit/config"
)

const keySize = 32
const headerSize = 5

// Keyring holds unwrapped keys in memory. Its methods may run concurrently.
type Keyring struct {
	mu      sync.RWMutex
	current uint32
	keys    map[uint32][]byte
}

// Development copies a single local development key into version 1. Callers
// pass their loaded environment; it is refused outside development, as are
// file signers.
func Development(env config.Environment, key []byte) (*Keyring, error) {
	if !env.IsDevelopment() {
		return nil, errors.New("development keyring requires AIPAY_ENVIRONMENT=development")
	}
	if len(key) != keySize {
		return nil, errors.New("sealing key must be 32 bytes")
	}
	return &Keyring{current: 1, keys: map[uint32][]byte{1: bytes.Clone(key)}}, nil
}

// Current returns the current version, or zero after Close.
func (k *Keyring) Current() uint32 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current
}

// Versions returns a sorted snapshot of the available versions.
func (k *Keyring) Versions() []uint32 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return slices.Sorted(maps.Keys(k.keys))
}

func (k *Keyring) aead(version uint32) (cipher.AEAD, error) {
	key, ok := k.keys[version]
	if !ok {
		return nil, errors.New("sealing key version unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// Seal encrypts with the current key and a fresh nonce.
func (k *Keyring) Seal(plaintext, aad []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	aead, err := k.aead(k.current)
	if err != nil {
		return nil, err
	}
	header := make([]byte, headerSize)
	header[0] = 1
	binary.BigEndian.PutUint32(header[1:], k.current)
	return aead.Seal(header, nil, plaintext, slices.Concat(header, aad)), nil
}

// Open authenticates a seal using the version in its header.
func (k *Keyring) Open(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < headerSize || ciphertext[0] != 1 {
		return nil, errors.New("invalid sealing header")
	}
	header := ciphertext[:headerSize]
	k.mu.RLock()
	defer k.mu.RUnlock()
	aead, err := k.aead(binary.BigEndian.Uint32(header[1:]))
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, ciphertext[headerSize:], slices.Concat(header, aad))
}

// Derive uses HKDF-SHA256 with the four-byte big-endian version as salt and
// info as the application context. Valid lengths are 1 through 8160 bytes.
func (k *Keyring) Derive(version uint32, info string, n int) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.keys[version]
	if !ok {
		return nil, errors.New("sealing key version unavailable")
	}
	if n <= 0 || n > 255*sha256.Size {
		return nil, errors.New("invalid derived key length")
	}
	var salt [4]byte
	binary.BigEndian.PutUint32(salt[:], version)
	return hkdf.Key(sha256.New, key, salt[:], info, n)
}

// Close waits for active operations and zeros all retained key bytes.
func (k *Keyring) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range k.keys {
		clear(key)
	}
	clear(k.keys)
	k.current = 0
}
