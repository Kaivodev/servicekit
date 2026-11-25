// kaivo-devtoken signs short-lived, target-specific tokens for the native stack.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/signing"
)

const keyID = "native-sa"
const lifetime = 10 * time.Minute
const rotation = 4 * time.Minute

// The controller serializes issuer processes. Each reader sees one complete file.
func replace(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rotate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func privateDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("issuer state requires a private directory")
	}
	return nil
}

func loadKey(dir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, "issuer.key")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		raw, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return key, replace(path, raw)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("invalid native issuer key")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(raw)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, errors.New("invalid native issuer key")
	}
	return key, nil
}

func token(key *ecdsa.PrivateKey, issuer, caller, target string, now time.Time) (string, error) {
	claims, err := json.Marshal(map[string]any{
		"iss": issuer, "sub": "system:serviceaccount:local:" + caller, "aud": []string{"kaivo:" + target},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(lifetime).Unix(),
		"kubernetes.io": map[string]any{"namespace": "local", "serviceaccount": map[string]string{"name": caller}},
	})
	if err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	enc := base64.RawURLEncoding
	message := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return message + "." + enc.EncodeToString(sig[:]), nil
}

func run(ctx context.Context, state, issuer string, targets map[string][]string) error {
	if state == "" || issuer == "" || len(targets) == 0 {
		return errors.New("missing native issuer configuration")
	}
	dir, tokens := filepath.Join(state, "token-issuer"), filepath.Join(state, "tokens")
	for _, path := range []string{state, dir, tokens} {
		if err := privateDir(path); err != nil {
			return err
		}
	}
	for caller, peers := range targets {
		if !config.ValidService(caller) {
			return errors.New("invalid caller")
		}
		for _, target := range peers {
			if !config.ValidService(target) {
				return errors.New("invalid target")
			}
		}
		if err := privateDir(filepath.Join(tokens, caller)); err != nil {
			return err
		}
	}
	key, err := loadKey(dir)
	if err != nil {
		return err
	}
	jwks, err := signing.MarshalJWKS(map[string]*ecdsa.PublicKey{keyID: &key.PublicKey})
	if err != nil {
		return err
	}
	if err := replace(filepath.Join(dir, "jwks.json"), jwks); err != nil {
		return err
	}
	ready := filepath.Join(dir, "ready")
	defer os.Remove(ready)
	ticker := time.NewTicker(rotation)
	defer ticker.Stop()
	for {
		now := time.Now()
		for caller, peers := range targets {
			for _, target := range peers {
				value, err := token(key, issuer, caller, target, now)
				if err != nil {
					return err
				}
				if err := replace(filepath.Join(tokens, caller, target), []byte(value)); err != nil {
					return err
				}
			}
		}
		if err := replace(ready, []byte("ready\n")); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func main() {
	state := flag.String("state", "", "private native stack directory")
	issuer := flag.String("issuer", "", "local issuer name")
	matrix := flag.String("targets", "", "JSON object mapping callers to their targets")
	flag.Parse()
	var targets map[string][]string
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if json.Unmarshal([]byte(*matrix), &targets) != nil || run(ctx, *state, *issuer, targets) != nil {
		fmt.Fprintln(os.Stderr, "native service token issuer failed")
		os.Exit(1)
	}
}
