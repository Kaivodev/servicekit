package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Kaivodev/servicekit/signing"
)

func TestIssuerRotation(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- run(ctx, root, "local-issuer", map[string][]string{"backend": {"iam", "ledger"}, "iam": {}})
		}()
		synctest.Wait()
		pub, err := signing.LoadJWKS(filepath.Join(root, "token-issuer", "jwks.json"))
		if err != nil {
			t.Fatal(err)
		}
		key, ok := pub.Lookup(keyID)
		if !ok {
			t.Fatal("issuer public key missing")
		}
		check := func(target string) string {
			t.Helper()
			path := filepath.Join(root, "tokens", "backend", target)
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(string(file), ".")
			if len(parts) != 3 {
				t.Fatal("invalid token")
			}
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err != nil || len(sig) != 64 || !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Fatal("invalid issuer signature")
			}
			body, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal("invalid claims encoding")
			}
			var c struct {
				Iss, Sub      string
				Aud           []string
				Nbf, Iat, Exp int64
				Kube          struct {
					Namespace      string
					ServiceAccount struct{ Name string }
				} `json:"kubernetes.io"`
			}
			if json.Unmarshal(body, &c) != nil || c.Iss != "local-issuer" || c.Sub != "system:serviceaccount:local:backend" || len(c.Aud) != 1 || c.Aud[0] != "kaivo:"+target ||
				c.Nbf != c.Iat || c.Iat != time.Now().Unix() || c.Exp-c.Iat != 600 || c.Kube.Namespace != "local" || c.Kube.ServiceAccount.Name != "backend" {
				t.Fatal("invalid issued claims")
			}
			return string(file)
		}
		first := check("iam")
		check("ledger")
		time.Sleep(4 * time.Minute)
		synctest.Wait()
		if check("iam") == first {
			t.Fatal("issuer did not refresh the target token")
		}
		for _, path := range []string{"token-issuer/issuer.key", "token-issuer/jwks.json", "tokens/backend/iam"} {
			info, err := os.Stat(filepath.Join(root, path))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("insecure material permissions", path)
			}
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, "token-issuer/ready")); !os.IsNotExist(err) {
			t.Fatal("issuer remains ready after stop")
		}
	})
}
