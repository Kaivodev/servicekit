package servicetoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/signing"
)

func encode(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func makeJWT(t *testing.T, alg, kid string, key any, claims map[string]any) string {
	t.Helper()
	message := rawURL.EncodeToString(encode(t, map[string]string{"alg": alg, "kid": kid})) + "." + rawURL.EncodeToString(encode(t, claims))
	hash := sha256.Sum256([]byte(message))
	var sig []byte
	switch alg {
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case "RS256":
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
	case "HS256":
		// Exercise algorithm confusion with the actual registered RSA public key.
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, der)
		mac.Write([]byte(message))
		sig = mac.Sum(nil)
	}
	return message + "." + rawURL.EncodeToString(sig)
}

func claims(now time.Time) map[string]any {
	return map[string]any{"iss": "native", "sub": "system:serviceaccount:local:backend", "aud": "kaivo:iam",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(),
		"kubernetes.io": map[string]any{"namespace": "local", "serviceaccount": map[string]string{"name": "backend"}}}
}

func TestVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]string{"kid": "rsa", "kty": "RSA", "alg": "RS256", "n": rawURL.EncodeToString(key.N.Bytes()), "e": rawURL.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
	reg, err := parseJWKS(encode(t, map[string]any{"keys": []any{jwk}}))
	if err != nil {
		t.Fatal(err)
	}
	tr := &Transport{service: "iam", options: config.Transport{Issuer: "native", ServiceNamespaces: map[string]string{"backend": "local"}}}
	tr.keys.Store(&snapshot{keys: reg})
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name, field string
		value       any
		want        string
	}{
		{"valid", "", "", ""}, {"audience array", "aud", []string{"other", "kaivo:iam"}, ""},
		{"wrong issuer", "iss", "other", "token_issuer"}, {"missing issuer", "iss", nil, "token_issuer"},
		{"wrong audience", "aud", []string{"kaivo:payment"}, "token_audience"}, {"bad audience type", "aud", 1, "token_audience"}, {"mixed audience array", "aud", []any{"kaivo:iam", nil}, "token_audience"},
		{"missing exp", "exp", nil, "token_malformed"}, {"missing iat", "iat", nil, "token_malformed"}, {"missing nbf", "nbf", nil, "token_malformed"},
		{"expired", "exp", now.Unix() - 31, "token_expired"}, {"exp boundary", "exp", now.Unix() - 30, "token_expired"},
		{"exp within skew", "exp", now.Unix() - 29, ""}, {"nbf boundary", "nbf", now.Unix() + 30, ""},
		{"too early", "nbf", now.Unix() + 31, "token_expired"}, {"iat boundary", "iat", now.Unix() + 30, ""},
		{"future issue", "iat", now.Unix() + 31, "token_expired"},
		{"malformed subject", "sub", "system:user:local:backend", "token_subject"},
		{"invalid SA", "sub", "system:serviceaccount:local:bad/name", "token_subject"},
		{"Kubernetes namespace", "kubernetes.io", map[string]any{"namespace": "other", "serviceaccount": map[string]string{"name": "backend"}}, "token_subject"},
		{"Kubernetes SA", "kubernetes.io", map[string]any{"namespace": "local", "serviceaccount": map[string]string{"name": "payment"}}, "token_subject"},
		{"Kubernetes null", "kubernetes.io", json.RawMessage("null"), "token_subject"},
		{"optional Kubernetes claim", "kubernetes.io", nil, ""},
		{"unknown service", "sub", "system:serviceaccount:local:worker", "token_namespace"},
		{"wrong namespace", "sub", "system:serviceaccount:other:backend", "token_namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claims(now)
			if tc.field == "sub" {
				delete(c, "kubernetes.io")
			}
			if tc.field != "" {
				if tc.value == nil {
					delete(c, tc.field)
				} else {
					c[tc.field] = tc.value
				}
			}
			peer, reason := tr.verify(makeJWT(t, "RS256", "rsa", key, c), now)
			if reason != tc.want || (tc.want == "" && peer != "backend") {
				t.Fatalf("peer=%q reason=%q", peer, reason)
			}
		})
	}
	c := claims(now)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, token, want string }{
		{"unknown kid", makeJWT(t, "RS256", "unknown", key, c), "token_signature"},
		{"wrong key type", makeJWT(t, "ES256", "rsa", ec, c), "token_signature"},
		{"algorithm confusion", makeJWT(t, "HS256", "rsa", &key.PublicKey, c), "token_malformed"},
		{"unsecured JWS", makeJWT(t, "none", "rsa", nil, c), "token_malformed"},
		{"invalid signature", makeJWT(t, "RS256", "rsa", key, c) + "AA", "token_signature"},
		{"wrong segment count", "a.b.c.d", "token_malformed"}, {"encoding", "!.!.!", "token_malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, r := tr.verify(tc.token, now); r != tc.want {
				t.Fatalf("reason %s", r)
			}
		})
	}
}

func TestJWKSRotationAndReadiness(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	now := time.Now()
	publish := func(id string) string {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		data, err := signing.MarshalJWKS(map[string]*ecdsa.PublicKey{id: &key.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		tmp := path + ".next"
		if err = os.WriteFile(tmp, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
		return makeJWT(t, "ES256", id, key, claims(now))
	}
	first := publish("first")
	tr, err := Load(config.Transport{TokenDir: dir, JWKSFile: path, Issuer: "native", ServiceNamespaces: map[string]string{"backend": "local"}}, "iam", true)
	if err != nil {
		t.Fatal(err)
	}
	if peer, r := tr.verify(first, now); peer != "backend" || r != "" {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Watch(ctx, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	defer func() { cancel(); <-done }()
	second := publish("second")
	deadline := time.Now().Add(time.Second)
	for {
		if _, r := tr.verify(second, now); r == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("JWKS rotation timed out")
		}
		time.Sleep(time.Millisecond)
	}
	if _, r := tr.verify(first, now); r != "token_signature" {
		t.Fatal("retired key accepted")
	}
	if err = os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if tr.Check(ctx) == nil {
		t.Fatal("broken JWKS reported ready")
	}
	if _, r := tr.verify(second, now); r != "" {
		t.Fatal("last valid key lost")
	}
	tr.options.TokenDir = filepath.Join(dir, "absent")
	if tr.Check(ctx) == nil {
		t.Fatal("missing token directory reported ready")
	}
}

func TestTokenFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam")
	f := &tokenFile{path: path}
	for _, data := range []string{"", " \n", "embedded\nnewline", strings.Repeat("a", 65537), "valid.token.file"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		value, err := f.read()
		if (err == nil) != (data == "valid.token.file") || (err == nil && value != data) {
			t.Fatal("unexpected token file result")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.read(); err == nil {
		t.Fatal("missing token reused cached credential")
	}
}

func TestRejectInvalidJWKS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signing.MarshalJWKS(map[string]*ecdsa.PublicKey{"k": &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"private member", func(k map[string]any) { k["d"] = "secret" }},
		{"algorithm mismatch", func(k map[string]any) { k["alg"] = "RS256" }},
		{"wrong curve", func(k map[string]any) { k["crv"] = "P-521" }},
		{"off curve", func(k map[string]any) { k["x"] = rawURL.EncodeToString(make([]byte, 32)) }},
		{"missing kid", func(k map[string]any) { delete(k, "kid") }},
		{"encryption key", func(k map[string]any) { k["use"] = "enc" }},
		{"key operations", func(k map[string]any) { k["key_ops"] = []string{"encrypt"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc struct {
				Keys []map[string]any `json:"keys"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			tc.edit(doc.Keys[0])
			if _, err := parseJWKS(encode(t, doc)); err != errKeys {
				t.Fatal("unsafe JWKS accepted")
			}
		})
	}
}

func TestPeerRequiresThisVerifier(t *testing.T) {
	first, second := new(Transport), new(Transport)
	ctx := context.WithValue(t.Context(), peerKey{first}, "backend")
	if got, err := first.Peer(ctx); got != "backend" || err != nil {
		t.Fatal("verified caller lost")
	}
	if _, err := second.Peer(ctx); err == nil {
		t.Fatal("accepted a caller verified for another transport")
	}
}
