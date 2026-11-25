package gcp

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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/sealing"
	"github.com/Kaivodev/servicekit/signing"
)

const (
	resource = "projects/P_1/locations/test-loc/keyRings/ring/cryptoKeys/sample"
	version  = resource + "/cryptoKeyVersions/12"
)

var (
	_ sealing.Wrapper   = (*SymmetricKey)(nil)
	_ sealing.Unwrapper = (*SymmetricKey)(nil)
)

func tlsClient(t *testing.T, handler http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	c, err := New(t.Context(), append([]Option{WithHTTPClient(server.Client()), WithEndpoint(server.URL)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wireCRC(data []byte) string {
	return fmt.Sprint(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
}

func serveJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func pemKey(t *testing.T, public crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestResourceNamesAndOptions(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "missing-credential-file")
	c, err := New(t.Context(), WithHTTPClient(http.DefaultClient))
	if err != nil {
		t.Fatal(err)
	}
	if c.attempts != 4 || c.timeout.Seconds() != 2 || c.endpoint != "https://cloudkms.googleapis.com/v1/" {
		t.Fatal("unexpected client defaults")
	}
	if _, err := c.SigningKey(version); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SymmetricKey(resource); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SigningKey(resource); err == nil {
		t.Fatal("unversioned signer")
	}
	if _, err := c.SymmetricKey(version); err == nil {
		t.Fatal("versioned symmetric key")
	}
	for _, name := range []string{"", resource + "/", resource + "?", resource + "/../other", strings.Replace(resource, "test-loc", "", 1), strings.Replace(resource, "P_1", "some.project", 1), strings.Replace(resource, "sample", "sample%2Fextra", 1), "/" + resource} {
		if _, err := c.SymmetricKey(name); err == nil {
			t.Errorf("accepted invalid key %q", name)
		}
		if _, err := c.SigningKey(name + "/cryptoKeyVersions/3"); err == nil {
			t.Errorf("accepted invalid key version %q", name)
		}
	}
	for _, suffix := range []string{"", "primary", "1/2", "-1", "1#", "1:sign", "１"} {
		if _, err := c.SigningKey(resource + "/cryptoKeyVersions/" + suffix); err == nil {
			t.Errorf("accepted invalid version suffix %q", suffix)
		}
	}
	for _, option := range []Option{WithTimeout(0), WithMaxAttempts(0), WithEndpoint("http://example.org"), WithEndpoint("https:///"), WithEndpoint("https://x:pw@example.org")} {
		if _, err := New(t.Context(), WithHTTPClient(http.DefaultClient), option); err == nil {
			t.Fatal("invalid option accepted")
		}
	}
	if _, err := New(t.Context()); err == nil || strings.Contains(err.Error(), "missing-credential-file") {
		t.Fatal("unsafe ADC error")
	}
}

func TestPublicKeyIntegrity(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongCurve, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		title, name, algorithm string
		public                 crypto.PublicKey
		badCRC, valid          bool
	}{
		{"p256", version, "EC_SIGN_P256_SHA256", &ec.PublicKey, false, true},
		{"rsa", version, "RSA_SIGN_PKCS1_2048_SHA256", &rk.PublicKey, false, true},
		{"crc", version, "EC_SIGN_P256_SHA256", &ec.PublicKey, true, false},
		{"wrong version", resource, "EC_SIGN_P256_SHA256", &ec.PublicKey, false, false},
		{"wrong curve", version, "EC_SIGN_P256_SHA256", &wrongCurve.PublicKey, false, false},
		{"wrong algorithm", version, "RSA_SIGN_PSS_2048_SHA256", &rk.PublicKey, false, false},
		{"weak RSA", version, "RSA_SIGN_PKCS1_1024_SHA256", &small.PublicKey, false, false},
	} {
		t.Run(tc.title, func(t *testing.T) {
			block := pemKey(t, tc.public)
			crc := wireCRC(block)
			if tc.badCRC {
				crc = ""
			}
			var calls atomic.Int32
			c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/v1/"+version+"/publicKey" || r.Method != "GET" {
					t.Error("unexpected public key request")
				}
				serveJSON(t, w, map[string]any{"name": tc.name, "algorithm": tc.algorithm, "pem": string(block), "pemCrc32c": crc})
			})
			k, _ := c.SigningKey(version)
			public, err := k.PublicKey(t.Context())
			if (err == nil) != tc.valid {
				t.Fatal("wrong public key validation result", err)
			}
			if !tc.valid {
				return
			}
			if !bytes.Equal(pemKey(t, public), block) {
				t.Fatal("wrong public key")
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					got, err := k.PublicKey(t.Context())
					if err != nil || got == public {
						t.Error("public key not independently returned", err)
					}
				})
			}
			wg.Wait()
			if calls.Load() != 1 {
				t.Fatal("public key fetched repeatedly")
			}
		})
	}
}

func TestSignDigestAndOpenSigner(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := []byte("test message")
	digest := sha256.Sum256(msg)
	block := pemKey(t, &ec.PublicKey)
	sig, err := ecdsa.SignASN1(rand.Reader, ec, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		title, name, crc string
		verified, valid  bool
	}{
		{"success", version, wireCRC(sig), true, true}, {"not verified", version, wireCRC(sig), false, false},
		{"wrong CRC", version, "-1", true, false}, {"wrong name", resource, wireCRC(sig), true, false},
	} {
		t.Run(tc.title, func(t *testing.T) {
			c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/"+version+"/publicKey" {
					serveJSON(t, w, map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "pem": string(block), "pemCrc32c": wireCRC(block)})
					return
				}
				if r.URL.Path != "/v1/"+version+":asymmetricSign" || r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("invalid sign request")
				}
				var in struct {
					Digest       map[string][]byte
					DigestCrc32c string
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !bytes.Equal(in.Digest["sha256"], digest[:]) || in.DigestCrc32c != wireCRC(digest[:]) {
					t.Error("invalid sign request fields")
				}
				serveJSON(t, w, map[string]any{"name": tc.name, "signature": sig, "signatureCrc32c": tc.crc, "verifiedDigestCrc32c": tc.verified})
			})
			cfg := signing.Config{Backend: signing.BackendKMS, KeyID: "sample", KMSKey: version}
			s, err := OpenSigner(t.Context(), c, cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Sign(t.Context(), msg)
			if (err == nil) != tc.valid || (tc.valid && !bytes.Equal(got, sig)) {
				t.Fatal("wrong signature result", err)
			}
			k, _ := c.SigningKey(version)
			if _, err := k.SignDigest(t.Context(), digest[1:]); err == nil {
				t.Fatal("short digest accepted")
			}
		})
	}
	if _, err := OpenSigner(t.Context(), nil, signing.Config{Backend: signing.BackendKMS, KeyID: "sample", KMSKey: version}); err == nil {
		t.Fatal("KMS opened without a client")
	}
	if _, err := OpenSigner(t.Context(), nil, signing.Config{Backend: signing.BackendMemory, Environment: config.Development, KeyID: "sample"}); err != nil {
		t.Fatal(err)
	}
}

func TestSymmetricKeyIntegrity(t *testing.T) {
	plain, ct, aad := []byte("plaintext"), []byte("wrapped"), []byte("purpose")
	for _, tc := range []struct {
		title, op, field string
		change           any
	}{
		{"encrypt", "encrypt", "", nil}, {"decrypt", "decrypt", "", nil},
		{"unverified plaintext", "encrypt", "verifiedPlaintextCrc32c", false}, {"unverified AAD", "encrypt", "verifiedAdditionalAuthenticatedDataCrc32c", false},
		{"wrong ciphertext CRC", "encrypt", "ciphertextCrc32c", "-1"}, {"missing ciphertext CRC", "encrypt", "ciphertextCrc32c", nil},
		{"wrong key", "encrypt", "name", resource + "-other/cryptoKeyVersions/1"}, {"no version", "encrypt", "name", resource + "/cryptoKeyVersions/"},
		{"wrong plaintext CRC", "decrypt", "plaintextCrc32c", "-1"}, {"missing plaintext CRC", "decrypt", "plaintextCrc32c", nil},
	} {
		t.Run(tc.title, func(t *testing.T) {
			c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/"+resource+":"+tc.op || r.Method != "POST" {
					t.Error("unexpected symmetric request")
				}
				input, field := plain, "plaintext"
				result := map[string]any{"ciphertext": ct, "ciphertextCrc32c": wireCRC(ct), "name": version, "verifiedAdditionalAuthenticatedDataCrc32c": true, "verifiedPlaintextCrc32c": true}
				if tc.op == "decrypt" {
					input, field = ct, "ciphertext"
					result = map[string]any{"plaintext": plain, "plaintextCrc32c": wireCRC(plain)}
				}
				var in map[string]string
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in) != 4 || in[field] != base64.StdEncoding.EncodeToString(input) || in[field+"Crc32c"] != wireCRC(input) || in["additionalAuthenticatedData"] != base64.StdEncoding.EncodeToString(aad) || in["additionalAuthenticatedDataCrc32c"] != wireCRC(aad) {
					t.Error("invalid symmetric request fields")
				}
				if tc.field != "" {
					if tc.change == nil {
						delete(result, tc.field)
					} else {
						result[tc.field] = tc.change
					}
				}
				serveJSON(t, w, result)
			})
			key, _ := c.SymmetricKey(resource)
			var out []byte
			var err error
			want := ct
			if tc.op == "encrypt" {
				out, err = key.Encrypt(t.Context(), plain, aad)
			} else {
				out, err = key.Decrypt(t.Context(), ct, aad)
				want = plain
			}
			if tc.field == "" {
				if err != nil || !bytes.Equal(out, want) {
					t.Fatal("unexpected result", err)
				}
			} else if err == nil || out != nil {
				t.Fatal("invalid provider result accepted")
			}
		})
	}
}

func TestSymmetricLimits(t *testing.T) {
	var calls atomic.Int32
	c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
		}
		if in["additionalAuthenticatedData"] != "" || in["additionalAuthenticatedDataCrc32c"] != "0" {
			t.Error("empty AAD checksum omitted")
		}
		serveJSON(t, w, map[string]any{"name": version, "ciphertext": []byte("w"), "ciphertextCrc32c": wireCRC([]byte("w")), "verifiedPlaintextCrc32c": true, "verifiedAdditionalAuthenticatedDataCrc32c": true})
	})
	key, _ := c.SymmetricKey(resource)
	if _, err := key.Encrypt(t.Context(), make([]byte, 65537), nil); err == nil || calls.Load() != 0 {
		t.Fatal("oversized plaintext sent")
	}
	if _, err := key.Encrypt(t.Context(), make([]byte, 65536), nil); err != nil || calls.Load() != 1 {
		t.Fatal("maximum plaintext rejected", err)
	}
}

func TestErrorBodyAndResponseLimit(t *testing.T) {
	for _, status := range []int{200, 403} {
		c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, strings.Repeat("private response", 8192))
		})
		k, _ := c.SymmetricKey(resource)
		out, err := k.Decrypt(context.Background(), []byte("private input"), nil)
		if out != nil || err == nil || err.Error() != fmt.Sprintf("KMS decrypt failed (HTTP %d)", status) {
			t.Fatal("unsafe or missing transport error")
		}
	}
}
