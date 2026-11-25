package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func decryptResponse(t *testing.T, w http.ResponseWriter) {
	plain := []byte("ok")
	serveJSON(t, w, map[string]any{"plaintext": plain, "plaintextCrc32c": wireCRC(plain)})
}

func TestRetryStatus(t *testing.T) {
	for _, tc := range []struct{ status, attempts int }{
		{429, 2}, {500, 2}, {502, 2}, {503, 2}, {504, 2}, {400, 1}, {401, 1}, {403, 1}, {404, 1}, {501, 1},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			first := make(chan []byte, 1)
			c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if calls.Add(1) == 1 {
					first <- body
					http.Error(w, "private response", tc.status)
					return
				}
				if !bytes.Equal(body, <-first) {
					t.Error("request changed across attempts")
				}
				decryptResponse(t, w)
			}, WithMaxAttempts(2))
			key, _ := c.SymmetricKey(resource)
			_, err := key.Decrypt(t.Context(), []byte("private ciphertext"), nil)
			if calls.Load() != int32(tc.attempts) || (err == nil) != (tc.attempts == 2) {
				t.Fatalf("calls=%d err=%v", calls.Load(), err)
			}
			if err != nil && err.Error() != fmt.Sprintf("KMS decrypt failed (HTTP %d)", tc.status) {
				t.Fatal("unsafe HTTP error")
			}
		})
	}
}

func TestRetryNetworkError(t *testing.T) {
	var calls atomic.Int32
	c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		decryptResponse(t, w)
	})
	key, _ := c.SymmetricKey(resource)
	if _, err := key.Decrypt(t.Context(), []byte("input"), nil); err != nil || calls.Load() != 2 {
		t.Fatal("connection retry failed", err)
	}
}

func TestAttemptDeadlineAndBudget(t *testing.T) {
	var attempts atomic.Int32
	c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}, WithTimeout(120*time.Millisecond), WithMaxAttempts(2))
	key, _ := c.SymmetricKey(resource)
	if _, err := key.Decrypt(t.Context(), []byte("input"), nil); !errors.Is(err, context.DeadlineExceeded) || attempts.Load() != 2 {
		t.Fatalf("timeouts=%d err=%v", attempts.Load(), err)
	}

	started := make(chan struct{})
	c = tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		http.Error(w, "private", 429)
	})
	key, _ = c.SymmetricKey(resource)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	if _, err := key.Decrypt(ctx, []byte("input"), nil); !errors.Is(err, context.Canceled) {
		t.Fatal("parent cancellation ignored", err)
	}
}

func TestRejectRedirect(t *testing.T) {
	var calls atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer other.Close()
	c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 307) })
	k, _ := c.SymmetricKey(resource)
	_, err := k.Encrypt(t.Context(), []byte("plaintext"), nil)
	if err == nil || calls.Load() != 0 {
		t.Fatal("followed redirect with plaintext")
	}
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) { return f() }

func TestCredentialRefreshDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	c := tlsClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected unauthenticated request") }, WithMaxAttempts(2), WithTimeout(30*time.Millisecond))
	c.auth = &credentials{source: tokenSourceFunc(func() (*oauth2.Token, error) {
		calls.Add(1)
		<-release
		return nil, errors.New("private credentials")
	})}
	key, _ := c.SymmetricKey(resource)
	_, err := key.Decrypt(t.Context(), nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatal("token refresh exceeded deadline or was duplicated", err)
	}
}

func TestExternalAccountImpersonation(t *testing.T) {
	const scopeWant = "https://www.googleapis.com/auth/cloudkms"
	var sts, iam, api atomic.Int32
	auth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sts":
			sts.Add(1)
			if r.FormValue("subject_token") != "projected-test-token" {
				t.Error("missing projected identity")
			}
			serveJSON(t, w, map[string]any{"access_token": "federated-test-token", "token_type": "Bearer", "expires_in": 3600})
		case "/impersonate":
			iam.Add(1)
			var in struct{ Scope []string }
			if r.Header.Get("Authorization") != "Bearer federated-test-token" || json.NewDecoder(r.Body).Decode(&in) != nil || !slices.Equal(in.Scope, []string{scopeWant}) {
				t.Error("incorrect impersonation request")
			}
			serveJSON(t, w, map[string]any{"accessToken": "impersonated-test-token", "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer auth.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.Add(1)
		if r.Header.Get("Authorization") != "Bearer impersonated-test-token" {
			t.Error("wrong KMS identity")
		}
		decryptResponse(t, w)
	}))
	defer server.Close()
	dir := t.TempDir()
	tokenPath, file := filepath.Join(dir, "projected"), filepath.Join(dir, "adc.json")
	if err := os.WriteFile(tokenPath, []byte("projected-test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{
		"type": "external_account", "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/test/providers/test",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": auth.URL + "/sts",
		"service_account_impersonation_url": auth.URL + "/impersonate", "credential_source": map[string]string{"file": tokenPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, config, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", file)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), oauth2.HTTPClient, server.Client()))
	c, err := New(ctx, WithEndpoint(server.URL), WithMaxAttempts(1))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := c.SymmetricKey(resource)
	for range 2 {
		if _, err := key.Decrypt(t.Context(), []byte("input"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if sts.Load() != 1 || iam.Load() != 1 || api.Load() != 2 {
		t.Fatal("unexpected token exchange or KMS call count")
	}
}
