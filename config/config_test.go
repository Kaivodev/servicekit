package config

import (
	"strings"
	"testing"
	"time"
)

func validSettings() map[string]string {
	return map[string]string{
		"AIPAY_DATABASE_URL":      "postgres://test:private-password@localhost/test",
		"AIPAY_TLS_CA_FILE":       "ca.crt",
		"AIPAY_TLS_CERT_FILE":     "tls.crt",
		"AIPAY_TLS_KEY_FILE":      "tls.key",
		"AIPAY_RPC_ALLOWED_PEERS": "backend,probe",
	}
}

func TestLoad(t *testing.T) {
	base := validSettings()
	for _, tc := range []struct{ key, value string }{
		{"AIPAY_DATABASE_URL", ""}, {"AIPAY_TLS_CA_FILE", ""}, {"AIPAY_TLS_KEY_FILE", ""},
		{"AIPAY_TLS_TRUST_DOMAIN", "bad/domain"}, {"AIPAY_RPC_ALLOWED_PEERS", ""},
		{"AIPAY_RPC_ALLOWED_PEERS", "backend,backend"}, {"AIPAY_RPC_ALLOWED_PEERS", "*"},
		{"AIPAY_GRPC_ADDR", "localhost:0"}, {"AIPAY_GRPC_ADDR", "localhost:90000"},
		{"AIPAY_RPC_CALL_TIMEOUT", "0"}, {"AIPAY_RPC_MAX_MESSAGE_BYTES", "-1"},
		{"AIPAY_DATABASE_MIN_CONNS", "100"}, {"AIPAY_REDIS_URL", "http://localhost"},
		{"AIPAY_LOG_LEVEL", "unknown"}, {"AIPAY_HEALTH_TIMEOUT", "20s"},
		{EnvironmentVariable, "dev"}, {EnvironmentVariable, "staging"}, {EnvironmentVariable, "Development"},
		{"AIPAY_TLS_RELOAD_INTERVAL", "0s"},
		{"AIPAY_RPC_MAX_CONNECTION_AGE", "2h"}, {"AIPAY_RPC_MAX_CONNECTION_AGE", "0s"}, {"AIPAY_RPC_MAX_CONNECTION_AGE", "10s"},
		{"AIPAY_RPC_MAX_CONNECTION_AGE_GRACE", "-1s"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			_, err := Load("iam", "127.0.0.1:9001", func(key string) string {
				if key == tc.key {
					return tc.value
				}
				return base[key]
			})
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), "private-password") {
				t.Fatal("credentials exposed")
			}
		})
	}
	c, err := Load("iam", "127.0.0.1:9001", func(key string) string { return base[key] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Redis.URL != "" || c.Service != "iam" || c.Logging.Service != "iam" || c.RPC.Address != "127.0.0.1:9001" || len(c.RPC.AllowedPeers) != 2 || c.Environment != Production || c.TLS.ReloadInterval != 30*time.Second || c.RPC.MaxConnectionAge != 54*time.Minute || c.RPC.MaxConnectionAgeGrace != 30*time.Second {
		t.Fatalf("unexpected defaults: %+v", c.RPC)
	}
	base[EnvironmentVariable] = "test"
	c, err = Load("iam", "127.0.0.1:9001", func(key string) string { return base[key] })
	if err != nil || c.Environment != Test {
		t.Fatalf("test environment: got %q, err=%v", c.Environment, err)
	}
}

func TestLoadCacheRedisTLS(t *testing.T) {
	const (
		plaintext   = "redis://:cache-password@localhost/0"
		tlsError    = "AIPAY_REDIS_URL requires rediss:// in production"
		formatError = "AIPAY_REDIS_URL must be a redis:// or rediss:// URL with a host"
	)
	for _, tc := range []struct{ name, environment, redisURL, wantErr string }{
		{"production plaintext", "production", plaintext, tlsError},
		{"default plaintext", "", plaintext, tlsError},
		{"production TLS", "production", "rediss://localhost/0", ""},
		{"development plaintext", "development", plaintext, ""},
		{"test plaintext", "test", plaintext, ""},
		{"production without cache", "production", "", ""},
		{"invalid environment", "dev", plaintext, "AIPAY_ENVIRONMENT must be development, test or production"},
		{"unsupported scheme", "production", "http://localhost/0", formatError},
		{"missing host", "production", "redis:///0", formatError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := validSettings()
			settings[EnvironmentVariable] = tc.environment
			settings["AIPAY_REDIS_URL"] = tc.redisURL
			_, err := Load("iam", "localhost:9001", func(key string) string { return settings[key] })
			if err != nil && strings.Contains(err.Error(), "cache-password") {
				t.Fatal("cache Redis password exposed")
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("Load() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
