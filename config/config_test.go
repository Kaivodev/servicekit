package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	base := map[string]string{"AIPAY_DATABASE_URL": "postgres://test:private-password@localhost/test", "AIPAY_TLS_CA_FILE": "ca.crt", "AIPAY_TLS_CERT_FILE": "tls.crt", "AIPAY_TLS_KEY_FILE": "tls.key", "AIPAY_RPC_ALLOWED_PEERS": "backend,probe"}
	for _, tc := range []struct{ key, value string }{
		{"AIPAY_DATABASE_URL", ""}, {"AIPAY_TLS_CA_FILE", ""}, {"AIPAY_TLS_KEY_FILE", ""},
		{"AIPAY_TLS_TRUST_DOMAIN", "bad/domain"}, {"AIPAY_RPC_ALLOWED_PEERS", ""},
		{"AIPAY_RPC_ALLOWED_PEERS", "backend,backend"}, {"AIPAY_RPC_ALLOWED_PEERS", "*"},
		{"AIPAY_GRPC_ADDR", "localhost:0"}, {"AIPAY_GRPC_ADDR", "localhost:90000"},
		{"AIPAY_RPC_CALL_TIMEOUT", "0"}, {"AIPAY_RPC_MAX_MESSAGE_BYTES", "-1"},
		{"AIPAY_DATABASE_MIN_CONNS", "100"}, {"AIPAY_REDIS_URL", "http://localhost"},
		{"AIPAY_LOG_LEVEL", "unknown"}, {"AIPAY_HEALTH_TIMEOUT", "20s"},
		{"AIPAY_ENVIRONMENT", "dev"}, {"AIPAY_TLS_RELOAD_INTERVAL", "0s"},
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
}
