package config

import (
	"maps"
	"testing"
)

func TestTransportConfiguration(t *testing.T) {
	base := map[string]string{"AIPAY_RPC_TRANSPORT": Plaintext, "AIPAY_RPC_TOKEN_DIR": "tokens", "AIPAY_RPC_TOKEN_JWKS_FILE": "keys", "AIPAY_RPC_TOKEN_ISSUER": "issuer", "AIPAY_RPC_SERVICE_NAMESPACES": "iam=kaivo-business,ledger=kaivo-ledger", "AIPAY_RPC_ALLOWED_PEERS": "ledger", "AIPAY_DATABASE_URL": "postgres://localhost/test"}
	load := func(env map[string]string) (Config, error) {
		return Load("iam", "localhost:9101", func(k string) string { return env[k] })
	}
	cfg, err := load(base)
	if err != nil || cfg.Transport.ServiceNamespaces["iam"] != "kaivo-business" || cfg.TLS.CertFile != "" {
		t.Fatal("plaintext config", err)
	}
	for _, tc := range []struct{ key, value string }{
		{"AIPAY_RPC_TRANSPORT", "typo"}, {"AIPAY_TLS_CA_FILE", "ca"}, {"AIPAY_RPC_TOKEN_DIR", ""}, {"AIPAY_RPC_TOKEN_JWKS_FILE", ""}, {"AIPAY_RPC_TOKEN_ISSUER", ""}, {"AIPAY_RPC_SERVICE_NAMESPACES", ""},
		{"AIPAY_RPC_SERVICE_NAMESPACES", "iam=ns,iam=other"}, {"AIPAY_RPC_SERVICE_NAMESPACES", "iam=-bad"}, {"AIPAY_RPC_SERVICE_NAMESPACES", "iam=ns,garbage"},
	} {
		env := maps.Clone(base)
		env[tc.key] = tc.value
		if _, err := load(env); err == nil {
			t.Fatal("accepted", tc.key, tc.value)
		}
	}
	tls := map[string]string{"AIPAY_TLS_CA_FILE": "ca", "AIPAY_TLS_CERT_FILE": "cert", "AIPAY_TLS_KEY_FILE": "key"}
	for _, key := range []string{"AIPAY_RPC_TOKEN_DIR", "AIPAY_RPC_TOKEN_JWKS_FILE", "AIPAY_RPC_TOKEN_ISSUER", "AIPAY_RPC_SERVICE_NAMESPACES"} {
		env := maps.Clone(tls)
		env[key] = base[key]
		get := func(k string) string { return env[k] }
		if _, _, err := LoadClientTransport(get); err == nil {
			t.Fatal("mixed client transport accepted", key)
		}
		if _, err := LoadProbe("iam", "localhost:9101", get); err == nil {
			t.Fatal("mixed probe transport accepted", key)
		}
	}
	client := map[string]string{"AIPAY_RPC_TRANSPORT": Plaintext, "AIPAY_RPC_TOKEN_DIR": "tokens", "AIPAY_RPC_SERVICE_NAMESPACES": "backend=business"}
	if _, _, err := LoadClientTransport(func(k string) string { return client[k] }); err != nil {
		t.Fatal(err)
	}
	get := func(k string) string {
		if k == "AIPAY_RPC_TRANSPORT" {
			return Plaintext
		}
		return ""
	}
	if p, err := LoadProbe("iam", ":9101", get); err != nil || p.Transport != Plaintext || p.Address != "127.0.0.1:9101" {
		t.Fatal("anonymous probe", err)
	}
}
