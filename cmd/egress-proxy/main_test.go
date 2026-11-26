package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestEnvironmentGate(t *testing.T) {
	for _, env := range []string{"", "production", "test", "staging", "unknown", "development"} {
		get := func(k string) string {
			return map[string]string{"AIPAY_ENVIRONMENT": env, "AIPAY_EGRESS_PROXY_TEST_ONLY_ALLOW_CIDRS": "198.18.0.0/15, 127.0.0.0/8", "AIPAY_EGRESS_PROXY_ALLOWED_HOSTS": "one.test, two.test"}[k]
		}
		addr, cfg, err := settings(get)
		if env == "development" {
			if err != nil || addr != ":3128" || cfg.MaxConnections != 64 || len(cfg.AllowCIDRs) != 2 || len(cfg.AllowedHosts) != 2 || cfg.AllowedHosts[1] != "two.test" {
				t.Fatal(cfg, err)
			}
		} else if err == nil {
			t.Fatal("accepted TEST_ONLY CIDRs in", env)
		} else if !strings.Contains(err.Error(), "AIPAY_EGRESS_PROXY_TEST_ONLY_ALLOW_CIDRS requires") {
			t.Fatal(err)
		}
	}
}

func TestCommand(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	get := func(string) string { return "" }
	if err := run(t.Context(), []string{"version"}, get, &out, log); err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v["service"] != "egress-proxy" || v["version"] == "" {
		t.Fatal(v, err)
	}
	for _, args := range [][]string{nil, {"serve"}, {"version", "extra"}, {"unknown"}} {
		if err := run(t.Context(), args, get, &out, log); err == nil {
			t.Fatal(args)
		}
	}
	for k, values := range map[string][]string{"MAX_CONNECTIONS": {"0", "1025", "x"}, "TEST_ONLY_ALLOW_CIDRS": {"127.0.0.1", "bad/99"}} {
		for _, value := range values {
			_, _, err := settings(func(name string) string {
				return map[string]string{"AIPAY_ENVIRONMENT": "development", "AIPAY_EGRESS_PROXY_ALLOWED_HOSTS": "test", "AIPAY_EGRESS_PROXY_" + k: value}[name]
			})
			if err == nil {
				t.Fatal("accepted", k, value)
			}
		}
	}
}
