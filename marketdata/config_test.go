package marketdata

import (
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := LoadConfig(func(k string) string {
		if k == "AIPAY_MARKET_EGRESS_PROXY" {
			return "http://localhost:3128"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLoadConfig(t *testing.T) {
	defaults := testConfig(t)
	if defaults.RequestTimeout != 10*time.Second || defaults.MinSamples != 5 || defaults.OrderMinCNY != "100" || defaults.OrderMaxCNY != "50000" || !defaults.CertifiedOnly {
		t.Fatalf("%+v", defaults)
	}
	for k, values := range map[string][]string{
		"EGRESS_PROXY":    {"", "https://proxy:3128", "http://name:secret@proxy:3128", "http://proxy:3128/secret", "http://proxy:3128?secret", "http://proxy:3128?", "http://proxy:3128#", "http://proxy", "http://:3128", "http://proxy:65536", "http://proxy:0", "http://[broken]:3128", "http://proxy:xyz"},
		"REQUEST_TIMEOUT": {"0", "500ms", "31s", "invalid"},
		"MIN_SAMPLES":     {"0", "21", "5.0"},
		"ORDER_MIN_CNY":   {"-1", "0", "0100", "1.0", "100000", "1234567890123"},
		"ORDER_MAX_CNY":   {"1e3", "99", "100.00000000001"},
		"CERTIFIED_ONLY":  {"TRUE", "1", "yes"},
	} {
		for _, value := range values {
			_, err := LoadConfig(func(name string) string {
				if name == "AIPAY_MARKET_"+k {
					return value
				}
				if name == "AIPAY_MARKET_EGRESS_PROXY" {
					return defaults.EgressProxy
				}
				return ""
			})
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("%s unexpectedly accepted or disclosed", k)
			}
		}
	}
	for _, proxy := range []string{"http://[::1]:3128", "http://a.b:1"} {
		cfg, err := LoadConfig(func(k string) string {
			return map[string]string{"AIPAY_MARKET_EGRESS_PROXY": proxy, "AIPAY_MARKET_CERTIFIED_ONLY": "false", "AIPAY_MARKET_ORDER_MIN_CNY": "0.1", "AIPAY_MARKET_MIN_SAMPLES": "20", "AIPAY_MARKET_REQUEST_TIMEOUT": "30s"}[k]
		})
		if err != nil || cfg.CertifiedOnly || cfg.MinSamples != 20 {
			t.Fatal(cfg, err)
		}
	}
}

func TestInvalidSchedules(t *testing.T) {
	for _, s := range []Schedule{
		{}, {Sources: []Source{"other"}, Every: time.Minute},
		{Sources: []Source{OKX, OKX}, Every: time.Minute},
		{Sources: []Source{Kraken}, Every: time.Minute},
		{Sources: []Source{OKX}, Every: 5 * time.Minute},
		{Sources: []Source{OKX}, Every: time.Minute, Pair: [2]Source{OKX, Binance}},
		{Sources: []Source{OKX, Binance}, Every: time.Minute, Pair: [2]Source{Binance, OKX}},
		{Sources: []Source{OKX}, Every: time.Minute, MaxDeviation: "0.01"},
		{Sources: []Source{OKX, Binance}, Every: time.Minute, Pair: [2]Source{OKX, Binance}, MaxDeviation: "-1"},
	} {
		if _, err := s.validate(); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
}
