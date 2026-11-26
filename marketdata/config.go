package marketdata

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds request and filtering settings shared by all domains.
type Config struct {
	EgressProxy              string
	RequestTimeout           time.Duration
	MinSamples               int
	OrderMinCNY, OrderMaxCNY string
	CertifiedOnly            bool
}

// LoadConfig reads AIPAY_MARKET settings and validates the proxy and filters.
func LoadConfig(get func(string) string) (Config, error) {
	if get == nil {
		return Config{}, errors.New("market configuration requires an environment reader")
	}
	read := func(key, fallback string) string {
		if s := get("AIPAY_MARKET_" + key); s != "" {
			return s
		}
		return fallback
	}
	cfg := Config{EgressProxy: read("EGRESS_PROXY", ""), OrderMinCNY: read("ORDER_MIN_CNY", "100"), OrderMaxCNY: read("ORDER_MAX_CNY", "50000")}
	var err error
	if cfg.RequestTimeout, err = time.ParseDuration(read("REQUEST_TIMEOUT", "10s")); err != nil {
		return Config{}, errors.New("invalid AIPAY_MARKET_REQUEST_TIMEOUT")
	}
	if cfg.MinSamples, err = strconv.Atoi(read("MIN_SAMPLES", "5")); err != nil {
		return Config{}, errors.New("invalid AIPAY_MARKET_MIN_SAMPLES")
	}
	switch read("CERTIFIED_ONLY", "true") {
	case "true":
		cfg.CertifiedOnly = true
	case "false":
	default:
		return Config{}, errors.New("invalid AIPAY_MARKET_CERTIFIED_ONLY")
	}
	if _, err := cfg.settings(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type settings struct {
	timeout            time.Duration
	proxy              *url.URL
	minOrder, maxOrder *big.Rat
	minSamples         int
	certifiedOnly      bool
}

var canonicalDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,11})(\.[0-9]{0,9}[1-9])?$`)

func (cfg Config) settings() (settings, error) {
	proxy, err := proxyURL(cfg.EgressProxy)
	if err != nil {
		return settings{}, err
	}
	if cfg.RequestTimeout < time.Second || cfg.RequestTimeout > 30*time.Second {
		return settings{}, errors.New("AIPAY_MARKET_REQUEST_TIMEOUT must be between 1s and 30s")
	}
	if cfg.MinSamples < 1 || cfg.MinSamples > 20 {
		return settings{}, errors.New("AIPAY_MARKET_MIN_SAMPLES must be between 1 and 20")
	}
	for _, v := range []string{cfg.OrderMinCNY, cfg.OrderMaxCNY} {
		if !canonicalDecimal.MatchString(v) || v == "0" {
			return settings{}, errors.New("AIPAY_MARKET_ORDER_MIN_CNY and ORDER_MAX_CNY require canonical positive decimals")
		}
	}
	lo, _ := new(big.Rat).SetString(cfg.OrderMinCNY)
	hi, _ := new(big.Rat).SetString(cfg.OrderMaxCNY)
	if lo.Cmp(hi) > 0 {
		return settings{}, errors.New("AIPAY_MARKET_ORDER_MIN_CNY exceeds ORDER_MAX_CNY")
	}
	return settings{timeout: cfg.RequestTimeout, proxy: proxy, minOrder: lo, maxOrder: hi, minSamples: cfg.MinSamples, certifiedOnly: cfg.CertifiedOnly}, nil
}

func proxyURL(raw string) (*url.URL, error) {
	invalid := errors.New("AIPAY_MARKET_EGRESS_PROXY requires http://host:port")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.Path != "" || strings.ContainsAny(raw, "?#") {
		return nil, invalid
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return nil, invalid
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() {
			return nil, invalid
		}
	} else if strings.Contains(host, ":") {
		return nil, invalid
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("AIPAY_MARKET_EGRESS_PROXY has invalid port on host %q", host)
	}
	return u, nil
}
