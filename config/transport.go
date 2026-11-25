package config

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	MTLS      = "mtls"
	Plaintext = "plaintext"
)

// Transport holds the service identity settings. An empty Mode selects mTLS
// for callers constructing Config directly.
type Transport struct {
	Mode              string
	TokenDir          string
	JWKSFile          string
	Issuer            string
	ServiceNamespaces map[string]string
}

var namespaceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate checks the transport selection without opening any files.
func (t Transport) Validate(tls TLS, server bool) error {
	switch t.Mode {
	case "", MTLS:
		if t.TokenDir != "" || t.JWKSFile != "" || t.Issuer != "" || len(t.ServiceNamespaces) != 0 {
			return errors.New("RPC token settings require plaintext transport")
		}
		return ValidateTLS(tls)
	case Plaintext:
		if tls.CAFile != "" || tls.CertFile != "" || tls.KeyFile != "" || tls.TrustDomain != "" {
			return errors.New("TLS settings conflict with plaintext transport")
		}
		if strings.TrimSpace(t.TokenDir) == "" || len(t.ServiceNamespaces) == 0 {
			return errors.New("plaintext transport requires a token directory and service namespaces")
		}
		if server && (strings.TrimSpace(t.JWKSFile) == "" || strings.TrimSpace(t.Issuer) == "") {
			return errors.New("plaintext server requires a token JWKS file and issuer")
		}
		for service, ns := range t.ServiceNamespaces {
			if !ValidService(service) || !namespaceName.MatchString(ns) {
				return errors.New("invalid RPC service namespace mapping")
			}
		}
		return nil
	default:
		return errors.New("AIPAY_RPC_TRANSPORT must be mtls or plaintext")
	}
}

func transportSettings(get func(string) string) (Transport, TLS, error) {
	t := Transport{Mode: get("AIPAY_RPC_TRANSPORT"), TokenDir: get("AIPAY_RPC_TOKEN_DIR"), JWKSFile: get("AIPAY_RPC_TOKEN_JWKS_FILE"), Issuer: get("AIPAY_RPC_TOKEN_ISSUER")}
	if t.Mode == "" {
		t.Mode = MTLS
	}
	if raw := get("AIPAY_RPC_SERVICE_NAMESPACES"); raw != "" {
		t.ServiceNamespaces = make(map[string]string)
		for _, entry := range strings.Split(raw, ",") {
			service, ns, ok := strings.Cut(strings.TrimSpace(entry), "=")
			if _, duplicate := t.ServiceNamespaces[service]; !ok || duplicate || !ValidService(service) || !namespaceName.MatchString(ns) {
				return Transport{}, TLS{}, errors.New("invalid AIPAY_RPC_SERVICE_NAMESPACES")
			}
			t.ServiceNamespaces[service] = ns
		}
	}
	tls := TLS{CAFile: get("AIPAY_TLS_CA_FILE"), CertFile: get("AIPAY_TLS_CERT_FILE"), KeyFile: get("AIPAY_TLS_KEY_FILE"), TrustDomain: get("AIPAY_TLS_TRUST_DOMAIN")}
	if t.Mode == MTLS && tls.TrustDomain == "" {
		tls.TrustDomain = "aipay.internal"
	}
	return t, tls, nil
}

// LoadClientTransport reads only client transport settings, without a
// database, listener, server allowlist or token verification keys.
func LoadClientTransport(get func(string) string) (Transport, TLS, error) {
	if get == nil {
		return Transport{}, TLS{}, errors.New("missing configuration reader")
	}
	t, tls, err := transportSettings(get)
	if err != nil {
		return Transport{}, TLS{}, err
	}
	tls.ReloadInterval = 30 * time.Second
	if raw := get("AIPAY_TLS_RELOAD_INTERVAL"); raw != "" {
		tls.ReloadInterval, err = time.ParseDuration(raw)
		if err != nil || tls.ReloadInterval <= 0 {
			return Transport{}, TLS{}, errors.New("AIPAY_TLS_RELOAD_INTERVAL must be a positive duration")
		}
	}
	return t, tls, t.Validate(tls, false)
}
