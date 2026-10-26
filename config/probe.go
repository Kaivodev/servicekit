package config

import (
	"errors"
	"net"
	"strings"
	"time"
)

// Probe settings intentionally require neither database nor Redis credentials.
type Probe struct {
	TLS        TLS
	Address    string
	ServerName string
	Timeout    time.Duration
}

func LoadProbe(service, defaultAddress string, get func(string) string) (Probe, error) {
	if get == nil || !ValidService(service) {
		return Probe{}, errors.New("invalid healthcheck configuration")
	}
	value := func(key, fallback string) string {
		if v := get("AIPAY_" + key); v != "" {
			return v
		}
		return fallback
	}
	p := Probe{TLS: TLS{CAFile: get("AIPAY_TLS_CA_FILE"), CertFile: get("AIPAY_TLS_CERT_FILE"), KeyFile: get("AIPAY_TLS_KEY_FILE"), TrustDomain: value("TLS_TRUST_DOMAIN", "aipay.internal")}, Address: value("GRPC_TARGET", value("GRPC_ADDR", defaultAddress)), ServerName: value("GRPC_SERVER_NAME", service)}
	var err error
	p.Timeout, err = time.ParseDuration(value("HEALTH_TIMEOUT", "2s"))
	if err != nil || p.Timeout <= 0 {
		return Probe{}, errors.New("invalid healthcheck timeout")
	}
	if err := ValidateTLS(p.TLS); err != nil {
		return Probe{}, err
	}
	if err := ValidateAddress(p.Address); err != nil {
		return Probe{}, err
	}
	if strings.TrimSpace(p.ServerName) == "" {
		return Probe{}, errors.New("healthcheck server name is required")
	}
	host, port, _ := net.SplitHostPort(p.Address)
	if host == "" || host == "0.0.0.0" || host == "::" {
		p.Address = net.JoinHostPort("127.0.0.1", port)
	}
	return p, nil
}
