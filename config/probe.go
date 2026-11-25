package config

import (
	"errors"
	"net"
	"strings"
	"time"
)

// Probe settings intentionally require neither database nor Redis credentials.
type Probe struct {
	Transport  string
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
	transport, tls, err := transportSettings(get)
	if err != nil {
		return Probe{}, err
	}
	p := Probe{Transport: transport.Mode, TLS: tls, Address: value("GRPC_TARGET", value("GRPC_ADDR", defaultAddress)), ServerName: value("GRPC_SERVER_NAME", service)}
	p.Timeout, err = time.ParseDuration(value("HEALTH_TIMEOUT", "2s"))
	if err != nil || p.Timeout <= 0 {
		return Probe{}, errors.New("invalid healthcheck timeout")
	}
	// A kubelet or standalone probe needs only the plaintext address.
	if transport.Mode == Plaintext {
		if tls.CAFile != "" || tls.CertFile != "" || tls.KeyFile != "" || tls.TrustDomain != "" {
			return Probe{}, errors.New("TLS settings conflict with plaintext probe")
		}
	} else if err := transport.Validate(tls, false); err != nil {
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
