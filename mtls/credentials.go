// Package mtls verifies certificate chains, hostnames and explicit service URI identities.
package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/aipay-dev/servicekit/config"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Material struct {
	certificate   tls.Certificate
	roots         *x509.CertPool
	domain        string
	service       string
	intermediates *x509.CertPool
}

func Load(options config.TLS, service string) (*Material, error) {
	if err := config.ValidateTLS(options); err != nil {
		return nil, err
	}
	if !config.ValidService(service) {
		return nil, errors.New("invalid local service identity")
	}
	ca, err := os.ReadFile(options.CAFile)
	if err != nil {
		return nil, errors.New("read TLS trust bundle failed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("TLS trust bundle contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
	if err != nil {
		return nil, errors.New("load TLS certificate and private key failed")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid local TLS certificate")
	}
	certificate.Leaf = leaf
	identity, err := certificateIdentity(leaf, options.TrustDomain)
	if err != nil || identity != service {
		return nil, errors.New("local TLS certificate does not match service identity")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("invalid local TLS intermediate certificate")
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: time.Now()}); err != nil {
		return nil, errors.New("local TLS certificate is not currently trusted")
	}
	return &Material{certificate: certificate, roots: roots, domain: options.TrustDomain, service: service, intermediates: intermediates}, nil
}

// Server requires a client certificate and checks the verified URI identity at
// handshake time. RPC interceptors still apply service/method authorization.
func (m *Material) Server(allowed []string) (*tls.Config, error) {
	if err := m.verifyUsage(x509.ExtKeyUsageServerAuth); err != nil {
		return nil, err
	}
	peers := map[string]bool{}
	for _, service := range allowed {
		if !config.ValidService(service) || peers[service] {
			return nil, errors.New("invalid or duplicate allowed TLS peer")
		}
		peers[service] = true
	}
	if len(peers) == 0 {
		return nil, errors.New("TLS server requires an explicit peer allowlist")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{m.certificate}, ClientCAs: m.roots, ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			name, err := verifiedIdentity(state, m.domain)
			if err != nil || !peers[name] {
				return errors.New("untrusted service identity")
			}
			return nil
		}}, nil
}

// Client preserves standard DNS and certificate-chain verification, then also
// binds the connection to the expected service URI. InsecureSkipVerify is never enabled.
func (m *Material) Client(serverName, expectedService string) (*tls.Config, error) {
	if err := m.verifyUsage(x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	if strings.TrimSpace(serverName) == "" || !config.ValidService(expectedService) {
		return nil, errors.New("client TLS requires a server name and expected service")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: m.roots, Certificates: []tls.Certificate{m.certificate}, ServerName: serverName,
		VerifyConnection: func(state tls.ConnectionState) error {
			name, err := verifiedIdentity(state, m.domain)
			if err != nil || name != expectedService {
				return errors.New("unexpected server identity")
			}
			return nil
		}}, nil
}

func (m *Material) verifyUsage(usage x509.ExtKeyUsage) error {
	if m == nil || m.certificate.Leaf == nil || m.roots == nil {
		return errors.New("TLS material is unavailable")
	}
	_, err := m.certificate.Leaf.Verify(x509.VerifyOptions{Roots: m.roots, Intermediates: m.intermediates, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: time.Now()})
	if err != nil {
		return errors.New("local TLS certificate is not valid for the required authentication role")
	}
	return nil
}

// Peer returns an identity only from the verified TLS transport, never metadata.
func (m *Material) Peer(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("missing authenticated transport")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errors.New("transport is not TLS")
	}
	return verifiedIdentity(info.State, m.domain)
}

func verifiedIdentity(state tls.ConnectionState, domain string) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", errors.New("unverified certificate chain")
	}
	return certificateIdentity(state.PeerCertificates[0], domain)
}

func certificateIdentity(cert *x509.Certificate, domain string) (string, error) {
	// One URI avoids ambiguous principals even when the same CA issued the leaf.
	if len(cert.URIs) != 1 {
		return "", errors.New("certificate requires exactly one service URI")
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" || u.Host != domain || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/service/") {
		return "", errors.New("invalid certificate service URI")
	}
	service := strings.TrimPrefix(u.Path, "/service/")
	if !config.ValidService(service) {
		return "", errors.New("invalid certificate service name")
	}
	return service, nil
}
