// Package mtls verifies certificate chains, hostnames and explicit service URI
// identities, and reloads short-lived certificates without a restart.
package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Material holds the current certificate, key and trust bundle. Reload swaps
// them atomically; every new TLS handshake uses the latest accepted files,
// while established connections keep the identity they were opened with.
type Material struct {
	options  config.TLS
	domain   string
	service  string
	current  atomic.Pointer[bundle]
	reloadMu sync.Mutex
}

type bundle struct {
	certificate   tls.Certificate
	roots         *x509.CertPool
	intermediates *x509.CertPool
	serverAuth    bool
	clientAuth    bool
	fingerprint   [32]byte
}

func Load(options config.TLS, service string) (*Material, error) {
	if err := config.ValidateTLS(options); err != nil {
		return nil, err
	}
	if !config.ValidService(service) {
		return nil, errors.New("invalid local service identity")
	}
	m := &Material{options: options, domain: options.TrustDomain, service: service}
	files, fingerprint, err := m.readFiles()
	if err != nil {
		return nil, err
	}
	current, err := m.parse(files, fingerprint)
	if err != nil {
		return nil, err
	}
	m.current.Store(current)
	return m, nil
}

func (m *Material) readFiles() ([3][]byte, [32]byte, error) {
	var files [3][]byte
	var err error
	for i, path := range []string{m.options.CAFile, m.options.CertFile, m.options.KeyFile} {
		if files[i], err = os.ReadFile(path); err != nil {
			return files, [32]byte{}, errors.New("read TLS trust bundle, certificate or private key failed")
		}
	}
	h := sha256.New()
	for _, file := range files {
		digest := sha256.Sum256(file)
		h.Write(digest[:])
	}
	var fingerprint [32]byte
	copy(fingerprint[:], h.Sum(nil))
	return files, fingerprint, nil
}

func (m *Material) parse(files [3][]byte, fingerprint [32]byte) (*bundle, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(files[0]) {
		return nil, errors.New("TLS trust bundle contains no certificates")
	}
	certificate, err := tls.X509KeyPair(files[1], files[2])
	if err != nil {
		return nil, errors.New("load TLS certificate and private key failed")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid local TLS certificate")
	}
	certificate.Leaf = leaf
	identity, err := certificateIdentity(leaf, m.domain)
	if err != nil || identity != m.service {
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
	b := &bundle{certificate: certificate, roots: roots, intermediates: intermediates, fingerprint: fingerprint}
	if !b.valid(x509.ExtKeyUsageAny) {
		return nil, errors.New("local TLS certificate is not currently trusted")
	}
	b.serverAuth, b.clientAuth = b.valid(x509.ExtKeyUsageServerAuth), b.valid(x509.ExtKeyUsageClientAuth)
	return b, nil
}

func (b *bundle) valid(usage x509.ExtKeyUsage) bool {
	_, err := b.certificate.Leaf.Verify(x509.VerifyOptions{Roots: b.roots, Intermediates: b.intermediates, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: time.Now()})
	return err == nil
}

// Reload re-reads the files and swaps in the new material when it changed and
// is valid: same service identity, a trusted chain, and every key usage the
// current certificate has. On error the current material stays in use.
func (m *Material) Reload() (bool, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	files, fingerprint, err := m.readFiles()
	if err != nil {
		return false, err
	}
	current := m.current.Load()
	if fingerprint == current.fingerprint {
		return false, nil
	}
	next, err := m.parse(files, fingerprint)
	if err != nil {
		return false, err
	}
	if (current.serverAuth && !next.serverAuth) || (current.clientAuth && !next.clientAuth) {
		return false, errors.New("reloaded TLS certificate lacks a key usage of the current certificate")
	}
	m.current.Store(next)
	return true, nil
}

// Watch reloads every interval until ctx ends. Failures are logged and retried;
// they never replace working material with a partial or invalid update.
func (m *Material) Watch(ctx context.Context, interval time.Duration, log *slog.Logger) {
	if interval <= 0 || log == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, err := m.Reload()
		if err != nil {
			log.WarnContext(ctx, "tls material reload failed; keeping current certificate", "error", err.Error())
		} else if changed {
			log.InfoContext(ctx, "tls material reloaded", "not_after", m.NotAfter().Format(time.RFC3339))
		}
	}
}

// NotAfter is the expiry of the current local certificate.
func (m *Material) NotAfter() time.Time { return m.current.Load().certificate.Leaf.NotAfter }

// Check fails once the current certificate has expired, e.g. because reloads
// kept failing; services add it to their readiness checks.
func (m *Material) Check(context.Context) error {
	if !m.current.Load().valid(x509.ExtKeyUsageAny) {
		return errors.New("local TLS certificate is no longer valid")
	}
	return nil
}

// Server requires a client certificate and checks the verified URI identity at
// handshake time. RPC interceptors still apply service/method authorization.
// Each handshake uses the material current at that moment.
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
	build := func() *tls.Config {
		current := m.current.Load()
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{current.certificate}, ClientCAs: current.roots, ClientAuth: tls.RequireAndVerifyClientCert,
			VerifyConnection: func(state tls.ConnectionState) error {
				name, err := verifiedIdentity(state, m.domain)
				if err != nil || !peers[name] {
					return errors.New("untrusted service identity")
				}
				return nil
			}}
	}
	cfg := build()
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return build(), nil }
	return cfg, nil
}

// Client preserves standard DNS and certificate-chain verification, then also
// binds the connection to the expected service URI. InsecureSkipVerify is never
// enabled. The returned config is a snapshot of the current material; use
// ClientCredentials for connections that must follow reloads.
func (m *Material) Client(serverName, expectedService string) (*tls.Config, error) {
	if err := m.verifyUsage(x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	if strings.TrimSpace(serverName) == "" || !config.ValidService(expectedService) {
		return nil, errors.New("client TLS requires a server name and expected service")
	}
	current := m.current.Load()
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: current.roots, Certificates: []tls.Certificate{current.certificate}, ServerName: serverName,
		VerifyConnection: func(state tls.ConnectionState) error {
			name, err := verifiedIdentity(state, m.domain)
			if err != nil || name != expectedService {
				return errors.New("unexpected server identity")
			}
			return nil
		}}, nil
}

// ClientCredentials builds a fresh Client config for every handshake, so
// reconnects pick up reloaded certificates and trust bundles.
func (m *Material) ClientCredentials(serverName, expectedService string) (credentials.TransportCredentials, error) {
	snapshot, err := m.Client(serverName, expectedService)
	if err != nil {
		return nil, err
	}
	return &clientCredentials{material: m, serverName: serverName, expected: expectedService, info: credentials.NewTLS(snapshot).Info()}, nil
}

type clientCredentials struct {
	material   *Material
	serverName string
	expected   string
	info       credentials.ProtocolInfo
}

func (c *clientCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cfg, err := c.material.Client(c.serverName, c.expected)
	if err != nil {
		return nil, nil, err
	}
	return credentials.NewTLS(cfg).ClientHandshake(ctx, authority, raw)
}

func (c *clientCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("client credentials cannot accept connections")
}

func (c *clientCredentials) Info() credentials.ProtocolInfo { return c.info }

func (c *clientCredentials) Clone() credentials.TransportCredentials {
	clone := *c
	return &clone
}

// OverrideServerName is required by the interface; the server name is fixed
// at construction.
func (c *clientCredentials) OverrideServerName(string) error {
	return errors.New("server name override is not supported")
}

func (m *Material) verifyUsage(usage x509.ExtKeyUsage) error {
	if m == nil || m.current.Load() == nil {
		return errors.New("TLS material is unavailable")
	}
	if !m.current.Load().valid(usage) {
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
