// Package devcert creates disposable local-development certificates. Production
// credentials must be issued and rotated by the deployment's certificate authority.
package devcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/aipay-dev/servicekit/config"
)

// Generate refuses to overwrite an existing directory, including a symlink.
func Generate(directory, domain string, services []string, validFor time.Duration) (err error) {
	if directory == "" || !config.ValidTrustDomain(domain) || validFor <= 0 || validFor > 30*24*time.Hour || len(services) == 0 {
		return errors.New("invalid development certificate options")
	}
	seen := map[string]bool{}
	for _, service := range services {
		if !config.ValidService(service) || seen[service] {
			return errors.New("development certificates require unique service names")
		}
		seen[service] = true
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return errors.New("create new development certificate directory failed; it must not already exist")
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(directory)
		}
	}()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	serial, err := serialNumber()
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "AI Pay local development CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(validFor), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePair(directory, "ca", caDER, caKey); err != nil {
		return err
	}
	for _, service := range services {
		dir := filepath.Join(directory, service)
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		serial, err := serialNumber()
		if err != nil {
			return err
		}
		identity := &url.URL{Scheme: "spiffe", Host: domain, Path: "/service/" + service}
		leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: service}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(validFor), BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames: []string{service, service + "." + domain, "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, URIs: []*url.URL{identity}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err := writePair(dir, "tls", der, key); err != nil {
			return err
		}
	}
	return nil
}

func serialNumber() (*big.Int, error) {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err == nil && value.Sign() == 0 {
		value.SetInt64(1)
	}
	return value, err
}

func writePair(dir, name string, certificate []byte, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
}
