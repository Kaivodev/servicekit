package mtls_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/devcert"
	"github.com/aipay-dev/servicekit/mtls"
)

func TestExpiredIdentityAndWrongEKU(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"iam"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	options := config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, "iam", "tls.crt"), KeyFile: filepath.Join(dir, "iam", "tls.key"), TrustDomain: "aipay.test"}
	if _, err := mtls.Load(options, "ledger"); err == nil {
		t.Fatal("wrong local identity accepted")
	}
	ca, err := tls.LoadX509KeyPair(options.CAFile, filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	write := func() {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &pair.PrivateKey.(*ecdsa.PrivateKey).PublicKey, ca.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(options.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	leaf.NotBefore = time.Now().Add(-2 * time.Hour)
	leaf.NotAfter = time.Now().Add(-time.Hour)
	write()
	if _, err = mtls.Load(options, "iam"); err == nil {
		t.Fatal("expired certificate accepted")
	}
	leaf.NotAfter = time.Now().Add(time.Hour)
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	write()
	material, err := mtls.Load(options, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = material.Server([]string{"backend"}); err == nil {
		t.Fatal("client-only certificate accepted for server")
	}
	if _, err = material.Client("iam", "iam"); err != nil {
		t.Fatal(err)
	}
	options.KeyFile = filepath.Join(dir, "missing.key")
	if _, err = mtls.Load(options, "iam"); err == nil {
		t.Fatal("missing private key accepted")
	}
}

func TestReloadKeepsKeyUsages(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"iam"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	options := config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, "iam", "tls.crt"), KeyFile: filepath.Join(dir, "iam", "tls.key"), TrustDomain: "aipay.test"}
	material, err := mtls.Load(options, "iam")
	if err != nil {
		t.Fatal(err)
	}
	server, err := material.Server([]string{"backend"})
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := tls.LoadX509KeyPair(options.CAFile, filepath.Join(dir, "ca.key"))
	parent, _ := x509.ParseCertificate(ca.Certificate[0])
	pair, _ := tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &pair.PrivateKey.(*ecdsa.PrivateKey).PublicKey, ca.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(options.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = material.Reload(); err == nil {
		t.Fatal("reload dropped server authentication")
	}
	// The running server keeps presenting the original certificate.
	current, err := server.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil || !bytes.Equal(current.Certificates[0].Certificate[0], pair.Certificate[0]) {
		t.Fatal("server config changed after a rejected reload")
	}
	if err = material.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}
