package devcert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/mtls"
)

func TestGeneratedCertificatesAndNoOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certificates")
	if err := Generate(dir, "aipay.test", []string{"iam", "backend"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	options := config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, "iam/tls.crt"), KeyFile: filepath.Join(dir, "iam/tls.key"), TrustDomain: "aipay.test"}
	if _, err := mtls.Load(options, "iam"); err != nil {
		t.Fatal(err)
	}
	ca, leaf := readCertificate(t, options.CAFile), readCertificate(t, options.CertFile)
	if len(ca.SubjectKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Fatal("leaf certificate lacks the CA authority key identifier")
	}
	info, err := os.Stat(options.KeyFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions are not 0600")
	}
	before, _ := os.ReadFile(options.KeyFile)
	if err := Generate(dir, "aipay.test", []string{"iam"}, time.Hour); err == nil {
		t.Fatal("existing directory overwritten")
	}
	after, _ := os.ReadFile(options.KeyFile)
	if string(before) != string(after) {
		t.Fatal("existing key changed")
	}
	if _, err := mtls.Load(options, "ledger"); err == nil {
		t.Fatal("wrong service identity accepted")
	}
	options.TrustDomain = "other.test"
	if _, err := mtls.Load(options, "iam"); err == nil {
		t.Fatal("wrong trust domain accepted")
	}
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
