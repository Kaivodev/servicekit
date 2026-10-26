package devcert

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/mtls"
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
