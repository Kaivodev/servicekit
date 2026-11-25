package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevelopmentLoopbackOnly(t *testing.T) {
	t.Setenv("AIPAY_ENVIRONMENT", "production")
	if err := run([]string{"serve"}); err == nil || !strings.Contains(err.Error(), "development") {
		t.Fatal(err)
	}
	t.Setenv("AIPAY_ENVIRONMENT", "development")
	for _, listen := range []string{"0.0.0.0:8545", "[::]:8545", "localhost:8545"} {
		if err := run([]string{"serve", "-listen", listen}); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatal(err)
		}
	}
}

func TestContainerListenerAndDatasetFromEnvironment(t *testing.T) {
	t.Setenv("AIPAY_ENVIRONMENT", "development")
	t.Setenv("AIPAY_DEVCHAIN_LISTEN", "0.0.0.0:8545")
	path := filepath.Join(t.TempDir(), "chain.json")
	t.Setenv("AIPAY_DEVCHAIN_DATASET", path)
	if err := os.WriteFile(path, []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"serve"}); err == nil || err.Error() != "invalid development chain dataset" {
		t.Fatal(err)
	}
}
