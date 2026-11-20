package main

import (
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
