package main

import (
	"strings"
	"testing"
)

func TestGuardBeforeOpeningResources(t *testing.T) {
	for _, pair := range [][2]string{{"", "31337"}, {"production", "31337"}, {"development", "56"}} {
		t.Setenv("AIPAY_ENVIRONMENT", pair[0])
		t.Setenv("AIPAY_DEVCOLLECTION_CHAIN_ID", pair[1])
		if err := run(t.Context(), []string{"serve"}); err == nil || !strings.Contains(err.Error(), "31337") {
			t.Fatal(err)
		}
	}
}
