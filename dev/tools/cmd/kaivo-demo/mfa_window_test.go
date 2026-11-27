package main

import (
	"testing"
	"time"
)

// WebAuthn and TOTP verifications share the IAM attempt window. A window with
// budget left, or one that has expired, never waits; an expired window restarts.
func TestChargeMFASharesTheAttemptWindow(t *testing.T) {
	d := newDriver(t.TempDir(), "", ledgerCarryover)
	read := func() mfaWindow {
		var w mfaWindow
		d.read("totp-window/finance", &w)
		return w
	}
	for i := 1; i < totpBudget; i++ {
		d.chargeMFA("finance", nil)
		if w := read(); w.Count != i {
			t.Fatalf("count after %d charges = %d", i, w.Count)
		}
	}
	first := read().Start
	start := time.Now()
	d.chargeMFA("finance", nil)
	if w := read(); w.Count != totpBudget || !w.Start.Equal(first) || time.Since(start) > time.Second {
		t.Fatalf("the last charge within budget changed the window or waited: %+v", w)
	}
	d.put("totp-window/finance", mfaWindow{Start: time.Now().Add(-totpWindow - time.Second), Count: totpBudget})
	start = time.Now()
	d.awaitMFA("finance")
	d.chargeMFA("finance", nil)
	if w := read(); w.Count != 1 || time.Since(start) > time.Second {
		t.Fatalf("an expired window did not restart without waiting: %+v", w)
	}
}
