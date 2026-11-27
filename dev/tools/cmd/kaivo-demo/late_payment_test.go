package main

import (
	"strings"
	"testing"
	"time"
)

func TestLatePaymentTiming(t *testing.T) {
	observed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		name, configured, source string
		pinned                   any
		window, margin           time.Duration
	}{
		{"approved window", "5s", "pinned", "60", time.Minute, 10 * time.Second},
		{"pin overrides invalid configuration", "invalid", "pinned", "3600", time.Hour, 10 * time.Second},
		{"native configuration", "5s", "configured", nil, 5 * time.Second, 2500 * time.Millisecond},
		{"fractional duration", "750ms", "configured", nil, 750 * time.Millisecond, 375 * time.Millisecond},
		{"default", "", "default", nil, 30 * time.Minute, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			timing, err := lateWindowTiming(observed, tc.pinned, tc.configured)
			if err != nil {
				t.Fatal(err)
			}
			deadline := observed.Add(tc.window - tc.margin)
			if timing.window != tc.window || timing.source != tc.source || timing.margin != tc.margin || !timing.deadline.Equal(deadline) {
				t.Fatalf("unexpected timing: %+v", timing)
			}
			if got := timing.observationTimeout(); got != tc.window+time.Minute {
				t.Fatalf("observation timeout = %s", got)
			}
			if err := timing.checkDeadline(deadline.Add(-time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			for _, now := range []time.Time{deadline, deadline.Add(time.Second)} {
				err := timing.checkDeadline(now)
				if err == nil {
					t.Fatal("accepted payment at or after the deadline")
				}
				for _, want := range []string{"late-payment window already closed", observed.Format(time.RFC3339Nano), "window " + tc.window.String(), "margin " + tc.margin.String()} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q is missing %q", err, want)
					}
				}
			}
		})
	}
}

func TestLatePaymentTimingInvalid(t *testing.T) {
	for _, pinned := range []any{"", "0", "-1", "3601", "1.5", "5s"} {
		if _, err := lateWindowTiming(time.Time{}, pinned, "1m"); err == nil || !strings.Contains(err.Error(), "pinned") {
			t.Errorf("invalid pin %q: got %v", pinned, err)
		}
	}
	for _, configured := range []string{"0", "-1s", "no duration"} {
		if _, err := lateWindowTiming(time.Time{}, nil, configured); err == nil || !strings.Contains(err.Error(), lateWindowEnv) {
			t.Errorf("invalid configuration %q: got %v", configured, err)
		}
	}
}

func TestCancellationObservationWindowProjection(t *testing.T) {
	if !strings.Contains(cancellationObservations, "to_jsonb(e)->>'late_payment_window_seconds'") ||
		!strings.Contains(cancellationObservations, "FROM reconciliation_verification_evidence AS e") {
		t.Fatal("the optional pin must be read from the evidence row as JSON")
	}
}

func TestClosedUnpaidObservations(t *testing.T) {
	first := object{"outcome": "closed_unpaid", "verified_at": "2026-01-02T03:04:05Z"}
	second := object{"outcome": "closed_unpaid", "verified_at": "2026-01-02T03:05:04Z"}
	paid := object{"outcome": "paid"}
	rows := []object{first, second}
	checkUnpaidSeparation(rows, time.Minute)
	expectFailure(t, func() { checkUnpaidSeparation(rows, time.Minute+time.Nanosecond) })
	expectFailure(t, func() { checkUnpaidSeparation(rows[:1], time.Second) })
	if paidAfterFirst([]object{paid, first}) || !paidAfterFirst([]object{first, paid}) {
		t.Fatal("expected paid evidence after the first unpaid observation")
	}
	expectFailure(t, func() { paidAfterFirst([]object{first, second, paid}) })
}
