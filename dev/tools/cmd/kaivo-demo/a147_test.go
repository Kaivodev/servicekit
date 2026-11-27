package main

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPaidDisputePlansBeforeSetup(t *testing.T) {
	t.Setenv("AIPAY_DEMO_TARGET", "native")
	for name, evidence := range map[string]string{
		disputePaidRelease: "payment_observed",
		disputePaidRefund:  rulingOutcomeDenied,
		disputePaidRace:    "ledger-matches pause",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			out := filepath.Join(root, "plan.json")
			if err := execute([]string{root, "", "run", name, "-o", out}); err == nil {
				t.Fatal("ran without a native gateway")
			}
			var plan report
			decode(file(out), &plan)
			if (plan.RefundFlow == "manual") != (name == disputePaidRefund) {
				t.Fatalf("unexpected refund flow %q", plan.RefundFlow)
			}
			if plan.Scenario != name || !isDisputePaidScenario(name) || len(plan.Checks) < 4 ||
				!strings.Contains(strings.Join(append(plan.Checks, plan.SourceNotes...), " "), evidence) {
				t.Fatal("missing scenario plan or source notes")
			}
		})
	}
	if isDisputePaidScenario(disputeReturnPaid) {
		t.Fatal("classified a paid-at-registration dispute as A147")
	}
	expectFailure(t, func() { disputePaidPlan("unknown") })
}

func TestCredentialOnlyApprovalRecords(t *testing.T) {
	checkRecord := func(a any) {
		checkRenderedApprovals(object{"approvals": []any{object{"assertion": a}}})
	}
	checkRecord(object{"credential_id": "credential"})
	for _, field := range []string{"authenticator_data", "client_data_json", "signature", "user_handle", "unexpected"} {
		t.Run(field, func(t *testing.T) {
			for _, value := range []any{nil, "", "data"} {
				expectFailure(t, func() { checkRecord(object{"credential_id": "credential", field: value}) })
			}
		})
	}
	for _, a := range []any{nil, object{}, object{"credential_id": ""}, object{"credential_id": nil}} {
		expectFailure(t, func() { checkRecord(a) })
	}
}

func TestDisputePaymentObservation(t *testing.T) {
	for _, tc := range []struct{ state, resolution, ruling string }{
		{"fenced", "", "ruling"}, {"verified", "no_ruling", ""}, {"verified", "reconciliation_denied", "ruling"},
		{"late_payment", "ledger_cancelled", "ruling"},
	} {
		t.Run(tc.state+tc.resolution, func(t *testing.T) {
			row := object{"state": tc.state, "notifications": 0, "paid_events": 0}
			if tc.ruling != "" {
				row["fence_ruling_id"] = tc.ruling
			}
			if tc.resolution != "" {
				row["resolution"], row["resolved_at"] = tc.resolution, "resolved"
			}
			if tc.state == "verified" {
				row["paid_verified_at"], row["notifications"], row["paid_events"] = "verified", 1, 1
			}
			if tc.state == "late_payment" {
				row["late_payment_id"] = "late"
			}
			verify := func(row object) { checkDisputeObservation(normalized(row), tc.state, tc.resolution, tc.ruling) }
			verify(row)
			bad := object{"fence_ruling_id": "another", "resolution": "wrong", "state": "wrong", "notifications": 2, "paid_events": 2}
			for _, key := range []string{"paid_verified_at", "resolved_at", "late_payment_id"} {
				if row[key] == nil {
					bad[key] = "unexpected"
				} else {
					bad[key] = nil
				}
			}
			for key, value := range bad {
				t.Run(key, func(t *testing.T) {
					changed := maps.Clone(row)
					changed[key] = value
					expectFailure(t, func() { verify(changed) })
				})
			}
		})
	}
}

func TestVerifiedDisputeViews(t *testing.T) {
	at, later := "2026-11-27T07:00:00Z", "2026-11-27T07:00:01Z"
	row := object{"state": "verified", "resolution": "reconciliation_denied", "digest": strings.Repeat("00", 32), "upstream_order_id": "up",
		"observed_at": at, "resolved_at": later}
	review := object{"stage": "lapsed", "review_reason": "payment_observed", "reviewed_at": at, "review_recorded_at": later}
	p := maps.Clone(row)
	delete(p, "digest")
	p["query_evidence_sha256"] = b64.EncodeToString(make([]byte, 32))
	p["observed_at"] = "2026-11-27T07:00:00.000000Z"
	platform := object{"payment_observation": p}
	seller := object{"payment_state": "verified"}
	verify := func() { checkDisputeViews(platform, seller, row, review) }
	verify()
	for _, key := range []string{"payment_observation", "ruling_review", "query_evidence_sha256", "upstream_order_id", "resolved_at"} {
		seller[key] = nil
		expectFailure(t, verify)
		delete(seller, key)
	}
	for _, field := range []string{"state", "resolution", "late_payment_id", "upstream_order_id", "query_evidence_sha256", "observed_at", "resolved_at"} {
		saved := p[field]
		p[field] = "wrong"
		expectFailure(t, verify)
		p[field] = saved
	}
	// The reviewed ruling has lapsed, so the platform view must not show a review.
	platform["ruling_review"] = object{"disposition": "denied"}
	expectFailure(t, verify)
	delete(platform, "ruling_review")
	review["stage"] = "approved"
	expectFailure(t, verify)
	review["stage"] = "lapsed"
	p["resolution"] = "no_ruling"
	expectFailure(t, verify)
}

type matchesTestEnvironment struct {
	demoEnvironment
	commands    []string
	failOnPause bool
}

func (e *matchesTestEnvironment) stack(args ...string) []byte {
	e.commands = append(e.commands, strings.Join(args, " "))
	if e.failOnPause && args[1] == "pause" {
		stop("partial pause")
	}
	return nil
}

func TestMatchesReaderCleanup(t *testing.T) {
	for _, failureAt := range []string{"none", "pause", "work"} {
		t.Run(failureAt, func(t *testing.T) {
			env := &matchesTestEnvironment{failOnPause: failureAt == "pause"}
			d := driver{demoEnvironment: env}
			run := func() {
				d.withPausedMatches(func() {
					env.commands = append(env.commands, "inspect")
					if failureAt == "work" {
						stop("failed observation")
					}
				})
			}
			if failureAt == "none" {
				run()
			} else {
				expectFailure(t, run)
			}
			want := []string{"ledger-matches pause", "inspect", "ledger-matches resume"}
			if failureAt == "pause" {
				want = []string{want[0], want[2]}
			}
			if !slices.Equal(env.commands, want) {
				t.Fatal(env.commands)
			}
		})
	}
	requireLiveCancellation(time.Now().Add(time.Minute))
	expectFailure(t, func() { requireLiveCancellation(time.Now().Add(-time.Second)) })
}
