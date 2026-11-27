package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	common "github.com/Kaivodev/protobuf/gen/go/aipay/common/v1"
	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	recon "github.com/Kaivodev/protobuf/gen/go/aipay/reconciliation/v1"
)

func TestDisputeReturnReportBeforeSetup(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "return.md")
	t.Setenv("AIPAY_DEMO_TARGET", "native")
	if err := execute([]string{root, "", "run", disputeReturn, "-o", out}); err == nil {
		t.Fatal("ran without the native gateway")
	}
	report := string(file(out))
	for _, fact := range []string{disputeReturn, rulingOutcomeDenied, "reconciliation_authorizations.payload", "merchant V2 query status 0"} {
		if !strings.Contains(report, fact) {
			t.Errorf("report is missing %q", fact)
		}
	}
}

func TestDisputeRulingRefusal(t *testing.T) {
	const path = "/disputes/dispute/rulings"
	f := failure{method: "POST", path: path, httpStatus: 200, businessCode: 409, message: rulingOutcomeDenied}
	call := func() { requireRefusedWrite(path, 409, rulingOutcomeDenied, func() { panic(f) }) }
	call()
	f.httpStatus = 409
	expectFailure(t, call)
	f.httpStatus, f.message = 200, "DISPUTE_RULING_ACTIVE"
	expectFailure(t, call)
	f.message = ""
	expectFailure(t, call)
	expectFailure(t, func() { requireRefusedWrite(path, 409, rulingOutcomeDenied, func() {}) })
}

func TestReturnAuthorizationBindsApprovedRuling(t *testing.T) {
	newEvent := func() *recon.TradeCancellationAuthorized {
		return &recon.TradeCancellationAuthorized{AuthorizationId: "auth", Trade: &common.TradeSnapshot{OrderId: "order"},
			DisputeResolution: &recon.DisputeResolution{DisputeId: "dispute", RulingId: "ruling"}}
	}
	check := func(event *recon.TradeCancellationAuthorized) {
		checkReturnAuthorization(event, "auth", "order", "dispute", "ruling")
	}
	check(newEvent())
	for name, change := range map[string]func(*recon.TradeCancellationAuthorized){
		"authorization": func(e *recon.TradeCancellationAuthorized) { e.AuthorizationId = "another" },
		"order":         func(e *recon.TradeCancellationAuthorized) { e.Trade.OrderId = "another" },
		"no resolution": func(e *recon.TradeCancellationAuthorized) { e.DisputeResolution = nil },
		"dispute":       func(e *recon.TradeCancellationAuthorized) { e.DisputeResolution.DisputeId = "another" },
		"ruling":        func(e *recon.TradeCancellationAuthorized) { e.DisputeResolution.RulingId = "another" },
	} {
		t.Run(name, func(t *testing.T) {
			event := newEvent()
			change(event)
			expectFailure(t, func() { check(event) })
		})
	}
}

func TestPreReleasePaymentFact(t *testing.T) {
	for _, tc := range []struct {
		status pay.OrderStatus
		paid   bool
	}{
		{pay.OrderStatus_ORDER_STATUS_AWAITING_PAYMENT, false},
		{pay.OrderStatus_ORDER_STATUS_UNKNOWN, false},
		{pay.OrderStatus_ORDER_STATUS_RISK_HELD, true},
	} {
		t.Run(tc.status.String(), func(t *testing.T) {
			row := normalized(object{"released": false, "paid": tc.paid, "original_status": tc.status})
			checkPreReleasePaymentFact(row, tc.paid)
			expectFailure(t, func() { checkPreReleasePaymentFact(row, !tc.paid) })
			row["paid"] = !tc.paid
			expectFailure(t, func() { checkPreReleasePaymentFact(row, !tc.paid) })
			row["released"], row["paid"] = true, tc.paid
			expectFailure(t, func() { checkPreReleasePaymentFact(row, tc.paid) })
		})
	}
}

func TestReturnObservationsUseCitedPairAndFullPin(t *testing.T) {
	first := object{"id": "first", "outcome": "closed_unpaid", "late_payment_window_seconds": "60", "verified_at": "2026-01-02T03:04:00Z"}
	second := object{"id": "second", "outcome": "closed_unpaid", "verified_at": "2026-01-02T03:05:00Z"}
	rows := []object{first, second}
	verify := func() { checkReturnObservations(rows, "first", "second", "5s") }
	if timing := checkReturnObservations(rows, "first", "second", "5s"); timing.window != time.Minute || timing.source != "pinned" {
		t.Fatal("missing the window pinned to the first cited observation")
	}
	expectFailure(t, func() { checkReturnObservations(rows[:1], "first", "second", "5s") })
	expectFailure(t, func() { checkReturnObservations(rows, "other", "second", "5s") })
	expectFailure(t, func() { checkReturnObservations(rows, "first", "other", "5s") })
	second["outcome"] = "paid"
	expectFailure(t, verify)
	second["outcome"], second["verified_at"] = "closed_unpaid", "2026-01-02T03:04:59.999999Z"
	expectFailure(t, verify)
}

func TestSellerReturnPosting(t *testing.T) {
	credit := normalized(object{"direction": "C", "code": "user_available:USDT:seller", "units": 100})
	debit := normalized(object{"direction": "D", "code": "trade_escrow:USDT:seller", "units": 100})
	lines := []object{credit, debit}
	checkSellerReturnLines(lines, "seller", 100)
	expectFailure(t, func() { checkSellerReturnLines(lines, "another-seller", 100) })
	expectFailure(t, func() { checkSellerReturnLines(lines, "seller", 99) })
	for _, rows := range [][]object{{credit}, {debit, credit}, {credit, debit, {"code": "trade_spread_revenue:USDT"}}} {
		expectFailure(t, func() { checkSellerReturnLines(rows, "seller", 100) })
	}
}
