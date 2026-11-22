package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisputeRefundRegistrationAndReport(t *testing.T) {
	for _, tc := range []struct{ name, ext, branch string }{
		{"dispute-refund-before-release", ".md", "PRE_RELEASE"},
		{"dispute-refund-after-release", ".json", "user_risk_held"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			d := newDriver(root, "", tc.name)
			d.put("credential/private-fixture", "private-auth-sentinel")
			d.put("cashier/"+tc.name+"/sample", "https://localhost/cashier/private-cashier-sentinel")
			out := filepath.Join(root, "user-selected"+tc.ext)
			// The actual CLI must register and report the failure before any network I/O.
			err := execute([]string{root, "", "run", tc.name, "-o", out})
			if err == nil || !strings.Contains(err.Error(), "seller-account") {
				t.Fatalf("unexpected run result %v", err)
			}
			data := string(file(out))
			for _, want := range []string{tc.name, tc.branch, "payment/internal/channeladmin/disputes.go:", "refund.dispatch_granted", "failed"} {
				if !strings.Contains(data, want) {
					t.Errorf("report missing %q", want)
				}
			}
			if strings.Contains(data, "private-auth-sentinel") || strings.Contains(data, "private-cashier-sentinel") {
				t.Fatal("report contains private driver state")
			}
			info, err := os.Stat(out)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("expected a private report", err)
			}
			if string(file(filepath.Join(d.dir, "reports", tc.name+tc.ext))) != data {
				t.Fatal("-o report differs from checkpoint report")
			}
		})
	}
}

func TestDisputeRefundReservation(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint("after=", after), func(t *testing.T) {
			h := object{"account_id": "merchant", "reserve_seq": 2, "escrow_usdt": 100, "recipient_usdt": 93}
			r := object{"account_id": "merchant", "refund_id": "f", "refund_reservation_id": "reserve", "prior_dispute_id": "d", "dispute_id": "d", "ruling_id": "a",
				"expected_version": 5, "control_version": 6, "digest": "sha", "approved_at": "2026-11-20T12:00:00Z", "reserve_seq": 2, "branch": "PRE_RELEASE", "reserved_usdt": 100}
			if after {
				h["released_seq"] = 3
				r["reserve_seq"] = 7
				r["branch"] = "POST_RELEASE"
				r["reserved_usdt"] = 93
			}
			p := object{"refund_id": "f", "refund_reservation_id": "reserve", "dispute_id": "d", "ruling_id": "a", "reserve_seq": r["reserve_seq"], "expected_version": 5, "digest": "sha", "approved_at": "2026-11-20T04:00:00-08:00"}
			prove := func() { checkRefundReservation(after, normalized(r), normalized(p), normalized(h), "d", "a") }
			prove()
			for field, value := range map[string]any{"prior_dispute_id": "old", "dispute_id": "elsewhere", "ruling_id": "old", "refund_reservation_id": "different", "branch": "unknown", "reserved_usdt": 0, "control_version": 7, "digest": "other", "account_id": "seller", "reserve_seq": 1, "approved_at": "2026-11-20T11:00:00Z"} {
				t.Run(field, func(t *testing.T) {
					old := r[field]
					r[field] = value
					defer func() { r[field] = old }()
					expectFailure(t, prove)
				})
			}
			wrongSeq := 1
			if after {
				wrongSeq = 3
			}
			r["reserve_seq"], p["reserve_seq"] = wrongSeq, wrongSeq
			expectFailure(t, prove)
		})
	}
}

func TestDisputeRefundDispatchOrder(t *testing.T) {
	audit := object{"occurred_at": "2026-11-20T12:00:00.000002Z"}
	after := object{"occurred_at": "2026-11-20T04:00:00.000003-08:00"}
	checkDispatchOrder(audit, []object{after})
	for _, grants := range [][]object{nil, {audit}, {after, {"occurred_at": "2026-11-20T12:00:00.000001Z"}}, {{"occurred_at": "unknown"}}} {
		expectFailure(t, func() { checkDispatchOrder(audit, grants) })
	}
}

func TestDisputeRefundVerificationEvidence(t *testing.T) {
	auth := object{"query_digest": "issued"}
	success := object{"query_digest": "issued", "operation": "query_refund", "eligible": true, "outcome": "refund_succeeded"}
	if !verifiedRefundQuery(auth, []object{{}, success, {}}) {
		t.Fatal("missed the successful query used at issuance")
	}
	for k, v := range map[string]any{"query_digest": "another", "eligible": false, "operation": "query_payment", "outcome": "refund_failed"} {
		r := normalized(success)
		r[k] = v
		if verifiedRefundQuery(auth, []object{r}) {
			t.Error("accepted mismatched " + k)
		}
	}
	if verifiedRefundQuery(auth, nil) {
		t.Fatal("accepted missing observation")
	}
}

func TestDisputeRefundPostingAndHold(t *testing.T) {
	r := normalized(object{"reserve_seq": 9, "refund_id": "f"})
	post := normalized(object{"source_event_id": "auth", "source_stream": "reconciliation.matches", "kind": "trade_refunded", "seq": 10})
	uniqueRefundPosting([]object{post}, "auth", 10, 9)
	for _, rows := range [][]object{nil, {post, post}, {normalized(object{"source_event_id": "ruling", "source_stream": "payment.orders", "kind": "trade_refunded", "seq": 10})}} {
		expectFailure(t, func() { uniqueRefundPosting(rows, "auth", 10, 9) })
	}
	expectFailure(t, func() { uniqueRefundPosting([]object{post}, "auth", 10, 10) })

	quote := normalized(object{"account_id": "merchant", "recipient_usdt": 93, "released_seq": 5})
	hold := object{"dispute_id": "d", "account_id": "merchant", "owner_account_id": "merchant", "hold_account": "user_risk_held:USDT:merchant",
		"reservation_key": "trade_released_dispute:d", "reserve_seq": 6, "held_usdt": 93, "amount_units": 93, "available_debit": 93, "held_credit": 93, "shortfall_usdt": 0,
		"status": "REFUND_PENDING", "fund_status": "released", "refund_id": "f", "close_seq": 8, "final_seq": 8, "refund_seq": 9, "refund_final_seq": 10, "refund_status": "settled"}
	checkHeld := func() { checkRiskHold(normalized(hold), quote, "d") }
	checkClosed := func() { checkClosedRiskHold(normalized(hold), r, post) }
	checkHeld()
	checkClosed()
	for k, v := range map[string]any{"owner_account_id": "other", "reservation_key": "trade_released_dispute:other", "amount_units": 92, "shortfall_usdt": 1, "held_credit": 0, "available_debit": 0} {
		old := hold[k]
		hold[k] = v
		expectFailure(t, checkHeld)
		hold[k] = old
	}
	for k, v := range map[string]any{"fund_status": "reserved", "refund_status": "reserved", "final_seq": 7, "refund_final_seq": 8, "refund_id": "other", "refund_seq": 8} {
		old := hold[k]
		hold[k] = v
		expectFailure(t, checkClosed)
		hold[k] = old
	}
}

func TestDisputeRefundBalanceDeltas(t *testing.T) {
	held := normalized(object{"seller": 20, "merchant": 40, "ledger_fee_accounts": 5})
	released := normalized(object{"seller": 20, "merchant": 133, "ledger_fee_accounts": 12})
	end := normalized(object{"seller": 120, "merchant": 40, "ledger_fee_accounts": 5})
	checkBalanceDelta(held, end, 100, 0, 0)
	checkBalanceDelta(released, end, 100, -93, -7)
	for _, field := range []string{"seller", "merchant", "ledger_fee_accounts"} {
		wrong := normalized(end)
		wrong[field] = num(end, field) + 1
		expectFailure(t, func() { checkBalanceDelta(released, normalized(wrong), 100, -93, -7) })
	}
}

func TestSimSuccessfulDisputeRefund(t *testing.T) {
	rawReply := object{"result": "accepted", "code": "refund_success", "refund": object{"account_id": "md5-demo", "order_id": "order", "refund_id": "refund", "amount": 100, "currency": "CNY", "status": "success"}, "order": object{"url": "https://localhost/cashier/private-cashier-sentinel"}}
	var fact simRefundResult
	decode(encoded(rawReply), &fact)
	checkSimRefund(fact, "order", "refund")
	if strings.Contains(string(encoded(fact)), "private-cashier-sentinel") {
		t.Fatal("simulator report included unselected fields")
	}
	for k, v := range map[string]any{"account_id": "other", "order_id": "other", "refund_id": "other", "status": "unknown", "amount": 99, "currency": "USD"} {
		test := normalized(rawReply)
		obj(test["refund"])[k] = v
		decode(encoded(test), &fact)
		expectFailure(t, func() { checkSimRefund(fact, "order", "refund") })
	}
}

func TestReleasedDisputeMissingEntry(t *testing.T) {
	for _, tc := range []struct {
		httpCode, code int
		missing        bool
	}{{404, 0, true}, {405, 0, true}, {200, 501, true}, {409, 409, true}, {503, 503, false}} {
		t.Run(fmt.Sprint(tc.httpCode, "-", tc.code), func(t *testing.T) {
			d := newDriver(t.TempDir(), "", "dispute-refund-after-release")
			b := d.browser("operations")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					io.WriteString(w, `{"code":200,"data":{"token":"private-csrf"}}`)
					return
				}
				w.WriteHeader(tc.httpCode)
				if tc.code == 0 {
					io.WriteString(w, "route unavailable")
					return
				}
				fmt.Fprintf(w, `{"code":%d}`, tc.code)
			}))
			defer srv.Close()
			b.addr = strings.TrimPrefix(srv.URL, "http://")
			expectFailure(t, func() {
				d.step("平台登记", func() { b.write("dispute", "/disputes", func() object { return object{"reason": "fixture"} }) })
			})
			got := d.history.Steps[0].Error
			if strings.Contains(got, "缺入口") != tc.missing || !strings.Contains(got, fmt.Sprintf("HTTP %d", tc.httpCode)) {
				t.Fatal(got)
			}
		})
	}
}
