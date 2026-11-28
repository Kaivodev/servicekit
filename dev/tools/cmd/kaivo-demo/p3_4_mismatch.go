package main

import (
	"encoding/hex"
	"strconv"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"google.golang.org/protobuf/proto"
)

const observedMinor = p34OrderMinor - 100

func (t tradeRun) stoppedMismatch() object {
	d := t.d
	var row object
	d.waitFor("open mismatch on a stopped order", 2*time.Minute, func() bool {
		rows := d.rows("payment", "stopped mismatch", `SELECT c.case_id,c.order_id,o.stage,o.status,c.state
			FROM payment_amount_mismatch_cases c JOIN payment_orders o ON o.id=c.order_id
			WHERE c.order_id=$1 AND c.state=1 AND o.stage='stopped' AND o.status=$2`, t.order, int32(pay.OrderStatus_ORDER_STATUS_UNKNOWN))
		if len(rows) == 0 {
			return false
		}
		row = oneFact(rows, "open mismatch case")
		return true
	})
	d.evidence("stopped_order", row)
	return row
}

func (t tradeRun) openMismatch() string {
	s := t.step("Pay through the cashier with an incorrect query amount", func() {
		t.setScenario(object{"query_amount": observedMinor})
		t.payA145Cashier()
		row := t.stoppedMismatch()
		d := t.d
		d.login("risk")
		detail := d.browser("risk").api("GET", t.orderPath("amount-mismatch"), "", nil)
		c := obj(detail["mismatch_case"])
		require(c["case_id"] == row["case_id"] && c["state"] == "open" && c["source"] == "query" && c["order_id"] == t.order, "mismatch detail does not match the stopped query")
		t.merchantUnpaid()
		d.evidence("case_id", c["case_id"])
		d.evidence("query_amount_minor", observedMinor)
	})
	return str(s.Evidence, "case_id")
}

func (t tradeRun) clearQueryAmount() {
	t.d.sim("DELETE", t.scenarioPath(), nil)
	var effective object
	decode(t.d.sim("GET", t.scenarioPath(), nil), &effective)
	require(effective["query_amount"] == nil, "account configuration still overrides the query amount")
}

func (t tradeRun) approveRecovery(caseID, outcome string) object {
	d := t.d
	step := t.step("Approve "+outcome+" for the stopped payment", func() {
		d.login("risk")
		h := t.reservation()
		body := object{"case_id": caseID, "outcome": outcome, "escrow_reservation_id": h["escrow_reservation_id"], "expected_control_version": h["control_version"], "reason": "Resolve the verified query amount discrepancy."}
		if outcome == "refund_observed" {
			body["refund_amount"] = strconv.FormatInt(observedMinor, 10)
		}
		r := d.browser("risk").write("recover/"+caseID, t.orderPath("amount-mismatch-recoveries"), func() object { return body })
		requester := d.required("user/risk")
		a := requireRecoveryApproval(r, "amount_mismatch_recovery", t.order, requester)
		op := obj(obj(a["material"])["amount_mismatch_recovery"])
		recovery := obj(r["recovery"])
		var sent object
		require(d.read("write/"+d.scope+"/recover/"+caseID+"/body", &sent) && matchesProposal(op, sent) &&
			recovery["recovery_id"] == op["recovery_id"] && recovery["case_id"] == caseID && recovery["order_id"] == t.order &&
			recovery["approval_request_id"] == obj(a["approval_request"])["id"], "recovery approval does not match the submitted proposal")
		if outcome == "refund_observed" {
			require(str(op, "refund_id") == recovery["refund_id"] && op["refund_amount"] == recovery["refund_amount"], "refund identity or amount differs from the approval")
		} else {
			require(op["refund_amount"] == nil && op["refund_id"] == nil && num(op, "reverify_attempt") == 1, "unexpected reverify terms")
		}
		d.approveExisting("recovery/"+caseID, "payment", requester, "/amount-mismatch-recoveries", a)
		d.evidence("recovery", recovery)
	})
	return obj(step.Evidence["recovery"])
}

func (d *driver) runMismatchReverify() {
	t := d.recoveryTrade(false)
	caseID := t.openMismatch()
	t.step("Clear the per-order query override", t.clearQueryAmount)
	recovery := t.approveRecovery(caseID, "reverify")
	t.step("Match the paid re-verification to OrderPaid", func() {
		d.waitFor("OrderPaid after the approved query", 2*time.Minute, func() bool {
			rows := d.facts("payment", "paid recovery query", `SELECT p.event_id,p.sequence,q.exchange_id
				FROM payment_outbox p JOIN payment_admin_requests a ON a.id=$2
				JOIN payment_gateway_executions q ON q.order_id=p.order_id AND q.operation='query_payment'
				AND q.category='succeeded' AND q.responses>0 AND q.occurred_at>=a.approved_at
				WHERE p.order_id=$1 AND p.event_type='OrderPaid' AND p.sequence IS NOT NULL`, t.order, str(recovery, "approval_request_id"))
			if len(rows) == 0 {
				return false
			}
			return len(d.facts("ledger", "applied OrderPaid", `SELECT source_event_id,source_sequence FROM ledger_trade_payments
				WHERE order_id=$1 AND source_event_id=$2 AND source_sequence=$3`, t.order, str(rows[0], "event_id"), num(rows[0], "sequence"))) == 1
		})
		d.login("risk")
		detail := d.browser("risk").api("GET", t.orderPath("amount-mismatch"), "", nil)
		c := obj(detail["mismatch_case"])
		require(c["case_id"] == caseID && c["state"] == "resolved" && c["resolution"] == "reverified_paid" && num(c, "reverify_attempts") == 1, "case did not resolve through re-verification")
	})
	t.release()
	t.step("Confirm payment completed the order", func() { t.awaitOrderStatus("completed") })
}

func (t tradeRun) awaitingMismatchRefund(refund string) {
	d := t.d
	t.step("Verify the ledger occupation preceded the seller notice", func() {
		d.waitFor("refund occupation", time.Minute, func() bool {
			h := t.reservation()
			return h["status"] == "REFUND_PENDING" && h["refund_id"] == refund && h["paid_verified_at"] == nil
		})
		// PRE_RELEASE reuses the trade's original reserve_seq. The ledger
		// writes its success audit after creating the refund occupation in
		// the same transaction. Both owner databases use the native clock.
		occupation := oneFact(d.facts("ledger", "refund occupation", `SELECT f.refund_reservation_id,f.reserved_usdt,a.occurred_at
			FROM ledger_trade_refunds f JOIN ledger_audit_logs a ON a.target_id=f.order_id::text AND a.xmin=f.xmin
			WHERE f.order_id=$1 AND f.refund_id=$2 AND f.branch='PRE_RELEASE'
			AND a.action='ledger.reserve_refund' AND a.result='succeeded'`, t.order, refund), "confirmed pre-release refund")
		d.waitFor("seller pending notice", time.Minute, func() bool {
			rows := d.rows("payment", "seller refund outbox", `SELECT event_id,recorded_at,encode(payload,'hex') AS wire
				FROM payment_outbox WHERE stream='payment.account_notices' AND event_type='SellerRefundNotice'
				AND refund_notice_order_id=$1 ORDER BY recorded_at`, t.order)
			for _, row := range rows {
				var m pay.SellerRefundNotice
				wire, err := hex.DecodeString(str(row, "wire"))
				check(err)
				check(proto.Unmarshal(wire, &m))
				if m.GetSubject().GetRefundId() != refund || m.Kind != pay.SellerRefundNoticeKind_SELLER_REFUND_NOTICE_KIND_PENDING {
					continue
				}
				checkMismatchNotice(&m, t.order, refund, d.required("seller-account"), coverageTime(row, "recorded_at"), coverageTime(occupation, "occurred_at"))
				d.evidence("pending_notice", object{"event_id": row["event_id"], "recorded_at": row["recorded_at"]})
				return true
			}
			return false
		})
		d.login("seller")
		view := d.browser("seller").api("GET", "/accounts/"+d.required("seller-account")+"/refunds/"+refund, "", nil)
		require(view["order_id"] == t.order && view["status"] == "awaiting_seller" && units(obj(view["fiat_amount"]), "amount_minor") == observedMinor, "seller has no matching refund to process")
		t.merchantUnpaid()
	})
}

func checkMismatchNotice(m *pay.SellerRefundNotice, order, refund, seller string, recorded, reserved time.Time) {
	require(m.OrderId == order && m.GetSubject().GetRefundId() == refund && m.SellerAccountId == seller &&
		m.Kind == pay.SellerRefundNoticeKind_SELLER_REFUND_NOTICE_KIND_PENDING && m.Origin == pay.RefundOrigin_REFUND_ORIGIN_AMOUNT_MISMATCH &&
		m.FiatCurrency == "CNY" && m.FiatAmount == observedMinor && recorded.After(reserved),
		"seller notice amount, scope or ordering differs from the confirmed occupation")
}

func (t tradeRun) mismatchRefund() (string, string) {
	caseID := t.openMismatch()
	recovery := t.approveRecovery(caseID, "refund_observed")
	refund := str(recovery, "refund_id")
	t.awaitingMismatchRefund(refund)
	return caseID, refund
}

func (d *driver) runMismatchRefund() {
	require(d.env("payment")["AIPAY_PAYMENT_REFUND_OBJECTION_WINDOW"] == "0s", "native recovery requires a zero objection window")
	t := d.recoveryTrade(false)
	caseID, refund := t.mismatchRefund()
	t.step("Refuse evidence for the original order amount", func() {
		d.login("seller")
		s := refundSubject(refund)
		c := portalCommand{path: "/accounts/" + d.required("seller-account") + s.path() + "/process", template: "/accounts/:seller_account_id/refunds/:id/process",
			permission: "payment.refund.process", key: d.key("wrong-amount/" + refund),
			body: object{"expected_evidence_version": 0, "upstream_refund_no": "demo:" + t.order, "refunded_at": d.value("wrong-amount/time/"+refund, func() string { return time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano) }),
				"money": t.amount, "files": []object{{"content_type": "image/png", "data": refundPNG(refund)}}}}
		requireRefusedWrite(c.path, 409, "REFUND_AMOUNT_NOT_APPROVED", func() { d.browser("seller").submitRecent(c) })
	})

	// The shared flow resumes uploads, obtains two reviews, verifies the
	// reconciliation resolution and matches its authorization to the posting.
	post := t.manualRefund(refund)
	t.step("Verify the seller received Q and the merchant still sees unpaid", func() {
		h := d.ledgerTrade(t.order)
		lines := d.facts("ledger", "refund posting lines", `SELECT a.code,l.direction,l.units FROM ledger_lines l
			JOIN ledger_accounts a ON a.id=l.account_id WHERE l.seq=$1 ORDER BY l.direction`, num(post, "posting_seq"))
		checkSellerReturnLines(lines, d.required("seller-account"), num(h, "escrow_usdt"))
		t.awaitOrderStatus("refunded")
		d.login("risk")
		c := obj(d.browser("risk").api("GET", t.orderPath("amount-mismatch"), "", nil)["mismatch_case"])
		require(c["case_id"] == caseID && c["resolution"] == "refunded", "mismatch case did not resolve as refunded")
		t.merchantUnpaid()
		t.clearQueryAmount()
	})
}

func (d *driver) runMismatchRefundFailed() {
	t := d.recoveryTrade(false)
	caseID, refund := t.mismatchRefund()
	step := t.step("Obtain two approvals for the refund failure", func() {
		d.login("risk")
		r := d.browser("risk").write("failure/"+refund, "/refunds/"+refund+"/failure-requests", func() object { return object{"reason": "The seller could not return the observed payment."} })
		op := obj(obj(r["material"])["seller_refund_failure"])
		require(obj(op["subject"])["refund_id"] == refund && obj(op["trade"])["order_id"] == t.order && op["branch"] == "pre_release" && op["evidence_id"] == nil, "failure approval differs from the awaiting-seller refund")
		d.approveExisting("failure/"+refund, "payment", d.required("user/risk"), "/seller-refund-failures", r)
	})
	t.step("Verify the failed refund restored the stopped order", func() {
		res := t.awaitRefundResolution(refund, str(step.Evidence, "approval_id"), str(step.Evidence, "request_digest"))
		require(t.stoppedMismatch()["case_id"] == caseID, "a different case reopened")
		h := t.reservation()
		require(h["status"] == "RESERVED" && h["paid_verified_at"] == nil && h["released_seq"] == nil, "failed refund did not restore unpaid escrow")
		require(len(d.facts("ledger", "failed refund authorization", `SELECT authorization_id,result_status FROM ledger_trade_authorizations
			WHERE order_id=$1 AND refund_id=$2 AND authorization_id=$3 AND event_type='TradeRefundAuthorized'
			AND outcome='REFUND_VERIFICATION_OUTCOME_FAILED' AND result_status='RESERVED' AND posting_seq IS NULL`, t.order, refund, str(res, "authorization_id"))) == 1, "missing ledger restoration")
		t.merchantUnpaid()
		t.clearQueryAmount()
	})
}
