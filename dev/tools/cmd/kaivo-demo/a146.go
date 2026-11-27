package main

import (
	"encoding/hex"
	"net/url"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	recon "github.com/Kaivodev/protobuf/gen/go/aipay/reconciliation/v1"
	"google.golang.org/protobuf/proto"
)

const (
	disputeReturn       = "dispute-return"
	disputeReturnPaid   = "dispute-return-paid"
	returnToSeller      = "return_to_original_seller"
	rulingOutcomeDenied = "DISPUTE_RULING_OUTCOME_NOT_ALLOWED"
)

func disputeReturnPlan() ([]string, []string) {
	return []string{
		"Open an unpaid 2.00 EPay V2 order, register both parties' evidence and archive the work before authorization.",
		"Refuse release to the recipient with HTTP 200, business code 409 and " + rulingOutcomeDenied + ". Check zero ruling requests and an unchanged control version.",
		"Backdate the simulator order and approve return to the original seller with two signatures. Match the cancellation authorization to the ruling and two closed-unpaid observations at least the pinned window apart.",
		"Verify CANCELLED, a return of Q without fees, the ledger cancellation audit, and the resolved payment, platform and seller dispute records.",
		"Verify merchant V2 query status 0, a refused close that leaves the order cancelled (existing behaviour after any platform-side cancellation) and zero payment notifications.",
	}, []string{"Reconciliation stores the TradeCancellationAuthorized protobuf in reconciliation_authorizations.payload and the observation IDs in evidence_material."}
}

func (t tradeRun) refuseDisputeRuling(dispute, outcome string) {
	d := t.d
	t.step("Refuse "+outcome, func() {
		registered := oneFact(d.facts("payment", "payment_fact_at_registration", `SELECT released,
			(original_order->>'status')::integer AS original_status,original_order ? 'paid_verified_at' AS paid
			FROM payment_disputes WHERE id=$1 AND order_id=$2`, dispute, t.order), "registered dispute")
		checkPreReleasePaymentFact(registered, outcome == returnToSeller)
		d.login("risk")
		before := d.ledgerTrade(t.order)
		require(before["status"] == "DISPUTED", "expected disputed escrow before the ruling proposal")
		version := num(before, "control_version")
		d.evidence("control_version_before", version)
		path := "/disputes/" + dispute + "/rulings"
		refusal := requireRefusedWrite(path, 409, rulingOutcomeDenied, func() {
			d.browser("risk").write("risk/refuse-"+outcome, path, func() object {
				return object{"expected_control_version": version, "outcome": outcome, "reason": "Check the ruling against the original payment fact."}
			})
		})
		d.evidence("refused_ruling", object{"dispute_id": dispute, "outcome": outcome, "http_status": refusal.httpStatus, "business_code": refusal.businessCode, "message": refusal.message})
		requests := d.facts("payment", "ruling_requests_after_refusal", `SELECT id FROM payment_admin_requests
			WHERE kind='dispute_ruling' AND material#>>'{dispute_ruling,dispute_id}'=$1`, dispute)
		require(len(requests) == 0, "payment created an approval request for the refused ruling")
		after := d.ledgerTrade(t.order)
		d.evidence("control_version_after", after["control_version"])
		require(after["status"] == "DISPUTED" && num(after, "control_version") == version, "the refused ruling changed the escrow")
		order := d.browser("operations").api("GET", "/orders/"+t.order, "", nil)
		d.evidence("order_status_after_refusal", order["status"])
		require(order["status"] == "disputed", "the refused ruling changed the payment order status")
	})
}

func checkPreReleasePaymentFact(row object, paid bool) {
	require(row["released"] == false && row["paid"] == paid, "the dispute does not have the expected pre-release payment fact")
	status := pay.OrderStatus(num(row, "original_status"))
	if paid {
		require(status == pay.OrderStatus_ORDER_STATUS_RISK_HELD, "paid dispute was not registered during the risk hold")
	} else {
		require(status == pay.OrderStatus_ORDER_STATUS_AWAITING_PAYMENT || status == pay.OrderStatus_ORDER_STATUS_UNKNOWN, "unpaid dispute was not registered on an awaiting or unknown order")
	}
}

func (d *driver) runDisputeReturn() {
	t := d.trade("Unpaid return", "v2")
	t.registerDispute(false)
	dispute := d.required("dispute/" + t.order)
	t.archiveCancellationWork(false)
	t.refuseDisputeRuling(dispute, "release_to_original_recipient")
	t.step("Backdate the unpaid simulator order", t.backdateUnpaid)
	approved := t.step("Approve return to the original seller", func() {
		m := d.browser("risk").approve("return-to-seller", "payment", "/disputes/"+dispute+"/rulings", "/dispute-rulings",
			object{"expected_control_version": num(d.ledgerTrade(t.order), "control_version"), "outcome": returnToSeller, "reason": "Return the unpaid order escrow to the original seller."})
		op := obj(m["dispute_ruling"])
		require(op["dispute_id"] == dispute && obj(op["trade"])["order_id"] == t.order, "approved ruling belongs to another dispute or order")
		d.evidence("approved_outcome", op["outcome"])
		d.evidence("approver_ids", []string{d.key("person/" + approvers[0]), d.key("person/" + approvers[1])})
	})
	ruling := str(approved.Evidence, "approval_id")
	cancelled := t.step("Trace the ruling through reconciliation and ledger", func() {
		configured := d.env("reconciliation")[lateWindowEnv]
		hold, _ := t.awaitUnpaidCancellation(configured)
		auth := t.returnAuthorization(dispute, ruling, configured)
		d.evidence("authorization_id", auth)
		require(hold["status"] == "CANCELLED" && units(hold, "held_usdt_micro") == 0, "seller escrow was not cancelled in full")
		lines := d.facts("ledger", "cancellation_posting", `SELECT a.source_event_id,l.seq,acct.code,l.direction,l.units
			FROM ledger_trade_authorizations a JOIN ledger_lines l ON l.seq=a.posting_seq JOIN ledger_accounts acct ON acct.id=l.account_id
			WHERE a.order_id=$1 AND a.event_type='TradeCancellationAuthorized' AND a.source_event_id=$2 AND l.seq=$3 ORDER BY l.direction`,
			t.order, auth, num(hold, "latest_seq"))
		checkSellerReturnLines(lines, str(hold, "seller_account_id"), num(hold, "escrow_usdt"))
		t.finish(false)
	})
	t.step("Verify the payment projection and both dispute views", func() {
		audit := t.checkCancellationProjection()
		require(audit["dispute_id"] == dispute && audit["ruling_id"] == ruling && audit["authorization_id"] == str(cancelled.Evidence, "authorization_id"),
			"the ledger cancellation audit does not reference the dispute, ruling and authorization")
		row := oneFact(d.facts("payment", "dispute_record", "SELECT id,state FROM payment_disputes WHERE id=$1 AND order_id=$2", dispute, t.order), "payment dispute")
		require(row["state"] == "resolved", "payment did not resolve the dispute")
		path := "/disputes/" + dispute
		platform := d.browser("operations").api("GET", path, "", nil)
		seller := d.browser("seller").api("GET", "/accounts/"+d.required("seller-account")+path, "", nil)
		d.evidence("platform_dispute", object{"dispute_id": obj(platform["dispute"])["dispute_id"], "status": platform["status"]})
		d.evidence("seller_dispute", object{"dispute_id": seller["dispute_id"], "status": seller["status"], "ruling_outcome": seller["ruling_outcome"]})
		require(obj(platform["dispute"])["dispute_id"] == dispute && platform["status"] == "resolved", "platform view did not resolve the dispute")
		require(seller["dispute_id"] == dispute && seller["status"] == "resolved" && seller["ruling_outcome"] == returnToSeller, "seller view did not resolve the dispute as a return")
	})
	t.step("Check the merchant query, close and notifications", func() {
		query := d.epay("v2", "/api/pay/query", url.Values{"out_trade_no": {t.number}})
		d.evidence("merchant_query", object{"out_trade_no": query["out_trade_no"], "status": query["status"], "code": query["code"]})
		require(query["out_trade_no"] == t.number && num(query, "status") == 0, "merchant query did not report the original order as unpaid")
		// Existing behaviour for every platform-side cancellation (A140, A144,
		// A145, a dispute return): payment only accepts a merchant close while
		// the escrow is still RESERVED, so a later close is refused and changes
		// nothing.
		status, closeReply := d.signedEPay("v2", "/api/pay/close", url.Values{"out_trade_no": {t.number}})
		d.evidence("merchant_close", object{"http_status": status, "code": closeReply["code"], "msg": closeReply["msg"]})
		require(status == 200 && num(closeReply, "code") == -1, "merchant close on the cancelled order was not refused")
		order := d.browser("operations").api("GET", "/orders/"+t.order, "", nil)
		hold := d.ledgerTrade(t.order)
		require(order["status"] == "cancelled" && hold["status"] == "CANCELLED", "the refused merchant close changed the cancelled order")
		notices := d.facts("payment", "payment_notifications", "SELECT id,status FROM payment_notifications WHERE order_id=$1", t.order)
		require(len(notices) == 0, "payment created a merchant notification for the unpaid order")
	})
}

func (t tradeRun) returnAuthorization(dispute, ruling, configured string) string {
	d := t.d
	rows := d.rows("reconciliation", "dispute cancellation authorization", `SELECT authorization_id,encode(payload,'hex') AS payload,
		convert_from(evidence_material,'UTF8')::jsonb#>>'{Review,Evidence,Cancellation,First,ID}' AS first_id,
		convert_from(evidence_material,'UTF8')::jsonb#>>'{Review,Evidence,Cancellation,Second,ID}' AS second_id
		FROM reconciliation_authorizations WHERE order_id=$1 AND event_type='TradeCancellationAuthorized'`, t.order)
	d.evidence("cancellation_authorization_count", len(rows))
	auth := oneFact(rows, "dispute cancellation authorization")
	id := str(auth, "authorization_id")
	var event recon.TradeCancellationAuthorized
	wire, err := hex.DecodeString(str(auth, "payload"))
	check(err)
	check(proto.Unmarshal(wire, &event))
	ref := event.GetDisputeResolution()
	d.evidence("authorization_payload", object{"authorization_id": event.AuthorizationId, "order_id": event.Trade.GetOrderId(), "dispute_id": ref.GetDisputeId(), "ruling_id": ref.GetRulingId()})
	checkReturnAuthorization(&event, id, t.order, dispute, ruling)
	first, second := str(auth, "first_id"), str(auth, "second_id")
	observations := d.facts("reconciliation", "authorized_observations", cancellationObservations+" AND id IN ($2,$3) ORDER BY verified_at,id", t.order, first, second)
	timing := checkReturnObservations(observations, first, second, configured)
	d.evidence("authorized_observation_window", object{"window": timing.window.String(), "source": timing.source, "first_id": first, "second_id": second})
	return id
}

func checkReturnObservations(rows []object, first, second, configured string) latePaymentTiming {
	require(first != second && len(rows) == 2 && rows[0]["id"] == first && rows[1]["id"] == second, "missing the two eligible queries cited by the authorization")
	timing := unpaidObservationTiming(rows[0], configured)
	checkUnpaidSeparation(rows, timing.window)
	return timing
}

func checkReturnAuthorization(event *recon.TradeCancellationAuthorized, id, order, dispute, ruling string) {
	ref := event.GetDisputeResolution()
	require(event.GetAuthorizationId() == id && event.GetTrade().GetOrderId() == order && ref.GetDisputeId() == dispute && ref.GetRulingId() == ruling,
		"stored cancellation authorization does not match the original order and approved ruling")
}

func checkSellerReturnLines(lines []object, seller string, q int64) {
	require(len(lines) == 2 && q > 0, "expected exactly two posting lines for the return of Q")
	credit, debit := lines[0], lines[1]
	require(credit["direction"] == "C" && credit["code"] == "user_available:USDT:"+seller && num(credit, "units") == q &&
		debit["direction"] == "D" && debit["code"] == "trade_escrow:USDT:"+seller && num(debit, "units") == q,
		"cancellation did not move exactly Q from the original seller escrow to available")
}
