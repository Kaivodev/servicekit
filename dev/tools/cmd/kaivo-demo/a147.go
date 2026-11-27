package main

import (
	"context"
	"encoding/hex"
	"net/url"
	"time"

	ledger "github.com/Kaivodev/protobuf/gen/go/aipay/ledger/v1"
	"google.golang.org/protobuf/proto"
)

const (
	disputePaidRelease = "dispute-paid-release"
	disputePaidRefund  = "dispute-paid-refund"
	disputePaidRace    = "dispute-paid-race"
	releaseToRecipient = "release_to_original_recipient"
)

func isDisputePaidScenario(s string) bool {
	return s == disputePaidRelease || s == disputePaidRefund || s == disputePaidRace
}

func disputePaidPlan(s string) ([]string, []string) {
	steps := []string{"Create an unpaid EPay V2 order, open its simulator instruction and register a pre-release dispute with evidence from both parties."}
	notes := []string{"Use the native simulator gateways with payment migration 000026 and reconciliation migration 000022. Approval assertions expose only credential_id."}
	switch s {
	case disputePaidRelease:
		steps = append(steps,
			"Approve a return with two signatures and immediately pay. Observe the payment fenced by that ruling.",
			"Wait for a reported payment_observed denial and its payment receipt. Check reconciliation_denied, the lapsed ruling, one notification and the paid DISPUTED escrow at registration version + 1.",
			"Compare platform payment_observation with owner records, check that the lapsed ruling shows no ruling_review, and check the seller's payment_state. Approve release at the new version.",
			"Wait for release after the risk hold. Verify COMPLETED, a resolved dispute, merchant query status 1 and no TradeCancelled in the payment inbox.")
		notes = append(notes, "Keep the original simulator creation time so reconciliation cannot authorize an unpaid cancellation.")
	case disputePaidRefund:
		steps = append(steps,
			"Pay without a ruling. Check verified with no_ruling and the new ledger version. Deliver two copies of the payment callback and check one observation, OrderPaid and merchant payment notification.",
			"Refuse return with business code 409 and "+rulingOutcomeDenied+". Check that no approval request exists.",
			"Approve a refund at registration version + 1. Complete seller evidence, two reviews and the objection period. Verify REFUNDED, the return of seller escrow and the signed merchant refund query.")
		notes = append(notes, "Use the 1.00 form-md5 route for the pre-release manual refund.")
	case disputePaidRace:
		steps = append(steps,
			"Backdate the simulator order and pause ledger's matches reader. Approve a return and wait for a signed cancellation citing two closed-unpaid observations.",
			"Pay while the ledger trade is DISPUTED. Check the fence, zero reconciliation reports and refusal of release, refund and another return without a new approval request.",
			"Resume matches within the authorization lifetime. Verify CANCELLED, a resolved dispute, a linked late payment awaiting the seller, merchant query status 0 and zero notifications.",
			"Check the cancellation inbox outcome. Submit seller evidence and obtain two reviews to close the late payment.")
		notes = append(notes, "Enable native deposits for ledger-matches pause. Cleanup resumes the reader on failure. The native cancellation authorization lasts five minutes.")
	default:
		stop("unknown dispute payment scenario")
	}
	return steps, notes
}

type paidDispute struct {
	tradeRun
	dispute string
	version int64 // Ledger control version at registration.
}

func (d *driver) openUnpaidDispute() paidDispute {
	t := d.trade("Dispute payment", "v2")
	t.registerDispute(false)
	dispute := d.required("dispute/" + t.order)
	s := t.step("Check the unpaid registration", func() {
		row := oneFact(d.facts("payment", "registration", `SELECT released,original_order ? 'paid_verified_at' AS paid,
			(original_order->>'status')::int AS original_status,(registered->>'control_version')::bigint AS version
			FROM payment_disputes WHERE id=$1 AND order_id=$2`, dispute, t.order), "dispute registration")
		checkPreReleasePaymentFact(row, false)
		version := num(row, "version")
		h := d.ledgerTrade(t.order)
		require(version > 0 && h["status"] == "DISPUTED" && num(h, "control_version") == version &&
			h["paid_verified_at"] == nil, "ledger does not have the registered unpaid escrow")
		d.evidence("registration_version", row["version"])
	})
	return paidDispute{t, dispute, num(s.Evidence, "registration_version")}
}

func (r paidDispute) approveRuling(outcome string, version int64) string {
	m := r.d.browser("risk").approve("ruling/"+outcome, "payment", "/disputes/"+r.dispute+"/rulings", "/dispute-rulings",
		object{"outcome": outcome, "expected_control_version": version, "reason": "Resolve the dispute using the original order and the submitted evidence."})
	op := obj(m["dispute_ruling"])
	require(op["dispute_id"] == r.dispute && obj(op["trade"])["order_id"] == r.order && op["outcome"] == outcome &&
		num(op, "expected_control_version") == version, "signed ruling differs from the dispute, order, outcome or version")
	r.d.evidence("ruling_approvers", []string{r.d.key("person/" + approvers[0]), r.d.key("person/" + approvers[1])})
	return str(m, "approval_request_id")
}

func (r paidDispute) refuseRuling(outcome string, version int64, existing string) {
	d := r.d
	d.login("risk")
	path := "/disputes/" + r.dispute + "/rulings"
	refusal := requireRefusedWrite(path, 409, rulingOutcomeDenied, func() {
		d.browser("risk").write("refuse/"+outcome, path, func() object {
			return object{"expected_control_version": version, "outcome": outcome, "reason": "Check the observed payment before changing the ruling."}
		})
	})
	d.evidence("refused_"+outcome, object{"http_status": refusal.httpStatus, "business_code": refusal.businessCode, "message": refusal.message})
	rows := d.facts("payment", "requests_after_"+outcome, `SELECT id FROM payment_admin_requests
		WHERE kind='dispute_ruling' AND material#>>'{dispute_ruling,dispute_id}'=$1`, r.dispute)
	require(existing == "" && len(rows) == 0 || len(rows) == 1 && rows[0]["id"] == existing,
		"refused ruling changed the set of approval requests")
}

const disputeObservationSQL = `SELECT p.dispute_id,p.state,p.resolution,p.fence_ruling_id,p.upstream_order_id,
	encode(p.query_evidence_sha256,'hex') AS digest,p.observed_at,p.resolved_at,p.late_payment_id,
	o.data->>'paid_verified_at' AS paid_verified_at,
	(SELECT count(*) FROM payment_notifications WHERE order_id=p.order_id) AS notifications,
	(SELECT count(*) FROM payment_outbox WHERE order_id=p.order_id AND event_type='OrderPaid') AS paid_events
	FROM payment_dispute_payments p JOIN payment_orders o ON o.id=p.order_id
	WHERE p.order_id=$1`

func (r paidDispute) observation(state, resolution, ruling string, limit time.Duration) object {
	var row object
	waitFor("dispute payment "+state, limit, func() bool {
		rows := r.d.facts("payment", "payment_"+state, disputeObservationSQL, r.order)
		if len(rows) == 0 {
			return false
		}
		row = oneFact(rows, "dispute payment observation for the order")
		require(row["dispute_id"] == r.dispute, "payment observation belongs to another dispute")
		if row["state"] == "fenced" && state != "fenced" {
			return false
		}
		require(row["state"] == state, "unexpected dispute payment state while waiting for "+state)
		return true
	})
	checkDisputeObservation(row, state, resolution, ruling)
	return row
}

func checkDisputeObservation(row object, state, resolution, ruling string) {
	matches := func(key, expected string) bool {
		if expected == "" {
			return row[key] == nil
		}
		return row[key] == expected
	}
	require(row["state"] == state && matches("resolution", resolution) && matches("fence_ruling_id", ruling),
		"payment observation has the wrong state, resolution or blocking ruling")
	require((row["resolved_at"] != nil) == (state != "fenced") && (row["late_payment_id"] != nil) == (state == "late_payment"),
		"unexpected resolution time or late payment reference")
	var paid int64
	if state == "verified" {
		paid = 1
	}
	require((row["paid_verified_at"] != nil) == (paid == 1) && num(row, "notifications") == paid && num(row, "paid_events") == paid,
		"payment verification, OrderPaid or merchant notification count differs from the observation")
}

func (r paidDispute) verified(resolution, ruling string) object {
	row := r.observation("verified", resolution, ruling, 2*time.Minute)
	waitFor("ledger OrderPaid on the disputed escrow", 2*time.Minute, func() bool {
		h := oneFact(r.d.facts("ledger", "paid_escrow", `SELECT status,dispute_id,control_version,paid_verified_at
			FROM ledger_trade_reservations WHERE order_id=$1`, r.order), "ledger trade")
		if h["paid_verified_at"] == nil {
			return false
		}
		require(h["status"] == "DISPUTED" && h["dispute_id"] == r.dispute && num(h, "control_version") == r.version+1 &&
			sameInstant(h["paid_verified_at"], row["paid_verified_at"]), "OrderPaid did not advance the registered escrow by one version")
		return true
	})
	return row
}

const rulingReportSQL = `SELECT disposition,reason,reviewed_at,reported_at FROM reconciliation_ruling_reports
	WHERE order_id=$1 AND dispute_id=$2 AND ruling_id=$3 AND control_version=$4`

func (r paidDispute) reportedDenial(ruling string) object {
	var report, review object
	waitFor("reported reconciliation denial", 3*time.Minute, func() bool {
		rows := r.d.facts("reconciliation", "ruling_report", rulingReportSQL, r.order, r.dispute, ruling, r.version)
		if len(rows) == 0 {
			return false
		}
		report = oneFact(rows, "ruling report")
		require(report["disposition"] == "denied" && report["reason"] == "payment_observed", "unexpected reconciliation ruling disposition")
		return report["reported_at"] != nil
	})
	waitFor("payment to record the denial and lapse the return ruling", 2*time.Minute, func() bool {
		review = oneFact(r.d.facts("payment", "return_ruling", `SELECT stage,review_disposition,review_reason,reviewed_at,review_recorded_at
			FROM payment_dispute_rulings WHERE id=$1 AND dispute_id=$2`, ruling, r.dispute), "approved return ruling")
		return review["stage"] == "lapsed" && review["review_recorded_at"] != nil
	})
	require(num(review, "review_disposition") == 1 && review["review_reason"] == report["reason"] &&
		sameInstant(review["reviewed_at"], report["reviewed_at"]), "payment recorded a different reconciliation review")
	return review
}

func (r paidDispute) checkViews(row, review object) {
	path := "/disputes/" + r.dispute
	platform := r.d.browser("operations").api("GET", path, "", nil)
	seller := r.d.browser("seller").api("GET", "/accounts/"+r.d.required("seller-account")+path, "", nil)
	require(obj(platform["dispute"])["dispute_id"] == r.dispute && seller["dispute_id"] == r.dispute, "portal returned another dispute")
	checkDisputeViews(platform, seller, row, review)
	r.d.evidence("platform_observation", platform["payment_observation"])
	r.d.evidence("platform_ruling_review", platform["ruling_review"])
	r.d.evidence("seller_payment_state", seller["payment_state"])
}

func checkDisputeViews(platform, seller, row, review object) {
	p := obj(platform["payment_observation"])
	require(p["state"] == row["state"] && p["resolution"] == row["resolution"] && p["late_payment_id"] == row["late_payment_id"] &&
		str(p, "upstream_order_id") == row["upstream_order_id"] && hex.EncodeToString(raw(str(p, "query_evidence_sha256"))) == row["digest"] &&
		sameInstant(p["observed_at"], row["observed_at"]) && sameInstant(p["resolved_at"], row["resolved_at"]), "platform payment observation differs from payment")
	require(seller["payment_state"] == p["state"], "seller payment state differs from platform")
	for _, key := range []string{"payment_observation", "ruling_review", "upstream_order_id", "query_evidence_sha256", "fence_ruling_id", "late_payment_id", "resolution", "observed_at", "resolved_at"} {
		_, present := seller[key]
		require(!present, "seller dispute exposes "+key)
	}
	// ruling_review describes the displayed ruling. Verification lapses the
	// reviewed return ruling, which the platform view no longer shows, so the
	// review itself is checked against the owner rows instead.
	_, present := platform["ruling_review"]
	require(!present, "platform dispute shows a review for a lapsed ruling")
	if review != nil {
		require(p["resolution"] == "reconciliation_denied" && review["stage"] == "lapsed", "verification did not cite the recorded reconciliation review")
	}
}

func (r paidDispute) merchantStatus(expected int64) {
	query := r.d.epay("v2", "/api/pay/query", url.Values{"out_trade_no": {r.number}})
	require(query["out_trade_no"] == r.number && num(query, "status") == expected, "signed merchant query differs from the order")
	r.d.evidence("merchant_query_status", query["status"])
}

func (r paidDispute) resolved(status string) {
	r.awaitOrderStatus(status)
	row := oneFact(r.d.facts("payment", "dispute", "SELECT state FROM payment_disputes WHERE id=$1 AND order_id=$2", r.dispute, r.order), "payment dispute")
	require(row["state"] == "resolved", "payment did not resolve the dispute")
}

// Wait for the terminal ledger event itself. A zero quarantine count before
// payment has consumed the cancellation would also pass for a stalled reader.
func (r paidDispute) checkTradeInbox(outcome, ruling string) {
	d := r.d
	exec := oneFact(d.facts("ledger", "terminal_authorization", `SELECT result_event_id,result_status FROM ledger_trade_authorizations
		WHERE order_id=$1 AND ruling_id=$2`, r.order, ruling), "executed ruling")
	event := "TradeReleased"
	if outcome == "CANCELLED" {
		event = "TradeCancelled"
	}
	require(exec["result_status"] == outcome, "unexpected ledger authorization outcome")
	waitFor("payment to consume "+event, 2*time.Minute, func() bool {
		rows := d.facts("payment", "terminal_inbox", `SELECT status,quarantine_reason FROM payment_trade_inbox
			WHERE stream='ledger.trades' AND event_type=$1 AND event_id=$2`, event, str(exec, "result_event_id"))
		if len(rows) == 0 || rows[0]["status"] == "pending" {
			return false
		}
		require(rows[0]["status"] == "applied" || rows[0]["status"] == "ignored", "payment quarantined the terminal ledger event")
		return true
	})
	// The inbox stores a wire payload without an order_id column. Narrow by the
	// UUID bytes, then match the decoded trade. Keep payloads out of evidence.
	rows := d.rows("payment", "order cancellation inbox", `SELECT event_id,status,encode(payload,'hex') AS payload
		FROM payment_trade_inbox WHERE stream='ledger.trades' AND event_type='TradeCancelled'
		AND position(convert_to($1,'UTF8') in payload)>0`, r.order)
	var matches []string
	for _, row := range rows {
		wire, err := hex.DecodeString(str(row, "payload"))
		check(err)
		var cancel ledger.TradeCancelled
		check(proto.Unmarshal(wire, &cancel))
		if cancel.GetTrade().GetOrderId() == r.order {
			require(outcome == "CANCELLED" && row["event_id"] == exec["result_event_id"] && row["status"] != "quarantined",
				"unexpected TradeCancelled in the payment inbox for this order")
			matches = append(matches, str(row, "event_id"))
		}
	}
	require(outcome != "CANCELLED" || len(matches) == 1, "missing cancellation in the payment inbox")
	d.evidence("order_cancellation_inbox_ids", matches)
}

func (d *driver) runDisputePaidRelease() {
	r := d.openUnpaidDispute()
	s := r.step("Approve return and pay through the simulator", func() {
		ruling := r.approveRuling(returnToSeller, r.version)
		r.payA145Cashier()
		r.observation("fenced", "", ruling, time.Minute)
	})
	old := str(s.Evidence, "approval_id")
	r.step("Verify the reported denial and disputed payment", func() {
		review := r.reportedDenial(old)
		row := r.verified("reconciliation_denied", old)
		r.checkViews(row, review)
	})
	release := r.step("Approve release at the paid version", func() { r.approveRuling(releaseToRecipient, r.version+1) })
	r.release()
	r.step("Check the completed release", func() {
		r.resolved("completed")
		r.checkTradeInbox("RELEASED", str(release.Evidence, "approval_id"))
		r.merchantStatus(1)
	})
}

func (d *driver) runDisputePaidRefund() {
	r := d.openUnpaidDispute()
	r.step("Pay without a ruling and repeat the callback", func() {
		r.setScenario(object{"callback_copies": 2})
		r.payA145Cashier()
		verified := r.verified("no_ruling", "")
		// The simulator sends copies serially, after the previous callback returns.
		// The no-ruling callback processes verification before acknowledging it.
		r.observePaid(2)
		r.merchantStatus(1)
		replay := r.observation("verified", "no_ruling", "", time.Minute)
		require(replay["observed_at"] == verified["observed_at"] && replay["digest"] == verified["digest"] &&
			replay["resolved_at"] == verified["resolved_at"], "callback replay replaced the verified observation")
	})
	r.step("Refuse return after payment verification", func() { r.refuseRuling(returnToSeller, r.version+1, "") })
	refundRuling := r.step("Approve refund at the paid version", func() { r.approveRuling("refund", r.version+1) })
	ruling := str(refundRuling.Evidence, "approval_id")
	refund := r.checkRefundHandoff(false, r.dispute, ruling)
	r.manualRefund(refund)
	r.step("Check the pre-release refund and merchant receipt", func() {
		r.resolved("refunded")
		r.proveRefundExecution(false, r.dispute, ruling, refund)
		r.finish(false)
		reply := d.epay("v2", "/api/pay/refundquery", url.Values{"refund_no": {refund}})
		require(reply["refund_no"] == refund && reply["out_refund_no"] == "dispute:"+ruling && reply["money"] == r.amount,
			"signed refund query differs from the settled dispute refund")
		d.evidence("merchant_refund_query", object{"refund_id": refund, "code": reply["code"], "money": reply["money"]})
		r.observation("verified", "no_ruling", "", time.Minute)
	})
}

func (d *driver) withPausedMatches(run func()) {
	// A failed pause can already have stopped ledger or written its delay marker.
	defer d.stack("ledger-matches", "resume")
	d.stack("ledger-matches", "pause")
	run()
}

func requireLiveCancellation(deadline time.Time) {
	require(time.Now().Before(deadline), "cancellation authorization expired before ledger could consume it; the race needs a new unpaid order")
}

func (r paidDispute) raceBeforeResume(ruling string) {
	d := r.d
	configured := d.env("reconciliation")[lateWindowEnv]
	timing, _ := r.awaitFirstUnpaid(configured, 2*time.Minute)
	waitFor("signed cancellation for the approved return", max(2*time.Minute, timing.observationTimeout()), func() bool {
		rows := d.facts("reconciliation", "signed_cancellation", `SELECT a.authorization_id,a.issued_at,o.sequence FROM reconciliation_authorizations a
			JOIN reconciliation_outbox o ON o.event_id=a.authorization_id WHERE a.order_id=$1 AND a.ruling_id=$2
			AND a.control_version=$3 AND a.event_type='TradeCancellationAuthorized' AND o.stream='reconciliation.matches' AND o.signature IS NOT NULL`, r.order, ruling, r.version)
		return len(rows) == 1
	})
	auth := r.returnAuthorization(r.dispute, ruling, configured)
	require(auth.GetExpiresAt().IsValid(), "signed cancellation lacks a valid expiration")
	deadline := auth.GetExpiresAt().AsTime()
	d.evidence("authorization_expires_at", deadline)
	requireLiveCancellation(deadline)
	// Bound HTTP, SQL and any login wait while the reader is paused. Surface
	// the signed deadline even if an individual operation times out first at it.
	parent := d.ctx
	ctx, cancel := context.WithDeadline(parent, deadline)
	d.ctx = ctx
	defer func() {
		cancel()
		d.ctx = parent
		requireLiveCancellation(deadline)
	}()
	h := d.ledgerTrade(r.order)
	require(h["status"] == "DISPUTED" && num(h, "control_version") == r.version && h["paid_verified_at"] == nil,
		"ledger already executed the cancellation or changed the unpaid escrow")
	r.payA145Cashier()
	r.observation("fenced", "", ruling, min(time.Minute, time.Until(deadline)))
	r.refuseRuling(releaseToRecipient, r.version, ruling)
	r.refuseRuling("refund", r.version, ruling)
	r.refuseRuling(returnToSeller, r.version, ruling)
	r.noRulingReport(ruling)
}

func (r paidDispute) noRulingReport(ruling string) {
	rows := r.d.facts("reconciliation", "reports_for_authorized_ruling", rulingReportSQL, r.order, r.dispute, ruling, r.version)
	require(len(rows) == 0, "reconciliation reported a denial for an authorized return")
}

func (d *driver) runDisputePaidRace() {
	r := d.openUnpaidDispute()
	r.step("Backdate the unpaid simulator order", r.backdateUnpaid)
	s := r.step("Pause matches until the authorized return fences payment", func() {
		d.withPausedMatches(func() {
			ruling := r.approveRuling(returnToSeller, r.version)
			r.raceBeforeResume(ruling)
		})
	})
	ruling := str(s.Evidence, "approval_id")
	cancelled := r.step("Check cancellation and the linked late payment", func() {
		deadline := ledgerTime(normalized(s.Evidence), "authorization_expires_at")
		waitFor("ledger cancellation before the signed authorization expires", 2*time.Minute, func() bool {
			h := d.ledgerTrade(r.order)
			if h["status"] == "CANCELLED" {
				require(h["paid_verified_at"] == nil && units(h, "held_usdt_micro") == 0, "cancelled escrow retained a payment or hold")
				return true
			}
			requireLiveCancellation(deadline)
			return false
		})
		r.resolved("cancelled")
		row := r.observation("late_payment", "ledger_cancelled", ruling, 2*time.Minute)
		late := str(row, "late_payment_id")
		owner := oneFact(d.facts("payment", "late_payment", `SELECT id,dispute_id,status,detected_at FROM payment_late_payments
			WHERE order_id=$1 AND id=$2`, r.order, late), "dispute late payment")
		require(owner["dispute_id"] == r.dispute && num(owner, "status") == 1 && sameInstant(owner["detected_at"], row["observed_at"]),
			"late payment does not reference the fenced observation in AWAITING_SELLER")
		detail := d.browser("operations").api("GET", latePaymentSubject(late).path(), "", nil)
		require(detail["late_payment_id"] == late && obj(detail["trade"])["order_id"] == r.order && detail["dispute_id"] == r.dispute &&
			detail["status"] == "awaiting_seller", "platform late payment lost the order, dispute or seller task")
		r.noRulingReport(ruling)
		r.checkTradeInbox("CANCELLED", ruling)
		r.merchantStatus(0)
		_, closeReply := d.signedEPay("v2", "/api/pay/close", url.Values{"out_trade_no": {r.number}})
		require(num(closeReply, "code") == -1, "merchant close succeeded on the cancelled order")
		d.evidence("late_payment_id", late)
	})
	subject := latePaymentSubject(str(cancelled.Evidence, "late_payment_id"))
	r.step("Submit seller evidence for the late payment", func() {
		e := r.evidenceVersion(subject, 1)
		d.evidence("evidence_id", str(e, "evidence_id"))
	})
	r.step("Close the late payment with two reviewers", func() {
		r.approveSellerEvidence(subject)
		seller := d.browser("seller").api("GET", "/accounts/"+d.required("seller-account")+subject.path(), "", nil)
		require(seller["late_payment_id"] == subject.id && seller["order_id"] == r.order &&
			seller["status"] == "closed" && obj(seller["evidence"])["status"] == "approved", "late payment did not close on the reviewed evidence")
		r.resolved("cancelled")
		r.observation("late_payment", "ledger_cancelled", ruling, time.Minute)
		r.finish(false)
		d.evidence("late_payment_status", seller["status"])
	})
}
