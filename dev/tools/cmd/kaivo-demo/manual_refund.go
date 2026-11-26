package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"image"
	"image/png"
	"net/url"
	"time"
)

// manualRefund resumes a previously created refund using only its owner IDs.
// The returned posting locates the seller credit relative to a balance snapshot.
func (t tradeRun) manualRefund(refund string) object {
	d := t.d
	account := d.required("seller-account")
	base := "/accounts/" + account + "/refunds"
	seller := d.browser("seller")
	label := "人工退款 " + refund
	d.liveStep(label+" 卖方凭证", func() {
		d.login("seller")
		var row object
		waitFor("seller refund reservation", time.Minute, func() bool {
			row = t.listedRefund(base, refund)
			return row != nil && row["status"] != "reserving"
		})
		d.evidence("order_id", t.order)
		d.evidence("starting_status", row["status"])
		switch row["status"] {
		case "awaiting_review", "confirming", "succeeded":
			return
		case "awaiting_seller":
			detail := seller.api("GET", base+"/"+refund, "", nil)
			require(detail["refund_id"] == refund && detail["order_id"] == t.order, "seller refund detail mismatch")
			e := t.submitRefundEvidence(base+"/"+refund, refund, detail)
			d.evidence("evidence_id", str(e, "evidence_id"))
		default:
			stop("refund %s cannot submit evidence in state %v", refund, row["status"])
		}
	})

	var approvalID, digest string
	d.liveStep(label+" 双人复核", func() {
		d.login(approvers[0])
		review := d.browser(approvers[0]).api("GET", "/refunds/"+refund+"/review", "", nil)
		r := obj(review["approval"])
		m := obj(r["material"])
		op := obj(m["seller_refund"])
		trade := obj(op["trade"])
		current := obj(review["refund"])
		require(m["kind"] == "seller_refund" && obj(op["subject"])["refund_id"] == refund &&
			trade["order_id"] == t.order && trade["seller_account_id"] == account && current["refund_id"] == refund &&
			str(op, "out_refund_no") == current["out_refund_no"] && matchesProposal(obj(op["refunded_amount"]), obj(current["fiat_amount"])), "wrong seller refund approval")
		d.evidence("out_refund_no", current["out_refund_no"])
		history, ok := review["evidence"].([]any)
		require(ok && len(history) > 0, "missing seller refund evidence")
		e := obj(history[len(history)-1])
		require(e["evidence_id"] == op["evidence_id"] && e["evidence_sha256"] == op["evidence_sha256"] &&
			e["version"] == op["evidence_version"] && obj(e["subject"])["refund_id"] == refund, "approval is not for the current evidence")
		header := obj(r["approval_request"])
		approvalID, digest = str(header, "id"), str(header, "request_digest")
		d.approveExisting("seller-refund/"+approvalID, "payment", str(e, "submitted_by"), "/seller-refund-reviews", r)
	})

	var posting object
	d.liveStep(label+" 异议期与入账", func() {
		state := func() object {
			return oneFact(d.rows("payment", "payment_refunds", `SELECT status,data->>'objection_deadline' AS deadline,
				data->>'verified_at' AS verified_at FROM payment_refunds WHERE id=$1 AND order_id=$2`, refund, t.order), "payment refund")
		}
		row := state()
		require(num(row, "status") == 8 || num(row, "status") == 3, "approved refund is not confirming or succeeded")
		deadline, err := time.Parse(time.RFC3339Nano, str(row, "deadline"))
		check(err)
		d.evidence("objection_deadline", deadline)
		if delay := time.Until(deadline); delay > 0 {
			d.sleep(delay)
		}
		waitFor("payment refund SUCCEEDED", 2*time.Minute, func() bool {
			row = state()
			require(num(row, "status") == 8 || num(row, "status") == 3, "refund left confirmation without success")
			return num(row, "status") == 3
		})
		verified, err := time.Parse(time.RFC3339Nano, str(row, "verified_at"))
		check(err)
		require(!verified.Before(deadline), "payment succeeded before objection deadline")
		var resolution object
		waitFor("manual refund resolution", 2*time.Minute, func() bool {
			rows := d.rows("reconciliation", "reconciliation_manual_refund_resolutions", `SELECT s.event_id AS resolution_id,s.outcome,
				s.approval_request_id,encode(s.request_digest,'hex') AS request_digest,s.authorization_id,a.event_type
				FROM reconciliation_manual_refund_reviews m JOIN reconciliation_manual_refund_resolutions s USING(event_id)
				LEFT JOIN reconciliation_authorizations a ON a.authorization_id=s.authorization_id AND a.order_id=m.order_id
				WHERE m.order_id=$1 AND m.refund_id=$2`, t.order, refund)
			if len(rows) == 0 {
				return false
			}
			resolution = oneFact(rows, "manual refund resolution")
			d.evidence("resolution", resolution)
			require(resolution["outcome"] == "authorized" && resolution["approval_request_id"] == approvalID &&
				resolution["request_digest"] == fmt.Sprintf("%x", raw(digest)) && resolution["event_type"] == "TradeRefundAuthorized", "manual refund resolution or authorization mismatch")
			return true
		})
		d.login("seller")
		d.login("operations")
		h := t.terminal("REFUNDED")
		posting = oneFact(d.rows("ledger", "ledger_trade_authorizations", `SELECT a.posting_seq,r.branch,r.reserved_usdt FROM ledger_trade_authorizations a
			JOIN ledger_trade_refunds r USING (order_id,refund_id,refund_reservation_id)
			WHERE a.authorization_id=$1 AND a.order_id=$2 AND a.refund_id=$3 AND a.result_status='REFUNDED' AND a.event_type='TradeRefundAuthorized'`,
			str(resolution, "authorization_id"), t.order, refund), "ledger refund posting")
		require(units(h, "held_usdt_micro") == 0 && num(posting, "posting_seq") == num(h, "latest_seq"), "refund hold was not cleared by the authorization")
		q := num(h, "escrow_usdt")
		reserve := num(posting, "reserved_usdt")
		require(posting["branch"] == "PRE_RELEASE" && reserve == q || posting["branch"] == "POST_RELEASE" && reserve == num(h, "recipient_usdt"), "refund reservation amount mismatch")
		posting["seller_credit"] = h["escrow_usdt"]
		d.evidence("ledger_posting", posting)
	})
	return posting
}

func (t tradeRun) submitRefundEvidence(path, refund string, detail object) object {
	d := t.d
	seller := d.browser("seller")
	var version int64
	if detail["evidence"] != nil {
		version = num(obj(detail["evidence"]), "version")
	}
	money := obj(detail["fiat_amount"])
	cents := units(money, "amount_minor")
	require(money["currency"] == "CNY" && cents > 0, "expected positive CNY refund")
	key := fmt.Sprintf("manual-refund/%s/evidence/%d", refund, version)
	when := d.value(key+"/time", func() string {
		return time.Now().In(time.FixedZone("UTC+8", 8*3600)).Truncate(time.Microsecond).Format(time.RFC3339Nano)
	})
	body := object{"expected_evidence_version": version, "upstream_refund_no": "demo:" + t.order,
		"refunded_at": when, "money": fmt.Sprintf("%d.%02d", cents/100, cents%100),
		"files": []object{{"content_type": "image/png", "data": refundPNG(refund)}}}
	c := portalCommand{path: path + "/process", template: "/accounts/:seller_account_id/refunds/:id/process",
		permission: "payment.refund.process", key: d.key(key), body: body}
	e := seller.submitRecent(c)
	require(obj(e["subject"])["refund_id"] == refund && num(e, "version") == version+1, "seller evidence version or refund mismatch")
	return e
}

func (t tradeRun) listedRefund(base, refund string) object {
	seen := map[string]bool{}
	query := url.Values{"order_id": {t.order}, "limit": {"100"}}
	for {
		page := t.d.browser("seller").api("GET", base+"?"+query.Encode(), "", nil)
		rows, ok := page["items"].([]any)
		require(ok, "missing seller refunds list")
		for _, item := range rows {
			row := obj(item)
			if row["refund_id"] == refund {
				require(row["order_id"] == t.order && row["seller_account_id"] == t.d.required("seller-account"), "seller refund scope mismatch")
				return row
			}
		}
		cursor, _ := page["next_cursor"].(string)
		if cursor == "" {
			return nil
		}
		require(!seen[cursor], "repeated seller refund cursor")
		seen[cursor] = true
		query.Set("cursor", cursor)
	}
}

func refundPNG(refund string) []byte {
	// A repeatable demo image per refund also keeps unrelated evidence distinct.
	digest := sha256.Sum256([]byte(refund))
	img := image.NewGray(image.Rect(0, 0, 32, 32))
	for i := range img.Pix {
		img.Pix[i] = digest[(i/32+i%32)%len(digest)]
	}
	var b bytes.Buffer
	check(png.Encode(&b, img))
	return b.Bytes()
}
