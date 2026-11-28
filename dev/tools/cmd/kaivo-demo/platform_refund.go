package main

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"google.golang.org/protobuf/proto"
)

func platformRefundCommand(order, escrow, key, reason string, version int64) portalCommand {
	b := appendField(appendField(commandPrefix("PaymentAdminService/CreatePlatformRefund", key), order), escrow)
	b = binary.BigEndian.AppendUint64(b, uint64(version))
	return portalCommand{"/orders/" + order + "/refunds", "/orders/:order_id/refunds", "payment.refund.initiate", key,
		object{"escrow_reservation_id": escrow, "expected_control_version": version, "reason": reason}, sha256.Sum256(appendField(b, reason))}
}

func (t tradeRun) platformRefund(branch string) string {
	d := t.d
	step := t.step("运营发起人工退款", func() {
		stateKey := "platform-refund/" + t.order
		var hold object
		if !d.read(stateKey+"/hold", &hold) {
			hold = d.ledgerTrade(t.order)
			require(branch == "PRE_RELEASE" && hold["status"] == "RESERVED" || branch == "POST_RELEASE" && hold["status"] == "RELEASED", "wrong trade state for platform refund")
			d.put(stateKey+"/hold", hold)
		}
		c := platformRefundCommand(t.order, str(hold, "escrow_reservation_id"), d.key(stateKey), "平台核对原单后发起全额退款", num(hold, "control_version"))
		b := d.browser("operations")
		r := b.apiGrant("POST", c.path, c.key, c.body, b.grant(c))
		refund := str(r, "refund_id")
		require(obj(r["trade"])["order_id"] == t.order && r["origin"] == "platform" && r["out_refund_no"] == "platform:"+refund, "platform refund receipt mismatch")
		d.waitFor("platform refund awaiting seller", time.Minute, func() bool {
			row := d.browser("seller").api("GET", "/accounts/"+d.required("seller-account")+"/refunds/"+refund, "", nil)
			return row["order_id"] == t.order && row["status"] == "awaiting_seller"
		})
		reserve := oneFact(t.reservations(), "platform refund reservation")
		amount := num(hold, "escrow_usdt")
		if branch == "POST_RELEASE" {
			amount = num(hold, "recipient_usdt")
		}
		require(reserve["refund_id"] == refund && reserve["branch"] == branch && num(reserve, "reserved_usdt") == amount, "wrong platform refund reservation")
		d.evidence("refund_id", refund)
	})
	return str(step.Evidence, "refund_id")
}

func (t tradeRun) noUpstreamRefund() {
	calls := t.d.facts("payment", "上游退款调用", `SELECT operation FROM payment_plugin_executions WHERE order_id=$1 AND operation IN ('refund','query_refund')
		UNION ALL SELECT operation FROM payment_gateway_executions WHERE order_id=$1 AND operation IN ('refund','query_refund')`, t.order)
	require(len(calls) == 0, "unexpected upstream refund operation")
}

// Recover an accepted upload if the response or the step checkpoint was lost.
func (t tradeRun) evidenceVersion(s reviewSubject, version int64) object {
	d := t.d
	d.login("seller")
	row := d.browser("seller").api("GET", "/accounts/"+d.required("seller-account")+s.path(), "", nil)
	require(row["order_id"] == t.order && row[s.kind+"_id"] == s.id, "wrong seller evidence subject")
	if row["status"] == "awaiting_seller" {
		var current int64
		if row["evidence"] != nil {
			current = num(obj(row["evidence"]), "version")
		}
		require(current == version-1, "unexpected prior seller evidence version")
		return t.submitRefundEvidence(s, row)
	}
	e := obj(row["evidence"])
	require(row["status"] == "awaiting_review" && num(e, "version") == version && obj(e["subject"])[s.kind+"_id"] == s.id, "unexpected submitted evidence")
	return e
}

func (d *driver) platformRefundSuccess() {
	t := d.refundTrade("平台退款", "v2")
	t.paid(1)
	released := t.release()
	t.step("放币订单已完成", func() { t.awaitOrderStatus("completed") })
	refund := t.platformRefund("POST_RELEASE")
	s := refundSubject(refund)
	first := t.step("卖方提交首版凭证", func() {
		e := t.evidenceVersion(s, 1)
		d.evidence("evidence_id", str(e, "evidence_id"))
	})
	firstID := str(first.Evidence, "evidence_id")
	t.step("卖方监听隔离", func() {
		d.login(approvers[0])
		view := d.browser(approvers[0]).api("GET", s.path()+"/review", "", nil)
		req := obj(obj(view["approval"])["approval_request"])
		seller := d.browser("seller")
		path := "/api/v1/platform" + s.path() + "/review"
		status, _ := seller.http("GET", path, path, "", nil, nil)
		require(status == 404, "platform review reachable on seller listener")
		path = "/api/v1/platform/seller-refund-reviews/approvals/" + str(req, "id") + "/assertions"
		status, _ = seller.http("POST", path, path, "application/json", encoded(object{}), nil)
		require(status == 404, "platform approval reachable on seller listener")
	})
	t.step("复核人驳回首版凭证", func() {
		d.login(approvers[0])
		d.browser(approvers[0]).write("reject/"+firstID, "/seller-refund-evidence/"+firstID+"/rejection", func() object {
			return object{"expected_evidence_version": 1, "reason": "请补充清晰的退款凭证"}
		})
		view := d.browser("seller").api("GET", "/accounts/"+d.required("seller-account")+s.path(), "", nil)
		e := obj(view["evidence"])
		require(view["status"] == "awaiting_seller" && e["evidence_id"] == firstID && e["status"] == "rejected", "first evidence was not rejected")
	})
	second := t.step("卖方重新提交第二版凭证", func() {
		e := t.evidenceVersion(s, 2)
		require(str(e, "evidence_id") != firstID, "rejected evidence reused")
		d.evidence("evidence_id", e["evidence_id"])
	})
	post := t.manualRefund(refund)
	t.step("核对核销、三项费用与卖方返还", func() {
		d.login(approvers[0])
		view := d.browser(approvers[0]).api("GET", s.path()+"/review", "", nil)
		r := obj(obj(view["approval"])["material"])
		op := obj(r["seller_refund"])
		require(op["evidence_id"] == second.Evidence["evidence_id"] && num(op, "evidence_version") == 2, "settled approval differs from resubmission")
		h := d.ledgerTrade(t.order)
		end := t.finish(false)
		checkBalanceDelta(released, end, num(h, "escrow_usdt"), -num(h, "recipient_usdt"), -num(h, "platform_fee_usdt"))
		// Compare each fee account's release credit with its refund debit, including zero fees.
		fees := d.facts("ledger", "逐项费用冲回", `SELECT a.code,
			coalesce(sum(l.units) FILTER (WHERE l.seq=$1 AND l.direction='C'),0)::bigint AS released,
			coalesce(sum(l.units) FILTER (WHERE l.seq=$2 AND l.direction='D'),0)::bigint AS reversed
			FROM ledger_accounts a LEFT JOIN ledger_lines l ON l.account_id=a.id AND l.seq IN ($1,$2)
			WHERE a.code IN ('merchant_trade_fee_revenue:USDT','channel_trade_fee_revenue:USDT','trade_spread_revenue:USDT') GROUP BY a.code ORDER BY a.code`,
			num(h, "released_seq"), num(post, "posting_seq"))
		var total int64
		for _, f := range fees {
			require(f["released"] == f["reversed"], "fee reversal mismatch: "+str(f, "code"))
			total += num(f, "reversed")
		}
		require(total == num(h, "platform_fee_usdt"), "incomplete fee reversal")
		t.noUpstreamRefund()
		t.awaitOrderStatus("refunded")
		d.waitFor("seller pending and merchant succeeded notices", time.Minute, func() bool {
			notices := t.refundNotices(refund)
			return notices["seller_pending"] != nil && notices["merchant_succeeded"] != nil
		})
	})
}

// payment syncs a ledger cancellation on its next order poll. Under A140 an
// unpaid order may be polled only every 10 minutes from creation, so a
// cancellation needs a longer wait than the other transitions.
func (t tradeRun) awaitOrderStatus(status string) object {
	timeout := 2 * time.Minute
	if status == "cancelled" {
		timeout = 12 * time.Minute
	}
	var order object
	t.d.waitFor("payment order "+status, timeout, func() bool {
		order = t.d.browser("operations").api("GET", "/orders/"+t.order, "", nil)
		return order["status"] == status
	})
	t.d.evidence("order_status", status)
	return order
}

// The seller can receive another pending notice after rejection. Match both
// audiences to this refund and keep only public outbox references in the report.
func (t tradeRun) refundNotices(refund string) map[string]object {
	d := t.d
	rows := d.rows("payment", "refund notices", `SELECT event_id,event_type,sequence,sequenced_at,encode(payload,'base64') AS notice
		FROM payment_outbox WHERE refund_notice_order_id=$1 AND stream='payment.account_notices' AND sequence IS NOT NULL
		ORDER BY sequence`, t.order)
	seen := map[string]object{}
	for _, r := range rows {
		proof := object{"event_id": r["event_id"], "sequence": r["sequence"], "sequenced_at": r["sequenced_at"]}
		switch r["event_type"] {
		case "SellerRefundNotice":
			var m pay.SellerRefundNotice
			check(proto.Unmarshal(standard(str(r, "notice")), &m))
			if m.OrderId == t.order && m.SellerAccountId == d.required("seller-account") && m.Subject.GetRefundId() == refund && m.Kind == pay.SellerRefundNoticeKind_SELLER_REFUND_NOTICE_KIND_PENDING {
				seen["seller_pending"] = proof
			}
		case "MerchantRefundNotice":
			var m pay.MerchantRefundNotice
			check(proto.Unmarshal(standard(str(r, "notice")), &m))
			if m.OrderId == t.order && m.AccountId == d.required("merchant-account") && m.OutRefundNo == "platform:"+refund {
				switch m.Kind {
				case pay.MerchantRefundNoticeKind_MERCHANT_REFUND_NOTICE_KIND_SUCCEEDED:
					seen["merchant_succeeded"] = proof
				case pay.MerchantRefundNoticeKind_MERCHANT_REFUND_NOTICE_KIND_FAILED:
					seen["merchant_failed"] = proof
				}
			}
		}
	}
	d.evidence("refund_notice_events", seen)
	return seen
}

func (t tradeRun) restoredOrder(refund string, reservationVersion int64) {
	d := t.d
	d.waitFor("payment restored RISK_HELD", 2*time.Minute, func() bool {
		o := d.browser("operations").api("GET", "/orders/"+t.order, "", nil)
		switch o["status"] {
		case "refunding":
			return false
		case "risk_held":
			require(o["escrow_status"] == "reserved" && num(o, "control_version") == reservationVersion+1, "order does not reflect the restored escrow")
			d.evidence("restored_order", object{"status": o["status"], "escrow_status": o["escrow_status"], "control_version": o["control_version"]})
		case "releasing", "completed":
			// On the native stack both databases share a clock. Payment emits the
			// FAILED notice only on projecting RESERVED or RELEASED. If already
			// sequenced before the only release, its projection had to be RISK_HELD.
			require(d.native(), "order already released before RISK_HELD was observed")
			notice := t.refundNotices(refund)["merchant_failed"]
			if notice == nil {
				return false
			}
			release := oneFact(d.facts("ledger", "恢复后的放币授权", `SELECT expected_version,executed_at FROM ledger_trade_authorizations
				WHERE order_id=$1 AND event_type='TradeReleaseAuthorized'`, t.order), "release after restoration")
			sequenced, err := time.Parse(time.RFC3339Nano, str(notice, "sequenced_at"))
			check(err)
			executed, err := time.Parse(time.RFC3339Nano, str(release, "executed_at"))
			check(err)
			require(num(release, "expected_version") == reservationVersion+1 && sequenced.Before(executed), "missing evidence that payment projected the failed refund before release")
		default:
			stop("unexpected order state after failed refund: %v", o["status"])
		}
		return true
	})
}

func (d *driver) platformRefundFailure() {
	t := d.refundTrade("平台判定失败", "v2")
	t.paid(1)
	refund := t.platformRefund("PRE_RELEASE")
	step := t.step("风控发起失败请求与双人审批", func() {
		d.login("risk")
		const reason = "卖方未能完成原单退款"
		r := d.browser("risk").write("failure/"+refund, "/refunds/"+refund+"/failure-requests", func() object { return object{"reason": reason} })
		m := obj(r["material"])
		op := obj(m["seller_refund_failure"])
		requester := d.required("user/risk")
		require(m["kind"] == "seller_refund_failure" && obj(op["subject"])["refund_id"] == refund && obj(op["trade"])["order_id"] == t.order &&
			op["branch"] == "pre_release" && op["reason"] == reason && op["evidence_id"] == nil, "failure request material mismatch")
		for _, person := range approvers {
			d.login(person)
			require(d.required("user/"+person) != requester, "failure requester cannot approve")
		}
		d.approveExisting("failure/"+refund, "payment", requester, "/seller-refund-failures", r)
		d.evidence("requested_by", requester)
		d.evidence("reservation_control_version", op["reservation_control_version"])
	})
	t.step("订单恢复风控冻结", func() {
		t.restoredOrder(refund, num(step.Evidence, "reservation_control_version"))
	})
	t.step("人工失败授权恢复原担保", func() {
		r := t.awaitRefundResolution(refund, str(step.Evidence, "approval_id"), str(step.Evidence, "request_digest"))
		event := oneFact(d.facts("payment", "RefundFailed v2", `SELECT o.event_id,o.schema_version,f.status FROM payment_outbox o JOIN payment_refunds f ON o.refund_id=f.id
			WHERE o.order_id=$1 AND o.refund_id=$2 AND o.event_type='RefundFailed'`, t.order, refund), "failed refund")
		require(num(event, "status") == 4 && num(event, "schema_version") == 2 && event["event_id"] == r["resolution_id"], "resolution did not authorize this failure")
		d.waitFor("ledger restored RESERVED", 2*time.Minute, func() bool {
			rows := d.facts("ledger", "失败恢复授权", `SELECT result_status,posting_seq,outcome FROM ledger_trade_authorizations
				WHERE authorization_id=$1 AND refund_id=$2 AND order_id=$3 AND event_type='TradeRefundAuthorized'`, str(r, "authorization_id"), refund, t.order)
			if len(rows) == 0 {
				return false
			}
			restore := oneFact(rows, "failed pre-release authorization")
			require(restore["outcome"] == "REFUND_VERIFICATION_OUTCOME_FAILED" && restore["result_status"] == "RESERVED" && restore["posting_seq"] == nil, "failed pre-release refund changed funds")
			return true
		})
		t.noUpstreamRefund()
	})
	t.release()
}
