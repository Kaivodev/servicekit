package main

import (
	"net/url"
	"time"
)

func (d *driver) latePayment() {
	t := d.refundTrade("取消后迟付", "v2")
	t.step("关闭上游订单", func() {
		require(t.channel == md5Channel, "late-payment requires the form-md5 cashier")
		t.setScenario(object{"late_payment": true})
		d.epay("v2", "/api/pay/close", url.Values{"out_trade_no": {t.number}})
	})
	cancelled := t.step("平台取消并归还原担保", func() {
		hold := t.terminal("CANCELLED")
		order := t.awaitOrderStatus("cancelled")
		require(order["escrow_status"] == "cancelled" && units(hold, "held_usdt_micro") == 0, "escrow is still held")
		d.evidence("cancelled_seq", hold["latest_seq"])
		d.evidence("cancelled_version", hold["control_version"])
		t.finish(false)
	})
	t.step("取消后收银付款", func() { d.cashier(t.link, true) })
	detected := t.step("主动查单登记迟到付款", func() {
		waitFor("late payment from active query", 2*time.Minute, func() bool {
			rows := d.rows("payment", "payment_late_payments", `SELECT l.id,l.upstream_order_id,encode(l.query_evidence_sha256,'hex') AS digest,l.detected_at
				FROM payment_late_payments l JOIN payment_orders o ON o.id=l.order_id AND o.upstream_order_id=l.upstream_order_id
				WHERE l.order_id=$1 AND o.status=7 AND (
					EXISTS (SELECT FROM payment_gateway_executions e WHERE e.order_id=l.order_id AND e.operation='query_payment' AND e.category='succeeded' AND e.evidence_sha256=l.query_evidence_sha256)
					OR EXISTS (SELECT FROM payment_plugin_executions e WHERE e.order_id=l.order_id AND e.operation='query_payment' AND e.category='completed' AND e.evidence_sha256=l.query_evidence_sha256))`, t.order)
			if len(rows) == 0 {
				return false
			}
			row := oneFact(rows, "late payment")
			d.evidence("active_query", row)
			d.evidence("late_payment_id", str(row, "id"))
			return true
		})
	})
	s := latePaymentSubject(str(detected.Evidence, "late_payment_id"))
	t.step("卖方提交迟付退款凭证", func() {
		e := t.evidenceVersion(s, 1)
		d.evidence("evidence_id", str(e, "evidence_id"))
	})
	t.step("双人复核并结案", func() {
		t.approveSellerEvidence(s)
		detail := d.browser("seller").api("GET", "/accounts/"+d.required("seller-account")+s.path(), "", nil)
		require(detail["status"] == "closed" && detail["order_id"] == t.order && obj(detail["evidence"])["status"] == "approved", "late payment did not close on approval")
		d.evidence("late_payment_status", detail["status"])
	})
	t.step("核对原单与账本", func() {
		t.awaitOrderStatus("cancelled")
		h := d.chainEvidence(t.order)
		require(h["status"] == "CANCELLED" && h["control_version"] == cancelled.Evidence["cancelled_version"] &&
			h["latest_seq"] == cancelled.Evidence["cancelled_seq"] && h["paid_verified_at"] == nil, "late payment changed the cancelled escrow")
		events := d.facts("payment", "迟付后的资金事件", `SELECT event_id FROM payment_outbox WHERE order_id=$1 AND event_type IN ('OrderPaid','RefundSucceeded','RefundFailed')`, t.order)
		require(len(events) == 0, "late payment emitted a financial event")
		auth := oneFact(d.facts("ledger", "本单执行授权", "SELECT event_type,posting_seq FROM ledger_trade_authorizations WHERE order_id=$1", t.order), "cancellation authorization")
		require(auth["event_type"] == "TradeCancellationAuthorized" && auth["posting_seq"] == h["latest_seq"], "unexpected late payment authorization")
		t.finish(false)
	})
}
