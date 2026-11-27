package main

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"
)

const lateWindowEnv = "AIPAY_RECONCILIATION_LATE_PAYMENT_WINDOW"

type latePaymentTiming struct {
	observed, deadline time.Time
	window, margin     time.Duration
	source             string
}

func lateWindowTiming(observed time.Time, pinned any, configured string) (latePaymentTiming, error) {
	window, source := 30*time.Minute, "default"
	switch {
	case pinned != nil:
		seconds, err := strconv.ParseInt(fmt.Sprint(pinned), 10, 64)
		if err != nil || seconds < 1 || seconds > 3600 {
			return latePaymentTiming{}, errors.New("pinned late_payment_window_seconds must be an integer from 1 to 3600")
		}
		window, source = time.Duration(seconds)*time.Second, "pinned"
	case configured != "":
		duration, err := time.ParseDuration(configured)
		if err != nil || duration <= 0 {
			return latePaymentTiming{}, errors.New(lateWindowEnv + " must be a positive Go duration")
		}
		window, source = duration, "configured"
	}
	margin := min(10*time.Second, window/2)
	return latePaymentTiming{observed: observed, deadline: observed.Add(window - margin), window: window, margin: margin, source: source}, nil
}

func (t latePaymentTiming) checkDeadline(now time.Time) error {
	if !now.Before(t.deadline) {
		return fmt.Errorf("late-payment window already closed (observed %s, window %s, margin %s, deadline %s)",
			t.observed.Format(time.RFC3339Nano), t.window, t.margin, t.deadline.Format(time.RFC3339Nano))
	}
	return nil
}

func (t latePaymentTiming) observationTimeout() time.Duration {
	return min(t.window, time.Duration(math.MaxInt64)-time.Minute) + time.Minute
}

func (d *driver) latePayment() {
	t := d.refundTrade("取消后迟付", "v2")
	t.step("关闭上游订单", func() {
		require(t.channel == md5Channel, "late-payment requires the form-md5 cashier")
		t.setScenario(object{"late_payment": true})
		d.epay("v2", "/api/pay/close", url.Values{"out_trade_no": {t.number}})
	})
	cancelled := t.step("平台取消并归还原担保", func() {
		hold, _ := t.awaitUnpaidCancellation(d.env("reconciliation")[lateWindowEnv])
		order := t.awaitOrderStatus("cancelled")
		require(order["escrow_status"] == "cancelled" && units(hold, "held_usdt_micro") == 0, "escrow is still held")
		d.evidence("cancelled_seq", hold["latest_seq"])
		d.evidence("cancelled_version", hold["control_version"])
		t.finish(false)
	})
	t.completeLatePayment(cancelled, "")
}

func (t tradeRun) completeLatePayment(cancelled *result, approvalID string) {
	d := t.d
	t.step("取消后收银付款", func() {
		if approvalID != "" {
			t.payA145Cashier()
		} else {
			d.cashier(t.link, true)
		}
	})
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
	if approvalID != "" {
		t.checkLateForcedClose(s.id, approvalID)
	}
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
