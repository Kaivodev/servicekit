package main

import (
	"fmt"
	"strings"
	"time"
)

func accountNoticeText(s string) bool {
	return strings.HasPrefix(s, "已收款\n") || strings.HasPrefix(s, "资金已可用\n") || strings.HasPrefix(s, "收款方式 ") && strings.Contains(s, " 审核结果：")
}

func (d *driver) ensureGroup() {
	d.liveStep("核对本人群绑定", func() {
		bindings := func() []object {
			return d.rows("iam", "iam_group_bindings", `SELECT account_id,telegram_user_id,group_chat_id FROM iam_group_bindings
            WHERE account_id=$1 AND telegram_user_id=$2 AND group_chat_id=$3 AND invalidated_at IS NULL`, d.required("merchant-account"), merchantUser, demoGroup)
		}
		rows := bindings()
		if len(rows) == 0 {
			challenge := d.telegram("bind-group/"+id(), demoGroup, func() string { return "/bind_group" })
			require(challenge.Chat == merchantUser, "group confirmation was not private")
			token := capture(`^请在本人私聊确认群绑定：\n/confirm_group (\S+)$`, challenge.Text)
			require(d.bot("confirm-group/"+id(), "/confirm_group "+token) == "群绑定已完成", "group binding was not confirmed")
			rows = bindings()
		}
		d.evidence("binding", oneFact(rows, "IAM 群绑定"))
	})
}

func noticeCopies(messages []message, heading, trade, number, expected string) map[int64]int64 {
	copies := map[int64]int64{}
	for _, m := range messages {
		if !strings.HasPrefix(m.Text, heading+"\n") || !(strings.Contains(m.Text, trade) || strings.Contains(m.Text, number)) {
			continue
		}
		require(m.Chat == merchantUser || m.Chat == demoGroup, "notice sent to unexpected chat")
		require(m.Text == expected && !m.Deleted && m.Document == nil, "notice differs from original order")
		require(copies[m.Chat] == 0, "duplicate account notice for this order and chat")
		copies[m.Chat] = m.ID
	}
	return copies
}

func (d *driver) deliveries(event object) []object {
	return d.rows("backend", "telegram_notice_deliveries", `SELECT d.event_id,i.sequence,i.event_type,d.chat_id,d.status,d.attempts FROM telegram_notice_deliveries d
        JOIN telegram_notice_inbox i USING(event_id) WHERE i.stream='payment.account_notices' AND i.event_id=$1 AND i.sequence=$2
        AND i.event_type=$3 AND i.status='applied' ORDER BY chat_id`, str(event, "event_id"), num(event, "sequence"), str(event, "event_type"))
}

func sentToBoth(rows []object) bool {
	seen := map[int64]bool{}
	for _, r := range rows {
		chat := num(r, "chat_id")
		require((chat == demoGroup || chat == merchantUser) && !seen[chat], "unexpected or duplicate delivery destination")
		seen[chat] = true
		if r["status"] == "pending" {
			return false
		}
		require(r["status"] == "sent" && num(r, "attempts") > 0, "notice delivery ended without sending")
	}
	return len(seen) == 2
}

func (t tradeRun) notice(kind, heading, expected string) {
	d := t.d
	trade := d.required("trade-no/" + d.scope + "/" + t.name)
	d.waitFor(heading+"在私聊和群各投递一次", time.Minute, func() bool {
		events := d.facts("payment", kind+"_outbox", `SELECT event_id,sequence,event_type FROM payment_outbox
            WHERE stream='payment.account_notices' AND order_id=$1 AND event_type=$2`, t.order, kind)
		if len(events) == 0 {
			return false
		}
		event := oneFact(events, kind)
		if event["sequence"] == nil {
			return false
		} // inserted, awaiting the payment sequencer
		rows := d.deliveries(event)
		d.evidence(kind+"_deliveries", rows)
		copies := noticeCopies(d.messages(), heading, trade, t.number, expected)
		d.evidence(kind+"_message_ids", copies)
		if !sentToBoth(rows) || len(copies) != 2 {
			return false
		}
		d.evidence(kind+"_text", expected)
		return true
	})
}

func (d *driver) botNotices() {
	d.ensureGroup()
	t := d.trade("通知", "v2")
	t.paid(1)
	trade := d.required("trade-no/" + d.scope + "/" + t.name)
	paid := fmt.Sprintf("已收款\n平台单号 %s\n商户单号 %s\n金额 %s CNY", trade, t.number, t.amount)
	t.step("已收款双投递", func() { t.notice("MerchantPaymentReceived", "已收款", paid) })
	t.release()
	t.step("资金已可用双投递", func() {
		n := num(d.ledgerTrade(t.order), "recipient_usdt")
		available := fmt.Sprintf("资金已可用\n平台单号 %s\n商户所得 %d.%06d USDT", trade, n/1_000_000, n%1_000_000)
		t.notice("MerchantFundsAvailable", "资金已可用", available)
		// Re-count the first event after release to catch later duplicates too.
		t.notice("MerchantPaymentReceived", "已收款", paid)
	})
	d.step("开通时的审核通知", func() {
		d.waitFor("开通审核推送记录", time.Minute, func() bool {
			events := d.facts("payment", "review_events", `SELECT o.event_id,o.sequence,o.event_type FROM payment_outbox o JOIN payment_access_changes a ON a.audit_id=o.review_audit_id
                WHERE o.stream='payment.account_notices' AND o.event_type='PaymentAccessReviewed' AND a.access_id=$1 ORDER BY o.sequence`, d.required("access"))
			for _, event := range events {
				if event["sequence"] == nil {
					return false
				}
				rows := d.deliveries(event)
				d.evidence("deliveries_"+str(event, "event_id"), rows)
				if len(rows) == 0 {
					return false
				}
				private := false
				for _, row := range rows {
					if row["status"] == "pending" {
						return false
					}
					require(row["status"] == "sent", "review notice did not reach its recipient")
					private = private || num(row, "chat_id") == merchantUser
				}
				require(private, "review delivery missing merchant private chat")
			}
			return true
		})
	})
}
