package main

import (
	"encoding/base64"
	"fmt"
	"time"
)

func disputeRefundPlan(after bool) ([]string, []string) {
	barrier := "付款后立即登记争议。ledger_trade_reservations 的 DISPUTED、争议 ID 及原担保 seq 证明 Q 仍在担保。"
	balances := "核对卖方门户可用恢复 Q、商户 bot 可用和三项费用余额维持下单前基线。"
	notes := []string{
		"payment/internal/channeladmin/disputes.go:274 拒绝原订单缺失 paid_verified_at 的退款裁决。用 OrderPaid 和登记前的订单状态核对。",
		"payment/internal/channeladmin/disputes.go:325-328,430-445 在第二签提交后同步交接并处理退款。若接口报错，签署可能已提交。对照 payment_dispute_rulings.stage、ledger 预留和派发审计定位。",
		"reconciliation/internal/streams/rulings.go:48-64 可能记录 refund_execution_unsupported、stale_control_version 或 no_matching_pre_release_dispute，取决于读取时的账本状态。reconciliation/internal/streams/triggers.go:120-143 另行处理退款终态，两次 ledger 读取不一致会留待重试。",
		"reconciliation/internal/authorization/dispute.go:58-73,123-142 会复核预留留存的裁决与签署版本、摘要和有效期。独立查退款成功后仍可能没有授权。",
		"reconciliation/internal/verification/state.go:63-71 检查整条 payment.orders 流。其他订单的隔离信封也可能使本单有成功查退款记录却无授权，可查 reconciliation_inbox 的 status 和 sequence。",
	}
	if after {
		barrier = "先放币并检查商户 +N、三项费用 +F，再从平台登记争议。按争议 ID 核对 ledger_trade_released_disputes 和原账户 user_risk_held 的有效预留 N。"
		balances = "相对放币后快照，商户可用减少 N、三项费用减少 F、卖方恢复 Q。按争议 ID 和退款 ID 检查两个预留的结清序号。"
		notes = append(notes,
			"backend/internal/transport/http/routes/platform_contracts.go:63 已声明 POST /api/v1/platform/disputes。payment/internal/channeladmin/disputes.go:103-109 只接受 Releasing/Completed 且担保已 RELEASED。backend/internal/transport/http/portal/request.go:179-180 将状态前提失败和并发冲突均映射为 409。",
			"ledger/internal/trade/authorization_rules.go:250-257 要求客户资金钱包覆盖冲回费用后的负债。覆盖不足可能已有独立查退款、授权和预留，账本仍不能结清。")
	} else {
		notes = append(notes, "payment/internal/channeladmin/disputes.go:136-140 校验实际账本控制版本。若登记时 20 秒风控期已结束且放币已落账，放币前样本会在登记时被拒绝。")
	}
	return []string{
		"以真实收银和 OrderPaid 确认原单付款。" + barrier,
		"商户 /order 与卖方门户分别举证，风控提交 refund，两名已登记审批人签署同一材料。按 payment 裁决 ID 比对 ledger_trade_refunds 的唯一记录、分支、金额及交接版本。",
		"同一 PostgreSQL 实例上，ledger_audit_logs 在交接事务内记录成功（ledger/internal/trade/service.go:70-88）。payment 持久化同一预留 ID 和 seq 后才进入 dispatch（payment/internal/channeladmin/disputes_postgres.go:305-311）。实际调用前的首笔 refund.dispatch_granted 必须严格晚于交接审计（payment/internal/orders/refund.go:152-165）。PRE_RELEASE 的 reserve_seq 沿用下单分录。",
		"独立 refund-query 按原单、退款号和原金额查成功。核对 reconciliation_verification_evidence 的 eligible query_refund、签发材料采用的证据摘要及 reconciliation_outbox 的签发序号。裁决触发的 disposition/reason 单列。",
		"等待 REFUNDED，检查两个 payment 事件与退款授权在 ledger_transactions 中合计只有授权的一笔核销。" + balances,
	}, notes
}

// Record only selected owner facts, including unexpected rows on a failed assertion.
func (d *driver) facts(owner, source, query string, args ...any) []object {
	rows := d.rows(owner, source, query, args...)
	d.evidence(source, rows)
	return rows
}

func oneFact(rows []object, what string) object {
	require(len(rows) == 1, fmt.Sprintf("%s：预期一条，实际 %d 条", what, len(rows)))
	return rows[0]
}

func (d *driver) disputeRefund(after bool) {
	t := d.trade("争议退款", "v1")
	t.paid(1)
	var beforeRefund object
	if after {
		beforeRefund = t.release()
	}
	// Preserve the original refusal and any available cross-service evidence,
	// even if the second assertion committed before its HTTP response failed.
	defer func() {
		if v := recover(); v != nil {
			if _, ok := v.(failure); ok {
				t.refundFailureEvidence()
			}
			panic(v)
		}
	}()
	t.registerDispute(after)
	dispute := d.required("dispute/" + t.order)
	held := t.checkRefundBarrier(after, dispute)
	if !after {
		beforeRefund = held
	}
	ruling := t.approveRefundRuling(dispute)
	refund := t.checkRefundHandoff(after, dispute, ruling)
	t.step("模拟上游独立查全额退款", func() {
		waitFor("模拟上游独立查到退款", time.Minute, func() bool {
			fact := d.simRefundQuery(t.order, refund)
			d.evidence("sim_refund_query", fact)
			if fact.Result == "rejected" && fact.Code == "not_found" {
				return false
			}
			checkSimRefund(fact, t.order, refund)
			return true
		})
	})
	t.step("独立授权、唯一分录与余额", func() {
		t.terminal("REFUNDED")
		t.proveRefundExecution(after, dispute, ruling, refund)
		final := t.finish(false)
		h := d.ledgerTrade(t.order)
		merchant, fees := int64(0), int64(0)
		if after {
			merchant, fees = -num(h, "recipient_usdt"), -num(h, "platform_fee_usdt")
		}
		d.evidence("退款前可用及费用余额", object{"seller": beforeRefund["seller"], "merchant": beforeRefund["merchant"], "ledger_fee_accounts": beforeRefund["ledger_fee_accounts"]})
		checkBalanceDelta(beforeRefund, final, num(h, "escrow_usdt"), merchant, fees)
	})
}

func (t tradeRun) checkRefundBarrier(after bool, dispute string) object {
	d := t.d
	step := t.step("核对裁决前资金占用", func() {
		h := d.ledgerTrade(t.order)
		barrier := oneFact(d.facts("ledger", "ledger_trade_reservations 屏障",
			"SELECT status,dispute_id,control_version,released_seq FROM ledger_trade_reservations WHERE order_id=$1", t.order), "原单屏障")
		require(barrier["dispute_id"] == dispute && barrier["control_version"] == h["control_version"], "争议或控制版本不匹配")
		if after {
			require(barrier["status"] == "RELEASED", "已放币登记后担保状态异常")
			hold := t.releasedHold(dispute)
			checkRiskHold(hold, h, dispute)
			require(hold["status"] == "HELD" && hold["fund_status"] == "reserved" && hold["final_seq"] == nil, "裁决前风控预留未生效")
		} else {
			require(barrier["status"] == "DISPUTED" && barrier["released_seq"] == nil, "放币前争议未控制原担保")
		}
		held := normalized(d.balanceSnapshot(t.order + "/held/" + id()))
		d.evidence("裁决前余额", held)
		var base object
		require(d.read("balances/"+d.scope+"/"+t.name, &base), "缺下单前余额")
		feeDelta := int64(0)
		if after {
			feeDelta = num(h, "platform_fee_usdt")
		}
		checkBalanceDelta(base, held, -num(h, "escrow_usdt"), 0, feeDelta)
	})
	return obj(step.Evidence["裁决前余额"])
}

func (t tradeRun) approveRefundRuling(dispute string) string {
	d := t.d
	step := t.step("风控提交退款裁决并双签", func() {
		m := d.browser("risk").approve("ruling", "payment", "/disputes/"+dispute+"/rulings", "/dispute-rulings",
			object{"outcome": "refund", "expected_control_version": num(d.ledgerTrade(t.order), "control_version"), "reason": "双方原单证据核对后全额原路退款"})
		op := obj(m["dispute_ruling"])
		require(op["dispute_id"] == dispute && obj(op["trade"])["order_id"] == t.order, "审批材料指向其他争议或订单")
		e := oneFact(d.facts("payment", "payment_evidence_versions 双方举证", `SELECT version,encode(digest,'base64') AS digest,
			length(evidence->>'recipient_evidence')>0 AS recipient_present,length(evidence->>'seller_evidence')>0 AS seller_present
			FROM payment_evidence_versions WHERE dispute_id=$1 ORDER BY version DESC LIMIT 1`, dispute), "裁决对应的双方举证")
		require(e["recipient_present"] == true && e["seller_present"] == true && num(e, "version") > 1 &&
			str(e, "digest") == base64.StdEncoding.EncodeToString(raw(str(op, "evidence_sha256"))), "裁决签署材料未绑定双方证据")
		d.evidence("裁决双签", object{"outcome": op["outcome"], "dispute_id": dispute, "approver_ids": []string{d.key("person/" + approvers[0]), d.key("person/" + approvers[1])}})
	})
	return str(step.Evidence, "approval_id")
}

func (t tradeRun) checkRefundHandoff(after bool, dispute, ruling string) string {
	d := t.d
	step := t.step("核对唯一预留和首次派发顺序", func() {
		r := oneFact(t.reservations(), "ledger_trade_refunds")
		p := oneFact(d.facts("payment", "payment_refunds 与已批准裁决", `SELECT f.id AS refund_id, dr.id AS ruling_id, dr.dispute_id,
			f.data#>>'{reservation,refund_reservation_id}' AS refund_reservation_id,
			(f.data#>>'{reservation,reserve_seq}')::bigint AS reserve_seq,
			f.expected_version,encode(a.request_digest,'hex') AS digest,a.approved_at
			FROM payment_refunds f LEFT JOIN payment_dispute_rulings dr ON dr.refund_id=f.id
			LEFT JOIN payment_admin_requests a ON a.id=dr.id WHERE f.order_id=$1`, t.order), "payment 退款回执")
		h := d.ledgerTrade(t.order)
		checkRefundReservation(after, r, p, h, dispute, ruling)
		refund := str(r, "refund_id")
		d.evidence("refund_id", refund)
		action, target := "ledger.reserve_refund", t.order
		if after {
			action, target = "ledger.resolve_released_trade_dispute", dispute
		}
		audit := oneFact(d.facts("ledger", "ledger_audit_logs 交接成功", `SELECT id,action,target_id,occurred_at FROM ledger_audit_logs
			WHERE actor_id='payment' AND result='succeeded' AND action=$1 AND target_id=$2`, action, target), "账本交接审计")
		// Grants are audited against the order. Both owner receipts identify
		// its only refund. The simulator independently confirms the send.
		var grants []object
		waitFor("payment 退款派发许可", time.Minute, func() bool {
			grants = t.dispatchGrants()
			return len(grants) > 0
		})
		if d.native() {
			checkDispatchOrder(audit, grants)
		} else {
			d.evidence("跨库审计时间严格先后", "仅本机栈；预发已按预留 ID、seq 和裁决摘要核对交接。")
		}
	})
	return str(step.Evidence, "refund_id")
}

func (t tradeRun) dispatchGrants() []object {
	return t.d.facts("payment", "payment_audit_logs 派发许可", `SELECT id,action,target_id,occurred_at FROM payment_audit_logs
		WHERE target_type='order' AND target_id=$1 AND action='refund.dispatch_granted' ORDER BY occurred_at,id`, t.order)
}

func (t tradeRun) reservations() []object {
	return t.d.facts("ledger", "ledger_trade_refunds 与争议交接", `SELECT f.refund_id,f.refund_reservation_id,f.branch,f.account_id,f.reserved_usdt,f.control_version,f.reserve_seq,
		f.dispute_ruling->>'dispute_id' AS dispute_id,f.dispute_ruling->>'ruling_id' AS ruling_id,
		encode(decode(f.dispute_ruling->>'ruling_sha256','base64'),'hex') AS digest,f.dispute_ruling->>'approved_at' AS approved_at,
		h.dispute_id AS prior_dispute_id,h.expected_version FROM ledger_trade_refunds f
		LEFT JOIN ledger_trade_refund_handoffs h USING(order_id,refund_id) WHERE f.order_id=$1`, t.order)
}

func checkRefundReservation(after bool, r, p, h object, dispute, ruling string) {
	require(r["dispute_id"] == dispute && r["prior_dispute_id"] == dispute && p["dispute_id"] == dispute &&
		r["ruling_id"] == ruling && p["ruling_id"] == ruling && r["account_id"] == str(h, "account_id"), "预留未绑定本争议、裁决和原收款账户")
	require(str(r, "digest") == str(p, "digest") && sameInstant(r["approved_at"], p["approved_at"]) &&
		num(r, "expected_version") == num(p, "expected_version") && num(r, "control_version") == num(p, "expected_version")+1, "交接与批准材料的摘要、时间或版本不匹配")
	seq := num(r, "reserve_seq")
	require(str(r, "refund_id") == str(p, "refund_id") && str(r, "refund_reservation_id") == str(p, "refund_reservation_id") && seq > 0 && seq == num(p, "reserve_seq"), "payment 退款未持有同一 ledger 预留凭证")
	if after {
		require(r["branch"] == "POST_RELEASE" && num(r, "reserved_usdt") == num(h, "recipient_usdt") && seq > num(h, "released_seq"), "放币后应预留原商户所得 N")
	} else {
		require(r["branch"] == "PRE_RELEASE" && num(r, "reserved_usdt") == num(h, "escrow_usdt") && seq == num(h, "reserve_seq") && h["released_seq"] == nil, "放币前应延续原担保 Q")
	}
}

func checkDispatchOrder(audit object, grants []object) {
	at, err := time.Parse(time.RFC3339Nano, str(audit, "occurred_at"))
	check(err)
	require(len(grants) > 0, "缺少退款派发许可")
	for _, g := range grants {
		granted, err := time.Parse(time.RFC3339Nano, str(g, "occurred_at"))
		check(err)
		require(granted.After(at), "首次上游派发许可未严格晚于 ledger 预留交接")
	}
}

func checkSimRefund(fact simRefundResult, order, refund string) {
	f := fact.Refund
	require(fact.Result == "accepted" && fact.Code == "refund_success" && f != nil && f.Account == "md5-demo" && f.Order == order &&
		f.ID == refund && f.Status == "success" && f.Currency == "CNY" && f.Amount == 100, "模拟上游未确认本单 1.00 CNY 全额原路退款")
}

func (t tradeRun) releasedHold(dispute string) object {
	return oneFact(t.d.facts("ledger", "ledger_trade_released_disputes 与原账户风控预留", `SELECT h.dispute_id,h.account_id,h.held_usdt,h.shortfall_usdt,h.reserve_seq,h.status,h.refund_id,h.close_seq,
		g.reservation_key,g.owner_account_id,g.amount_units,g.status AS fund_status,g.final_seq,a.code AS hold_account,
		(SELECT sum(l.units)::bigint FROM ledger_lines l JOIN ledger_accounts src ON src.id=l.account_id
		 WHERE l.seq=h.reserve_seq AND l.direction='D' AND src.code='user_available:USDT:'||h.account_id::text) AS available_debit,
		(SELECT sum(l.units)::bigint FROM ledger_lines l WHERE l.seq=h.reserve_seq AND l.direction='C' AND l.account_id=g.hold_account_id) AS held_credit,
		f.reserve_seq AS refund_seq,rg.status AS refund_status,rg.final_seq AS refund_final_seq
		FROM ledger_trade_released_disputes h LEFT JOIN ledger_reservations g ON g.id=h.generic_reservation_id
		LEFT JOIN ledger_accounts a ON a.id=g.hold_account_id LEFT JOIN ledger_trade_refunds f ON f.refund_id=h.refund_id
		LEFT JOIN ledger_reservations rg ON rg.id=f.generic_reservation_id WHERE h.order_id=$1 AND h.dispute_id=$2`, t.order, dispute), "本争议风控冻结")
}
func checkRiskHold(hold, h object, dispute string) {
	account, n := str(h, "account_id"), num(h, "recipient_usdt")
	require(hold["dispute_id"] == dispute && hold["reservation_key"] == "trade_released_dispute:"+dispute && hold["account_id"] == account &&
		hold["owner_account_id"] == account && hold["hold_account"] == "user_risk_held:USDT:"+account && num(hold, "reserve_seq") > num(h, "released_seq") &&
		num(hold, "held_usdt") == n && num(hold, "amount_units") == n && num(hold, "shortfall_usdt") == 0 &&
		num(hold, "available_debit") == n && num(hold, "held_credit") == n, "A119 未从原收款账户按争议 ID 足额冻结 N")
}

func (t tradeRun) rulingTriggers(grace time.Duration) []object {
	d := t.d
	events := d.facts("payment", "payment_outbox 两类触发", `SELECT event_id,event_type,sequence,approval_request_id,refund_id
		FROM payment_outbox WHERE order_id=$1 AND event_type IN ('DisputeRulingApproved','RefundSucceeded','RefundFailed') ORDER BY sequence`, t.order)
	for _, e := range events {
		if e["event_type"] == "DisputeRulingApproved" {
			until := time.Now().Add(grace)
			for {
				rows := d.facts("reconciliation", "裁决触发处理 "+str(e, "event_id"), `SELECT i.event_id,i.status AS inbox_status,r.object_id AS dispute_id,r.ruling_id,
				r.disposition,r.reason,r.next_attempt_at FROM reconciliation_inbox i LEFT JOIN reconciliation_verification_requests r USING(event_id)
				WHERE i.event_id=$1`, str(e, "event_id"))
				if len(rows) > 0 && rows[0]["disposition"] != nil {
					break
				}
				if !time.Now().Before(until) {
					d.evidence("裁决触发观察", "截至本次读取尚无终态处置")
					break
				}
				time.Sleep(400 * time.Millisecond)
			}
		}
	}
	return events
}

func (t tradeRun) refundFailureEvidence() {
	// Diagnostic reads can fail independently (e.g. the owner is down).
	// Keep the failing step and its original error in either case.
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(failure); ok {
				t.d.evidence("补充取证错误", f.reason)
			} else {
				panic(v)
			}
		}
		t.d.report()
	}()
	d := t.d
	d.facts("payment", "payment_disputes 与裁决进度", `SELECT d.id AS dispute_id,d.state,d.released,r.id AS ruling_id,r.stage,r.refund_id,f.stage AS refund_stage
		FROM payment_disputes d LEFT JOIN payment_dispute_rulings r ON r.dispute_id=d.id LEFT JOIN payment_refunds f ON f.id=r.refund_id
		WHERE d.order_id=$1`, t.order)
	d.facts("ledger", "ledger_trade_reservations 失败时状态", "SELECT status,control_version,latest_seq,dispute_id,refund_id FROM ledger_trade_reservations WHERE order_id=$1", t.order)
	d.facts("ledger", "ledger_trade_released_disputes 失败时冻结", `SELECT dispute_id,account_id,status,held_usdt,shortfall_usdt,reserve_seq,close_seq,refund_id
		FROM ledger_trade_released_disputes WHERE order_id=$1`, t.order)
	t.reservations()
	t.dispatchGrants()
	t.refundExecutions()
	t.rulingTriggers(0)
	d.facts("reconciliation", "独立查退款尝试", `SELECT id,verified_at,eligible,category,convert_from(record_json,'UTF8')::jsonb->>'Outcome' AS outcome
		FROM reconciliation_verification_evidence WHERE order_id=$1 AND operation='query_refund' ORDER BY verified_at`, t.order)
	issued := d.facts("reconciliation", "退款授权进度", `SELECT a.authorization_id,a.issued_at,o.sequence FROM reconciliation_authorizations a
		JOIN reconciliation_outbox o ON o.event_id=a.authorization_id WHERE a.order_id=$1 AND a.event_type='TradeRefundAuthorized'`, t.order)
	for _, a := range issued {
		id := str(a, "authorization_id")
		d.facts("ledger", "ledger_inbox 退款授权 "+id, `SELECT event_id,sequence,status,quarantine_reason FROM ledger_inbox WHERE event_id=$1`, id)
	}
}

func (t tradeRun) proveRefundExecution(after bool, dispute, ruling, refund string) {
	d := t.d
	t.refundExecutions()
	events := t.rulingTriggers(8 * time.Second)
	var trigger, succeeded string
	for _, e := range events {
		switch {
		case e["event_type"] == "DisputeRulingApproved" && e["approval_request_id"] == ruling:
			trigger = str(e, "event_id")
		case e["event_type"] == "RefundSucceeded" && e["refund_id"] == refund:
			succeeded = str(e, "event_id")
		}
	}
	require(len(events) == 2 && trigger != "" && succeeded != "", "缺少本裁决的批准事件或本退款的成功事件")
	auth := oneFact(d.facts("reconciliation", "reconciliation_authorizations 与签名 outbox", `SELECT a.authorization_id,a.control_version,a.issued_at,o.sequence,
		convert_from(a.evidence_material,'UTF8')::jsonb#>>'{Review,Evidence,SHA256}' AS query_digest,
		convert_from(a.evidence_material,'UTF8')::jsonb#>>'{Review,Evidence,PendingRefundID}' AS refund_id
		FROM reconciliation_authorizations a JOIN reconciliation_outbox o ON o.event_id=a.authorization_id
		WHERE a.order_id=$1 AND a.event_type='TradeRefundAuthorized' AND o.stream='reconciliation.matches' AND o.signature IS NOT NULL`, t.order), "签名退款授权")
	require(auth["refund_id"] == refund && num(auth, "sequence") > 0, "退款授权指向其他预留或未取得流序号")
	verified := d.facts("reconciliation", "reconciliation_verification_evidence 独立查退款", `SELECT id,operation,eligible,verified_at,
		convert_from(record_json,'UTF8')::jsonb->>'Outcome' AS outcome,encode(evidence_sha256,'base64') AS query_digest
		FROM reconciliation_verification_evidence WHERE order_id=$1 AND operation='query_refund' ORDER BY verified_at`, t.order)
	require(verifiedRefundQuery(auth, verified), "签发材料缺少匹配摘要的 eligible 独立查退款成功证据")

	signed := str(auth, "authorization_id")
	exec := oneFact(d.facts("ledger", "ledger_trade_authorizations 退款核销", `SELECT authorization_id,source_event_id,source_sequence,expected_version,
		refund_id,refund_reservation_id,result_status,posting_seq FROM ledger_trade_authorizations
		WHERE order_id=$1 AND event_type='TradeRefundAuthorized'`, t.order), "已执行的退款授权")
	reservation := oneFact(t.reservations(), "ledger_trade_refunds")
	h := d.ledgerTrade(t.order)
	require(exec["authorization_id"] == signed && exec["source_event_id"] == signed && exec["source_sequence"] == auth["sequence"] &&
		exec["expected_version"] == auth["control_version"] && exec["refund_id"] == refund && exec["refund_reservation_id"] == reservation["refund_reservation_id"] &&
		exec["result_status"] == "REFUNDED" && exec["posting_seq"] == h["latest_seq"], "退款授权、预留与终态分录不匹配")

	// Wait for both payment envelopes to reach ledger before counting their
	// effects. A separate stream may already have delivered the authorization.
	waitFor("ledger 接收裁决和退款事件", time.Minute, func() bool {
		rows := d.facts("ledger", "ledger_inbox 两类触发", `SELECT event_id,event_type,status FROM ledger_inbox
			WHERE stream='payment.orders' AND event_id IN ($1,$2) ORDER BY sequence`, trigger, succeeded)
		return len(rows) == 2 && rows[0]["status"] != "pending" && rows[1]["status"] != "pending"
	})
	postings := d.facts("ledger", "ledger_transactions 三个来源的实际分录", `SELECT seq,kind,source_event_id,source_stream FROM ledger_transactions
		WHERE source_event_id IN ($1,$2,$3) ORDER BY seq`, trigger, succeeded, signed)
	post := uniqueRefundPosting(postings, signed, num(exec, "posting_seq"), num(reservation, "reserve_seq"))
	if after {
		hold := t.releasedHold(dispute)
		checkRiskHold(hold, h, dispute)
		checkClosedRiskHold(hold, reservation, post)
	} else {
		escrow := oneFact(d.facts("ledger", "ledger_reservations 原卖方担保", `SELECT owner_account_id,amount_units,reserve_seq,status,final_seq
			FROM ledger_reservations WHERE id=$1 AND reservation_key=$2`, str(h, "escrow_reservation_id"), "trade:"+t.order), "原卖方担保")
		require(escrow["owner_account_id"] == h["seller_account_id"] && num(escrow, "amount_units") == num(h, "escrow_usdt") &&
			escrow["reserve_seq"] == reservation["reserve_seq"] && escrow["status"] == "released" && escrow["final_seq"] == post["seq"], "原担保 Q 未持续占用至唯一退款分录")
	}
}

func (t tradeRun) refundExecutions() {
	t.d.facts("payment", "payment_plugin_executions 上游退款调用", `SELECT id,refund_id,operation,category,error_code,occurred_at
		FROM payment_plugin_executions WHERE order_id=$1 AND operation='refund' ORDER BY occurred_at,id`, t.order)
}

func uniqueRefundPosting(rows []object, signed string, postingSeq, reserveSeq int64) object {
	post := oneFact(rows, "裁决、退款事件和授权的资金分录")
	require(post["source_event_id"] == signed && post["source_stream"] == "reconciliation.matches" && post["kind"] == "trade_refunded" &&
		num(post, "seq") == postingSeq && postingSeq > reserveSeq, "唯一核销分录来源或序号错误")
	return post
}

func verifiedRefundQuery(auth object, rows []object) bool {
	digest := str(auth, "query_digest")
	for _, r := range rows {
		if r["query_digest"] == digest && r["operation"] == "query_refund" && r["eligible"] == true && r["outcome"] == "refund_succeeded" {
			return true
		}
	}
	return false
}
func checkClosedRiskHold(hold, reservation, post object) {
	require(hold["status"] == "REFUND_PENDING" && hold["fund_status"] == "released" && hold["refund_id"] == str(reservation, "refund_id") &&
		num(hold, "final_seq") == num(hold, "close_seq") && num(hold, "close_seq") > num(hold, "reserve_seq") &&
		num(hold, "refund_seq") == num(reservation, "reserve_seq") && num(hold, "refund_seq") > num(hold, "close_seq") &&
		hold["refund_status"] == "settled" && num(hold, "refund_final_seq") == num(post, "seq"), "争议冻结未完整转入退款预留并结清")
}
