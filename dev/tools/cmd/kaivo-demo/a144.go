package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"google.golang.org/protobuf/proto"
)

const (
	a144NotSent  = "a144-not-sent"
	a144NotFound = "a144-not-found"
	a144Reason   = "create_not_found_inferred"
)

func isPaymentDevCommand(service string, args []string) bool {
	return service == "payment" && len(args) >= 2 && args[0] == "dev" && (args[1] == "backdate-create" || args[1] == "archive-work")
}

func (d *driver) checkA144Environment(scenario string, startForwards func()) {
	d.liveStep("本机网关与模拟器控制接口", func() {
		switch {
		case d.native():
			_, err := os.Stat(filepath.Join(d.root, "stack.env"))
			require(os.IsNotExist(err), scenario+" 仅支持本机进程栈，请检查状态目录是否属于 Compose")
		case scenario == disputePaidRace:
			stop("%s requires the native ledger-matches pause control", scenario)
		case scenario != disputePaidRelease && scenario != disputePaidRefund:
			d.requireNative(scenario)
		}
		require(d.gatewayMode() && d.env("reconciliation")["AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS"] != "", scenario+" 需要交易与核验网关")
		if scenario == a144NotFound || scenario == kLedgerCancelEvent || scenario == disputeReturn || isA145Scenario(scenario) && scenario != a145NeverSent {
			require(d.env("payment")["AIPAY_ENVIRONMENT"] == "development", scenario+" requires AIPAY_ENVIRONMENT=development for payment dev commands")
		}
		if scenario == disputePaidRace {
			_, err := os.Stat(filepath.Join(d.root, "deposits.enabled"))
			require(err == nil, scenario+" requires deposits enabled for ledger-matches pause")
		}
		var cfg struct {
			Environment string
			Token       string `json:"control_token"`
		}
		decode(d.input("inputs/upstream-sim/config.json"), &cfg)
		require(cfg.Environment == "test" && cfg.Token != "", scenario+" requires the simulator test control API and a control token")
		var pause listenerPause
		if scenario == kQueryTransient && d.read(queryPauseKey, &pause) && time.Now().Before(pause.ResumeAt.Add(listenerResumeMargin)) {
			// The listener also serves the control API. This run already authenticated the pause.
			return
		}
		// Exercise the authenticated control path before any publication or fault.
		startForwards()
		var next object
		_, channel := scenarioOrder(scenario, true)
		decode(d.sim("GET", "/__test/accounts/"+simulatorAccount(channel)+"/next-create", nil), &next)
		switch scenario {
		case a144NotSent, a145NeverSent, a145LatePayment, a145Refusals, kQueryTransient, kLedgerCancelEvent, disputeReturn, disputePaidRelease, disputePaidRefund, disputePaidRace:
			require(len(next) == 0, "the simulator account already has a pending create fault")
		}
	})
}

func acceptedCreate(status int, reply object) bool {
	return status == 200 && (num(reply, "code") == 1 || num(reply, "code") == -1 && reply["msg"] == "结果待确认")
}

func (t tradeRun) a144Orders() []object {
	d := t.d
	return d.rows("payment", "payment_orders", `SELECT id AS order_id, trade_no, channel_code, channel_account_id,
		data#>>'{snapshot,plugin_version}' AS plugin_version_id, (data#>>'{snapshot,trade,quote,fiat_amount}')::bigint AS amount_minor
		FROM payment_orders WHERE account_id=$1 AND application_id=$2 AND out_trade_no=$3`,
		d.required("merchant-account"), d.required("app/v1"), t.number)
}

func (d *driver) a144Trade(name string) (tradeRun, map[string]string) {
	k := d.scope + "/" + name
	amount, channel := scenarioOrder(d.history.Scenario, true)
	t := tradeRun{d: d, name: name, proto: "v1", amount: amount, channel: channel, number: d.key(k)}
	var pins map[string]string
	if !d.read(k+"/plugins", &pins) || len(t.a144Orders()) == 0 {
		pins = d.a144Plugins()
		d.put(k+"/plugins", pins)
	}
	t.baseline()
	created := t.step("注入故障并下单", func() {
		rows := t.a144Orders()
		// A lost merchant response or checkpoint must not arm the next order's fault.
		if len(rows) == 0 {
			params := d.createParams(t.number, amount)
			if d.scope == a144NotSent {
				d.sim("POST", "/__test/listener/pause", object{"duration_ms": 3000})
				d.evidence("暂停监听毫秒数", 3000)
			} else {
				var armed object
				decode(d.sim("PUT", "/__test/accounts/"+simulatorAccount(channel)+"/next-create", object{"create_fault": "lost"}), &armed)
				require(armed["create_fault"] == "lost", "模拟器未确认一次性下单故障")
				d.evidence("一次性下单故障", armed["create_fault"])
			}
			status, reply := d.signedEPay("v1", "/mapi.php", params)
			d.evidence("商户应答", object{"HTTP": status, "code": reply["code"]})
			if !acceptedCreate(status, reply) {
				// A definitive refusal leaves the account-wide one-shot available
				// to an unrelated order. A 5xx may still have committed this order.
				if d.scope == a144NotFound && status < 500 {
					d.sim("DELETE", "/__test/accounts/"+simulatorAccount(channel)+"/next-create", nil)
				}
				stop("商户下单返回非预期结果，HTTP %d，EPay code %v", status, reply["code"])
			}
			rows = t.a144Orders()
		}
		row := oneFact(rows, "商户原单")
		t.order, _, _ = t.checkOrderRoute(row)
		require(row["channel_account_id"] == d.required("uuid/"+channelKey(channel, "channel")) &&
			row["plugin_version_id"] == pins[channel], "原单未绑定已核对的 EPay 账户和交易插件")
		d.evidence("订单绑定插件", row["plugin_version_id"])
		d.evidence("平台单号", row["trade_no"])
		d.put("trade-no/"+k, str(row, "trade_no"))
		hold := d.ledgerTrade(t.order)
		require(hold["status"] == "RESERVED", "原单担保未冻结")
		var base object
		require(d.read("balances/"+k, &base) && units(d.sellerBalance(), "available_usdt_micro") == num(base, "seller")-num(hold, "escrow_usdt"), "卖方可用余额与原单冻结不符")
		d.evidence("原单冻结", hold)
	})
	t.order = str(created.Evidence, "订单 ID")
	return t, pins
}

// Each journal key carries the audit ID of the grant that allowed that create.
// During the pause more than one retry may fail before the listener returns.
func validA144Retries(audits, creates []object) bool {
	if len(creates) < 2 || len(audits) != 2*len(creates) {
		return false
	}
	for i, create := range creates {
		grant, result := audits[2*i], audits[2*i+1]
		action := "order.retry_claimed"
		if i == 0 {
			action = "order.dispatch_control"
		}
		if grant["action"] != action || create["execution_key"] != "create_payment:"+str(grant, "id") {
			return false
		}
		if i == len(creates)-1 {
			return result["action"] == "order.dispatched" && create["category"] == "succeeded" && num(create, "responses") > 0
		}
		if result["action"] != "order.dispatch_not_sent" || create["category"] != "not_sent" || create["error_code"] != "transport_connect" || num(create, "requests") != 0 {
			return false
		}
	}
	return false
}

func (d *driver) runA144NotSent() {
	t, _ := d.a144Trade("建单未发送")
	t.step("核对未发送与重新派单", func() {
		var audits []object
		waitFor("原单重派成功审计", 2*time.Minute, func() bool {
			audits = d.facts("payment", "派单许可与结果", `SELECT id,action,occurred_at FROM payment_audit_logs
				WHERE target_type='order' AND target_id=$1 AND action IN ('order.dispatch_control','order.dispatch_not_sent','order.retry_claimed','order.dispatched')
				ORDER BY occurred_at,id`, t.order)
			return len(audits) > 0 && audits[len(audits)-1]["action"] == "order.dispatched"
		})
		creates := d.facts("payment", "网关建单记录", `SELECT exchange_id,execution_key,category,error_code,requests,responses,occurred_at
			FROM payment_gateway_executions WHERE order_id=$1 AND operation='create_payment' ORDER BY occurred_at,exchange_id`, t.order)
		require(validA144Retries(audits, creates), "未发送、重试许可与成功建单记录不匹配")
	})
	k := d.scope + "/" + t.name + "/instruction"
	t.step("读取重试后的付款指令", func() {
		order := t.awaitOrderStatus("awaiting_payment")
		instruction := obj(order["payment_instruction"])
		link, _ := instruction["url"].(string)
		if link == "" {
			link = str(instruction, "qrcode")
		}
		d.cashier(link, false)
		d.put(k, link)
		d.evidence("上游单号", str(order, "upstream_order_id"))
		d.evidence("指令到期时间", str(instruction, "expires_at"))
	})
	t.link = d.required(k)
	t.paid(1)
	t.notify()
	t.release()
}

func (d *driver) runA144NotFound() {
	t, pins := d.a144Trade("建单丢失")
	t.step("核对创建未知与缺单等待", func() {
		waitFor("创建未知与原单等待审计", 2*time.Minute, func() bool {
			rows := d.facts("payment", "创建与缺单查询", `SELECT u.id AS unknown_id,u.action AS create_action,u.occurred_at AS unknown_at,
				c.exchange_id AS create_exchange,c.category AS create_category,c.requests AS create_requests,c.responses AS create_responses,
				w.id AS waiting_id,w.action,w.changes#>>'{metadata,outcome}' AS outcome,w.changes#>>'{metadata,not_before}' AS not_before,
				q.exchange_id,q.operation,q.category,q.upstream_code,q.responses,q.occurred_at
				FROM payment_audit_logs u JOIN payment_audit_logs w ON w.target_type=u.target_type AND w.target_id=u.target_id AND w.occurred_at>=u.occurred_at
				JOIN payment_gateway_executions c ON c.order_id=$1::uuid AND c.operation='create_payment' AND c.category='unknown' AND c.requests>0 AND c.responses=0
				JOIN payment_gateway_executions q ON q.order_id=c.order_id AND encode(q.evidence_sha256,'hex')=w.changes#>>'{metadata,query_evidence_sha256}'
				WHERE u.target_type='order' AND u.target_id=($1::uuid)::text AND u.action='order.dispatch_unknown' AND w.action='order.query_not_found'
				AND w.changes#>>'{metadata,outcome}'='waiting' AND w.changes#>>'{metadata,not_before}' IS NOT NULL
				AND q.operation='query_payment' AND q.category='rejected' AND q.upstream_code='not_found' AND q.responses>0`, t.order)
			return len(rows) > 0
		})
		hold := d.ledgerTrade(t.order)
		d.evidence("等待期间担保", hold)
		require(hold["status"] == "RESERVED" && hold["paid_verified_at"] == nil, "缺单等待期间担保状态不符")
	})
	t.backdateA144Create()
	intent := t.step("核对系统关单意图", func() {
		// Allow a complete normal polling interval if the worker was already leased.
		waitFor("系统缺单关单意图", 11*time.Minute, func() bool {
			rows := d.facts("payment", "系统关单审计", `SELECT id,action,occurred_at,changes->'metadata' AS metadata
				FROM payment_audit_logs WHERE target_type='order' AND target_id=$1 AND action='order.system_close_requested'
				AND changes#>>'{metadata,reason}'=$2`, t.order, a144Reason)
			if len(rows) == 0 {
				return false
			}
			audit := oneFact(rows, "系统关单意图")
			d.evidence("意图时间", audit["occurred_at"])
			d.evidence("原冻结", obj(audit["metadata"])["escrow_reservation_id"])
			return true
		})
	})
	request := t.step("核对缺单取消核验请求", func() {
		var rows []object
		waitFor("取消核验请求", 2*time.Minute, func() bool {
			rows = d.rows("payment", "payment_outbox", `SELECT event_id,sequence,cancellation_version,encode(payload,'hex') AS payload
				FROM payment_outbox WHERE order_id=$1 AND event_type='OrderCancellationVerificationRequested' AND schema_version=1 AND sequence IS NOT NULL`, t.order)
			return len(rows) > 0
		})
		row := oneFact(rows, "原单取消核验请求")
		event := a144Cancellation(str(row, "payload"), t.order)
		require(event.EscrowReservationId == str(intent.Evidence, "原冻结") && event.ControlVersion == uint64(num(row, "cancellation_version")), "取消请求与原冻结或版本不符")
		confirmed := d.facts("payment", "意图提交后的缺单复查", `SELECT a.id,a.occurred_at,a.changes#>>'{metadata,outcome}' AS outcome,
			q.exchange_id,q.category,q.upstream_code,q.occurred_at AS query_at FROM payment_audit_logs a
			JOIN payment_gateway_executions q ON q.order_id=$1::uuid AND encode(q.evidence_sha256,'hex')=a.changes#>>'{metadata,query_evidence_sha256}'
			WHERE a.target_type='order' AND a.target_id=($1::uuid)::text AND a.action='order.query_not_found' AND a.changes#>>'{metadata,outcome}'='requested'
			AND q.operation='query_payment' AND q.category='rejected' AND q.upstream_code='not_found' AND q.responses>0 AND q.occurred_at>=$2::text::timestamptz`,
			t.order, str(intent.Evidence, "意图时间"))
		require(len(confirmed) > 0, "缺少意图提交后的 payment 缺单复查")
		d.evidence("核验请求", object{"event_id": row["event_id"], "sequence": row["sequence"], "basis": event.Basis.String(), "escrow_reservation_id": event.EscrowReservationId})
		d.evidence("控制版本", event.ControlVersion)
	})
	authorization := t.a144CancellationEvidence(pins[epayChannel+"_verify"], num(normalized(request.Evidence), "控制版本"))
	t.step("核对订单取消与资金归还", func() {
		hold := t.terminal("CANCELLED")
		order := t.awaitOrderStatus("cancelled")
		require(order["escrow_status"] == "cancelled" && units(hold, "held_usdt_micro") == 0, "原单担保尚未归还")
		posting := oneFact(d.facts("ledger", "取消授权入账", `SELECT source_event_id,posting_seq FROM ledger_trade_authorizations
			WHERE order_id=$1 AND event_type='TradeCancellationAuthorized'`, t.order), "原单取消分录")
		require(posting["source_event_id"] == authorization && posting["posting_seq"] == hold["latest_seq"], "原单取消分录与核验授权不符")
		t.finish(false)
	})
}

func (t tradeRun) backdateA144Create() {
	d := t.d
	t.step("开发属主回拨最后建单时间", func() {
		timeout, err := strconv.ParseInt(d.required(channelKey(t.channel, "unpaid-timeout")), 10, 64)
		check(err)
		seconds := timeout + 120
		t.backdateCreate(seconds, "回拨审计")
		d.evidence("通道未付超时秒数", timeout)
	})
}

func (t tradeRun) backdateCreate(seconds int64, source string) {
	d := t.d
	read := func() []object {
		return d.facts("payment", source, `SELECT id,actor_id,action,occurred_at,changes->'metadata' AS metadata FROM payment_audit_logs
				WHERE target_type='order' AND target_id=$1 AND action='order.dev_create_backdated'`, t.order)
	}
	// The command subtracts time, so recover a committed invocation by its
	// transactional audit even when the driver never received its output.
	rows := read()
	if len(rows) == 0 {
		d.owner("payment", "AIPAY_DATABASE_URL", "dev", "backdate-create", "--order", t.order, "--seconds", strconv.FormatInt(seconds, 10))
		rows = read()
	}
	row := oneFact(rows, source)
	require(num(obj(row["metadata"]), "seconds") == seconds && row["actor_id"] == "payment/dev", "属主回拨秒数或身份与预期不符")
}

func a144Cancellation(payload, order string) *pay.OrderCancellationVerificationRequested {
	var event pay.OrderCancellationVerificationRequested
	b, err := hex.DecodeString(payload)
	check(err)
	require(proto.Unmarshal(b, &event) == nil && event.OrderId == order && event.EscrowReservationId != "" && event.ControlVersion > 0 &&
		event.Basis == pay.OrderCancellationBasis_ORDER_CANCELLATION_BASIS_CREATE_NOT_FOUND_INFERRED, "取消核验请求的原单、担保或 basis 不符")
	return &event
}

func (t tradeRun) a144CancellationEvidence(verifyPlugin string, version int64) string {
	return t.cancellationEvidence(verifyPlugin, version, a144Reason, "not_found_unpaid", "两次独立缺单核验与取消授权")
}

func (t tradeRun) cancellationEvidence(verifyPlugin string, version int64, reason, outcome, label string) string {
	d := t.d
	step := t.step(label, func() {
		var authorizations []object
		waitFor("带缺单原因的取消授权", 2*time.Minute, func() bool {
			authorizations = d.facts("reconciliation", "取消授权与审计", `SELECT r.authorization_id,r.event_type,r.control_version,r.issued_at,a.action,a.reason_code,
				convert_from(r.evidence_material,'UTF8')::jsonb#>>'{Review,Evidence,Cancellation,First,ID}' AS first_id,
				convert_from(r.evidence_material,'UTF8')::jsonb#>>'{Review,Evidence,Cancellation,Second,ID}' AS second_id
				FROM reconciliation_authorizations r JOIN reconciliation_audit_logs a ON a.target_type='trade_authorization' AND a.target_id=r.authorization_id::text
				WHERE r.order_id=$1 AND r.control_version=$2 AND r.event_type='TradeCancellationAuthorized'
				AND a.action='reconciliation.authorize' AND a.result='succeeded'`, t.order, version)
			return len(authorizations) > 0
		})
		auth := oneFact(authorizations, "原单取消授权")
		require(auth["reason_code"] == reason, "authorization audit reason differs from the cancellation basis")
		// Use the two observations cited by the issued authorization. Unrelated
		// polls on the same order cannot fill either side of the five-second window.
		rows := d.facts("reconciliation", "授权采信的核验及审计", `SELECT e.id,e.verified_at,e.category,e.exchange_id,e.plugin_version_id,
			convert_from(e.record_json,'UTF8')::jsonb->>'Outcome' AS outcome,a.action,a.reason_code
			FROM reconciliation_verification_evidence e JOIN reconciliation_audit_logs a ON a.id=e.audit_id AND a.target_id=e.id::text
			WHERE e.order_id=$1 AND e.plugin_version_id=$2 AND e.verification_account_id=$3 AND e.eligible AND e.operation='query_payment'
			AND convert_from(e.record_json,'UTF8')::jsonb->>'Outcome'=$8
            AND ($8 <> 'not_found_unpaid' OR e.category='rejected')
			AND (convert_from(e.record_json,'UTF8')::jsonb->>'ControlVersion')::bigint=$4 AND a.action='reconciliation.verification.query' AND a.reason_code=$5
			AND e.id IN ($6,$7) ORDER BY e.verified_at,e.id`, t.order, verifyPlugin, d.required("uuid/"+channelKey(epayChannel, "verify-account")),
			version, reason, str(auth, "first_id"), str(auth, "second_id"), outcome)
		require(len(rows) == 2 && rows[0]["id"] == auth["first_id"] && rows[1]["id"] == auth["second_id"], "取消授权未引用两次独立的缺单核验")
		first, err := time.Parse(time.RFC3339Nano, str(rows[0], "verified_at"))
		check(err)
		second, err := time.Parse(time.RFC3339Nano, str(rows[1], "verified_at"))
		check(err)
		issued, err := time.Parse(time.RFC3339Nano, str(auth, "issued_at"))
		check(err)
		require(!issued.Before(second), "cancellation authorization predates its second observation")
		d.evidence("观测间隔", second.Sub(first).String())
		require(second.Sub(first) >= 5*time.Second, "取消授权的两次观测间隔不足 5 秒")
		d.evidence("授权 ID", auth["authorization_id"])
	})
	return str(step.Evidence, "授权 ID")
}
