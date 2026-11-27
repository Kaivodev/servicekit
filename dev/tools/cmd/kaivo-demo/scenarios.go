package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (d *driver) epay(version, path string, v url.Values) object {
	code, r := d.signedEPay(version, path, v)
	if version == "v1" {
		require(code == 200 && num(r, "code") == 1, fmt.Sprintf("%s HTTP %d EPay code %v", path, code, r["code"]))
	} else {
		pending := path == "/api/pay/close" && num(r, "code") == -1 && r["msg"] == "结果待确认"
		if pending {
			d.trace("EPay signed pending result; await owner evidence")
		}
		require(num(r, "code") == 0 || pending, fmt.Sprintf("%s EPay code %v", path, r["code"]))
	}
	return r
}

func (d *driver) signedEPay(version, path string, v url.Values) (int, object) {
	v.Set("pid", d.required("pid/"+version))
	if version == "v1" {
		var keys struct{ Key string }
		decode(file(filepath.Join(d.dir, "merchant-key.json")), &keys)
		v.Set("sign_type", "MD5")
		v.Set("sign", v1Sign(v, keys.Key))
	} else {
		v.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		v.Set("sign_type", "RSA")
		plain, ok := canonical(v)
		require(ok, "invalid V2 parameters")
		h := sha256.Sum256([]byte(plain))
		sig, e := rsa.SignPKCS1v15(rand.Reader, d.merchantRSA(), crypto.SHA256, h[:])
		check(e)
		v.Set("sign", base64.StdEncoding.EncodeToString(sig))
	}
	code, body := d.browser("merchant").http("POST", path, path, "application/x-www-form-urlencoded", form(v), nil)
	var r object
	decode(body, &r)
	if version == "v2" {
		if code != 200 || r["sign"] == nil {
			stop("%s HTTP %d EPay code %v", path, code, r["code"])
		}
		f := url.Values{}
		for k, v := range r {
			f.Set(k, fmt.Sprint(v))
		}
		plain, ok := canonical(f)
		require(ok && f.Get("sign_type") == "RSA", "invalid V2 response parameters")
		h := sha256.Sum256([]byte(plain))
		block, _ := pem.Decode(d.input("handoff/platform-public.pem"))
		require(block != nil, "missing platform SPKI")
		key, e := x509.ParsePKIXPublicKey(block.Bytes)
		check(e)
		pk, ok := key.(*rsa.PublicKey)
		require(ok && rsa.VerifyPKCS1v15(pk, crypto.SHA256, h[:], standard(str(r, "sign"))) == nil, "invalid platform signature")
	}
	return code, r
}
func (d *driver) sim(method, path string, data object) []byte {
	var cfg object
	decode(d.input("inputs/upstream-sim/config.json"), &cfg)
	var body []byte
	if data != nil {
		body = encoded(data)
	}
	req, e := http.NewRequestWithContext(d.ctx, method, d.addresses().sim+path, bytes.NewReader(body))
	check(e)
	req.Header.Set("Authorization", "Bearer "+str(cfg, "control_token"))
	req.Header.Set("Content-Type", "application/json")
	res, e := localHTTP.Do(req)
	require(e == nil, "sim transport failed")
	defer res.Body.Close()
	d.trace(fmt.Sprintf("%s %s → HTTP %d", method, path, res.StatusCode))
	require(res.StatusCode >= 200 && res.StatusCode < 300, "sim rejected request")
	b, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	check(e)
	return b
}
func (d *driver) cashier(link string, pay bool) {
	u, e := url.Parse(link)
	require(e == nil && u.Scheme+"://"+u.Host == d.addresses().cashier && u.User == nil && u.RawQuery == "" && u.Fragment == "" && regexp.MustCompile(`^/cashier/[A-Za-z0-9_-]+$`).MatchString(u.EscapedPath()), "unexpected cashier link")
	c := d.cashierClient()
	defer c.CloseIdleConnections()
	methods := []string{"GET"}
	if pay {
		methods = append(methods, "POST")
	}
	for _, method := range methods {
		req, e := http.NewRequestWithContext(d.ctx, method, link, nil)
		check(e)
		res, e := c.Do(req)
		require(e == nil, "cashier request failed")
		res.Body.Close()
		d.trace(fmt.Sprintf("%s /cashier/{token} → HTTP %d", method, res.StatusCode))
		require(res.StatusCode == 200, "cashier rejected request")
	}
}

type tradeRun struct {
	d                                *driver
	name, proto, number, order, link string
	channel, amount                  string
}

func scenarioOrder(scenario string, gateway bool) (amount, channel string) {
	switch scenario {
	case livePhase:
		return "1.11", epayChannel
	case "main", "duplicates", "dispute", "seller-offline", "bot-notices", "statement", "archived-work", "cancel", a144NotSent, a144NotFound,
		a145NeverSent, a145StaleBinding, a145UnpaidBeforeT, a145LatePayment, a145Refusals, kQueryTransient, kLedgerCancelEvent:
		if gateway {
			return "2.00", epayChannel
		}
		return "2.00", md5Channel
	default:
		return "1.00", md5Channel
	}
}

func (t tradeRun) setScenario(fields object) {
	t.d.sim("PUT", "/__test/scenarios/"+simulatorAccount(t.channel)+"/"+t.order, fields)
}

func (t tradeRun) step(label string, f func()) *result {
	t.d.step(t.name+" "+label, f)
	return t.d.active
}
func (d *driver) createParams(number, amount string) url.Values {
	return url.Values{"out_trade_no": {number}, "type": {"alipay"}, "name": {"阶段二担保"}, "money": {amount}, "notify_url": {d.addresses().notify + "/notify"}, "return_url": {"https://merchant.aipay.test/return"}, "clientip": {"127.0.0.1"}, "method": {"web"}}
}

// Resolve the immutable binding on the created order before using any upstream
// endpoint. On resume this also recovers pre-UG-7 embedded order amounts.
func (t tradeRun) readOrderRoute() (order, code, money string) {
	d := t.d
	rows := d.rows("payment", "payment_orders", `SELECT id::text AS order_id,channel_code,channel_account_id,
		(data#>>'{snapshot,trade,quote,fiat_amount}')::bigint AS amount_minor FROM payment_orders
		WHERE account_id=$1 AND application_id=$2 AND out_trade_no=$3`, d.required("merchant-account"), d.required("app/"+t.proto), t.number)
	require(len(rows) == 1, "order for merchant number not found")
	return t.checkOrderRoute(rows[0])
}

func (t tradeRun) checkOrderRoute(row object) (order, code, money string) {
	d := t.d
	order, code = str(row, "order_id"), str(row, "channel_code")
	cents := num(row, "amount_minor")
	money = fmt.Sprintf("%d.%02d", cents/100, cents%100)
	d.evidence("订单 ID", order)
	d.evidence("订单通道", code)
	d.evidence("订单金额（元）", money)
	if d.scope == livePhase {
		account := str(row, "channel_account_id")
		d.evidence("channel_account_id", account)
		require(account == d.required("uuid/"+channelKey(liveVariant, "channel")),
			fmt.Sprintf("order routed to %s channel account %s instead of the EPay test upstream", code, account))
	}
	gateway := d.gatewayMode()
	amount, expected := scenarioOrder(d.history.Scenario, gateway)
	require(code == expected, fmt.Sprintf("order %s routed to %s, expected %s", order, code, expected))
	if gateway {
		require(money == amount, "gateway order amount differs from scenario")
	}
	return order, code, money
}

func (t tradeRun) baseline() {
	d := t.d
	k := d.scope + "/" + t.name
	t.step("余额基线", func() {
		snap := d.balanceSnapshotFrom(k+"/before", d.waitForIdleBalances())
		d.put("balances/"+k, snap)
		d.evidence("before", snap)
		if !d.native() && units(obj(snap["seller_portal"]), "available_usdt_micro") == 0 {
			stop("缺样本：卖方可用 USDT 为零；请核对 setup seller 的正常预存步骤")
		}
	})
}

func (d *driver) trade(name, proto string) tradeRun {
	amount, _ := scenarioOrder(d.history.Scenario, d.gatewayMode())
	t := tradeRun{d: d, name: name, proto: proto, number: d.key(d.scope + "/" + name)}
	k := d.scope + "/" + name
	t.baseline()
	t.step("下单与冻结", func() {
		v := d.createParams(t.number, amount)
		path := "/mapi.php"
		link := "payurl"
		if proto == "v2" {
			path = "/api/pay/create"
			link = "pay_info"
		}
		r := d.epay(proto, path, v)
		order, code, money := t.readOrderRoute()
		d.put("channel/"+k, code)
		d.put("amount/"+k, money)
		if proto == "v1" && r[link] == nil {
			link = "qrcode"
		}
		d.put("trade-no/"+k, str(r, "trade_no"))
		d.put("cashier/"+k, str(r, link))
		d.evidence("trade_no", str(r, "trade_no"))
		d.cashier(str(r, link), false)
		// /orders pages oldest first, so a long-lived demo merchant cannot find a
		// new order there. Resolve the ID by merchant number, then check the bot view.
		app := d.required("app/" + proto)
		view := d.bot(k+"/order", "/order "+app+" "+order)
		require(regexp.MustCompile("^"+regexp.QuoteMeta(order)+" · 应用 "+regexp.QuoteMeta(app)+" · 业务 "+regexp.QuoteMeta(d.required("business"))+" · 商户单号 "+regexp.QuoteMeta(t.number)+" · 平台单号 "+regexp.QuoteMeta(str(r, "trade_no"))+" · ").MatchString(view), "bot order view differs from the created order")
		d.put("order/"+k, order)
		hold := d.ledgerTrade(order)
		require(hold != nil && str(hold, "status") == "RESERVED" && str(hold, "seller_account_id") == d.required("seller-account") && str(hold, "account_id") == d.required("merchant-account"), "not the expected frozen order")
		var base object
		d.read("balances/"+k, &base)
		require(units(d.sellerBalance(), "available_usdt_micro") == num(base, "seller")-num(hold, "escrow_usdt"), "seller Q was not reserved")
		d.evidence("seller_hold_platform_quote_and_ledger_posting", hold)
	})
	t.link = d.required("cashier/" + k)
	t.order = d.required("order/" + k)
	if !d.read("channel/"+k, &t.channel) || !d.read("amount/"+k, &t.amount) {
		t.step("订单通道", func() {
			order, code, money := t.readOrderRoute()
			require(order == t.order, "saved order differs from payment order")
			d.put("channel/"+k, code)
			d.put("amount/"+k, money)
		})
		t.channel, t.amount = d.required("channel/"+k), d.required("amount/"+k)
	}
	return t
}
func (t tradeRun) paid(copies int) {
	d := t.d
	t.step("收银与主动查单", func() {
		if copies > 1 {
			t.setScenario(object{"callback_copies": copies})
		}
		d.cashier(t.link, true)
		t.observePaid(copies)
	})
}

func (t tradeRun) observePaid(copies int) {
	d := t.d
	waitFor("acknowledged callback copies and ledger OrderPaid", 60*time.Second, func() bool {
		var rows []object
		decode(d.sim("GET", "/__test/deliveries", nil), &rows)
		matches := []object{}
		event := ""
		for _, r := range rows {
			if r["account_id"] == simulatorAccount(t.channel) && r["order_id"] == t.order && r["ack"] == true {
				if event == "" {
					event = str(r, "event_id")
				}
				require(str(r, "event_id") == event, "callback copy event ID mismatch")
				matches = append(matches, r)
			}
		}
		v := d.ledgerTrade(t.order)
		if len(matches) >= copies && v["paid_verified_at"] != nil {
			paid := d.rows("ledger", "ledger_trade_payments", "SELECT source_event_id,source_sequence,expected_version,paid_verified_at,encode(query_evidence_sha256,'hex') AS query_evidence_sha256 FROM ledger_trade_payments WHERE order_id=$1", t.order)
			events := d.rows("payment", "payment_outbox", "SELECT event_id,sequence FROM payment_outbox WHERE event_type='OrderPaid' AND order_id=$1", t.order)
			require(len(paid) == 1 && len(events) == 1 && paid[0]["source_event_id"] == events[0]["event_id"] && paid[0]["source_sequence"] == events[0]["sequence"], "OrderPaid evidence mismatch")
			d.evidence("active_query_and_OrderPaid", paid)
			d.evidence("upstream_callbacks", matches)
			d.chainEvidence(t.order)
			return true
		}
		return false
	})
}
func (t tradeRun) terminal(status string) object {
	d := t.d
	waitFor(status, 2*time.Minute, func() bool { return d.ledgerTrade(t.order)["status"] == status })
	return d.chainEvidence(t.order)
}
func (t tradeRun) finish(released bool) object {
	d := t.d
	k := d.scope + "/" + t.name
	var before object
	require(d.read("balances/"+k, &before), "missing baseline")
	after := normalized(d.balanceSnapshot(k + "/after/" + id()))
	h := d.ledgerTrade(t.order)
	q, n, f := num(h, "escrow_usdt"), num(h, "recipient_usdt"), num(h, "platform_fee_usdt")
	require(q == n+f, "Q differs from N+F")
	if !released {
		q, n, f = 0, 0, 0
	}
	d.evidence("after", after)
	if d.liveEPay {
		delta := object{}
		for _, balance := range []string{"seller", "merchant", "ledger_fee_accounts"} {
			delta[balance] = num(after, balance) - num(before, balance)
		}
		d.evidence("balance_delta_usdt_micro", delta)
	}
	checkBalanceDelta(before, after, -q, n, f)
	return after
}

func checkBalanceDelta(before, after object, seller, merchant, fees int64) {
	require(num(after, "seller")-num(before, "seller") == seller && num(after, "merchant")-num(before, "merchant") == merchant &&
		num(after, "ledger_fee_accounts")-num(before, "ledger_fee_accounts") == fees, "卖方可用、商户可用或三项费用余额变化不符")
}
func (t tradeRun) release() object {
	step := t.step("风控到期与独立放币", func() {
		t.terminal("RELEASED")
		h := t.d.ledgerTrade(t.order)
		require(h["risk_release_at"] != nil && num(h, "released_seq") > num(h, "reserve_seq"), "missing release journal")
		auth := t.d.rows("reconciliation", "reconciliation_authorizations/outbox", "SELECT a.authorization_id,a.control_version,a.issued_at,o.sequence FROM reconciliation_authorizations a JOIN reconciliation_outbox o ON o.event_id=a.authorization_id WHERE a.order_id=$1 AND a.event_type='TradeReleaseAuthorized'", t.order)
		require(len(auth) == 1, "expected one independent release authorization")
		issued, e := time.Parse(time.RFC3339Nano, str(auth[0], "issued_at"))
		check(e)
		deadline, e := time.Parse(time.RFC3339Nano, str(h, "risk_release_at"))
		check(e)
		require(!issued.Before(deadline), "release authorization predates risk deadline")
		calls := t.d.rows("reconciliation", "reconciliation_verification_evidence", "SELECT id,verified_at FROM reconciliation_verification_evidence WHERE order_id=$1 AND eligible AND operation='query_payment' AND convert_from(record_json,'UTF8')::jsonb->>'Outcome'='paid'", t.order)
		require(len(calls) > 0, "missing independent paid verification")
		t.d.evidence("reconciliation_release", auth)
		if t.d.liveEPay {
			t.d.evidence("independent_paid_observations", calls)
		}
		t.finish(true)
	})
	return obj(step.Evidence["after"])
}
func (t tradeRun) notify() {
	t.step("商户验签回执", func() {
		waitFor("signed merchant notification", 90*time.Second, func() bool {
			var rs []receipt
			decode(t.d.fixtureRecord("notifications.json"), &rs)
			for _, r := range rs {
				if r.MerchantOrder == t.number && r.Trade == t.d.required("trade-no/"+t.d.scope+"/"+t.name) && r.Money == t.amount && r.PID == t.d.required("pid/v1") {
					t.d.evidence("merchant_receipt", r)
					return true
				}
			}
			return false
		})
	})
}

func (t tradeRun) backdateUnpaid() {
	seconds, err := strconv.ParseInt(t.d.required(channelKey(t.channel, "unpaid-timeout")), 10, 64)
	check(err)
	fields := object{"query_addtime_backdate_seconds": seconds + 120}
	t.setScenario(fields)
	t.d.evidence("未付超时（秒）", seconds)
	t.d.evidence("模拟器场景", fields)
}

// Pay only inside the late-payment window after the first independent
// closed/unpaid observation, before any second one.
func (t tradeRun) awaitFirstUnpaid(obs string) {
	d := t.d
	waitFor("first independent closed/unpaid", time.Minute, func() bool {
		rs := d.rows("reconciliation", "reconciliation_verification_evidence", obs, t.order)
		count := 0
		var first object
		for _, r := range rs {
			if r["outcome"] == "closed_unpaid" {
				count++
				first = r
			}
		}
		require(count < 2, "second unpaid observation already occurred")
		if count == 1 {
			observed, e := time.Parse(time.RFC3339Nano, str(first, "verified_at"))
			check(e)
			require(time.Now().Before(observed.Add(5*time.Second)), "late-payment window already closed")
			d.evidence("first_observation", rs)
			return true
		}
		return false
	})
}

func (t tradeRun) inferredCloseEvidence() {
	d := t.d
	audits := d.facts("payment", "关单审计", `SELECT id,action,occurred_at FROM payment_audit_logs
		WHERE target_id=$1 AND action='order.close_skipped_unsupported'`, t.order)
	require(len(audits) > 0, "missing unsupported close audit")
	queries := d.facts("payment", "超时推定关单的查单记录", `SELECT exchange_id,upstream_code,occurred_at FROM payment_gateway_executions
		WHERE order_id=$1 AND operation='query_payment' AND category='succeeded' AND upstream_code='timeout_inferred_close' ORDER BY occurred_at`, t.order)
	require(len(queries) > 0, "missing timeout-inferred query completion")
	events := d.facts("payment", "取消核验请求", `SELECT event_id,sequence FROM payment_outbox
		WHERE order_id=$1 AND event_type='OrderCancellationVerificationRequested'`, t.order)
	require(len(events) > 0, "missing cancellation verification request")
}

func (d *driver) cancel(late bool) {
	name := "未付"
	if late {
		name = "迟付"
	}
	t := d.trade(name, "v2")
	t.step("关单", func() {
		if t.channel == epayChannel {
			t.backdateUnpaid()
		} else if late {
			t.setScenario(object{"late_payment": true})
		}
		d.epay("v2", "/api/pay/close", url.Values{"out_trade_no": {t.number}})
	})
	const obs = `SELECT id,verified_at,convert_from(record_json,'UTF8')::jsonb->>'Outcome' AS outcome,
		convert_from(record_json,'UTF8')::jsonb->>'Kind' AS kind FROM reconciliation_verification_evidence
		WHERE order_id=$1 AND eligible AND operation='query_payment' ORDER BY verified_at`
	if !late {
		if d.scope == kLedgerCancelEvent {
			t.archiveCancellationWork()
		}
		t.step("二次未付核验并归还", func() {
			t.terminal("CANCELLED")
			if d.scope == kLedgerCancelEvent {
				t.checkCancellationProjection()
			}
			rows := d.rows("reconciliation", "reconciliation_verification_evidence", obs, t.order)
			var first, last time.Time
			for _, r := range rows {
				if r["outcome"] == "closed_unpaid" {
					v, e := time.Parse(time.RFC3339Nano, str(r, "verified_at"))
					check(e)
					if first.IsZero() {
						first = v
					}
					last = v
				}
			}
			require(!first.IsZero() && last.Sub(first) >= 5*time.Second, "missing two separated closed/unpaid observations")
			d.evidence("independent_observations", rows)
			if t.channel == epayChannel {
				t.inferredCloseEvidence()
			}
			t.finish(false)
		})
		return
	}
	t.step("两次观察之间迟付", func() {
		// Any eligible paid observation after the first closed/unpaid one shows the
		// late payment. Payment may find it first and start the release review, so
		// reconciliation can record it under either kind. A resumed step accepts it.
		paidAfterFirst := func(rs []object) bool {
			unpaid := false
			for _, r := range rs {
				if r["outcome"] == "closed_unpaid" {
					unpaid = true
				} else if unpaid && r["outcome"] == "paid" {
					return true
				}
			}
			return false
		}
		if !paidAfterFirst(d.rows("reconciliation", "reconciliation_verification_evidence", obs, t.order)) {
			t.awaitFirstUnpaid(obs)
			d.cashier(t.link, true)
		}
		waitFor("independent paid observation after late payment", time.Minute, func() bool {
			rs := d.rows("reconciliation", "reconciliation_verification_evidence", obs, t.order)
			if paidAfterFirst(rs) {
				d.evidence("independent_observations", rs)
				return true
			}
			return false
		})
		d.chainEvidence(t.order)
		if t.channel == epayChannel {
			t.inferredCloseEvidence()
		}
		require(d.ledgerTrade(t.order)["status"] != "CANCELLED" && len(d.rows("ledger", "ledger_trade_authorizations", "SELECT source_event_id FROM ledger_trade_authorizations WHERE order_id=$1 AND event_type='TradeCancellationAuthorized'", t.order)) == 0, "late payment released escrow as unpaid")
		d.evidence("after", d.balanceSnapshot(d.scope+"/late"))
	})
	t.release()
	if t.channel == epayChannel {
		t.step("无取消授权", func() {
			auth := d.facts("reconciliation", "取消授权", `SELECT authorization_id FROM reconciliation_authorizations
				WHERE order_id=$1 AND event_type='TradeCancellationAuthorized'`, t.order)
			require(len(auth) == 0, "cancellation authorization issued for late payment")
		})
	}
}
func (d *driver) refund(after bool) {
	t := d.refundTrade("退款", "v2")
	t.paid(1)
	branch := "PRE_RELEASE"
	if after {
		t.release()
		branch = "POST_RELEASE"
	}
	// Check the intended branch before the command. A lost response can be
	// replayed even after payment has already reserved this refund.
	t.step("核对退款前担保", func() {
		h := d.ledgerTrade(t.order)
		require(after && h["status"] == "RELEASED" || !after && h["status"] == "RESERVED" && h["released_seq"] == nil, "wrong trade state before merchant refund")
	})
	step := t.step("商户申请人工退款", func() {
		_, reply := d.signedEPay("v2", "/api/pay/refund", t.refundParams())
		require(num(reply, "code") == -1 && reply["msg"] == "退款已受理，等待处理" && reply["out_refund_no"] == t.number, "missing signed manual refund acceptance")
		d.evidence("refund_id", str(reply, "refund_no"))
	})
	refund := str(step.Evidence, "refund_id")
	post := t.manualRefund(refund)
	t.step("核对退款分支与余额", func() {
		require(post["branch"] == branch, "wrong refund reservation branch")
		t.noUpstreamRefund()
		t.finish(false)
	})
	t.step("商户查询退款终态", func() {
		reply := d.epay("v2", "/api/pay/refundquery", url.Values{"out_refund_no": {t.number}})
		require(reply["refund_no"] == refund && reply["out_refund_no"] == t.number && reply["money"] == t.amount, "signed refund query differs from settled refund")
	})
}
func (t tradeRun) refundParams() url.Values {
	return url.Values{"out_trade_no": {t.number}, "out_refund_no": {t.number}, "money": {t.amount}}
}

func (t tradeRun) registerDispute(after bool) {
	d := t.d
	t.step("登记争议与双方举证", func() {
		r := d.browser("operations").write("dispute", "/disputes", func() object {
			h := d.ledgerTrade(t.order)
			d.evidence("登记前的订单担保", h)
			if after {
				require(h["status"] == "RELEASED" && num(h, "released_seq") > 0, "登记放币后争议需要已放币的原单")
			} else {
				require(h["released_seq"] == nil, "dispute needs original escrow")
			}
			recipient := d.bot("recipient-order", "/order "+d.required("app/"+t.proto)+" "+t.order)
			return object{"order_id": t.order, "escrow_reservation_id": str(h, "escrow_reservation_id"), "expected_control_version": num(h, "control_version"), "reason": "核对本单收款状态", "evidence": object{"recipient_evidence": b64.EncodeToString([]byte(recipient)), "investigation": "商户本人订单查询记录"}}
		})
		di := str(r, "dispute_id")
		d.put("dispute/"+t.order, di)
		d.evidence("dispute_id", di)
		b := d.browser("seller")
		p := "/accounts/" + d.required("seller-account")
		record := b.api("GET", p+"/orders/"+t.order, "", nil)
		path := p + "/disputes/" + di
		v := b.api("GET", path, "", nil)
		b.write("seller-evidence", path+"/evidence", func() object {
			return object{"expected_evidence_version": num(v, "evidence_version"), "evidence": b64.EncodeToString(encoded(record))}
		})
	})
}
func (d *driver) dispute() {
	t := d.trade("争议", "v1")
	t.paid(1)
	t.registerDispute(false)
	t.step("裁决双批与复核", func() {
		p := "/disputes/" + d.required("dispute/"+t.order)
		d.browser("risk").approve("ruling", "payment", p+"/rulings", "/dispute-rulings", object{"expected_control_version": num(d.ledgerTrade(t.order), "control_version"), "outcome": "release_to_original_recipient", "reason": "双方真实订单记录一致"})
		t.terminal("RELEASED")
		t.finish(true)
	})
}

var scenarios = map[string]func(*driver){
	ledgerReadOnlyExit: (*driver).runLedgerReadOnlyExit,
	ledgerCarryover:    (*driver).runLedgerCarryover,
	kQueryTransient:    (*driver).runKQueryTransient,
	kLedgerCancelEvent: func(d *driver) { d.cancel(false) },

	a145NeverSent:     (*driver).runA145NeverSent,
	a145StaleBinding:  (*driver).runA145StaleBinding,
	a145UnpaidBeforeT: (*driver).runA145UnpaidBeforeT,
	a145LatePayment:   (*driver).runA145LatePayment,
	a145Refusals:      (*driver).runA145Refusals,
	a144NotSent:       (*driver).runA144NotSent,
	a144NotFound:      (*driver).runA144NotFound,
	livePhase:         (*driver).runLiveEPay,
	"coverage":        (*driver).coverage,
	"seller-offline":  (*driver).sellerOffline,
	"bot-notices":     (*driver).botNotices,
	"statement":       (*driver).statement,
	"archived-work":   (*driver).archivedWork,
	"main":            func(d *driver) { d.releasedTrade(1) },
	"duplicates": func(d *driver) {
		d.releasedTrade(3)
		d.duplicateEnvelope()
		d.staleAuthorization()
	},
	"cancel":                        func(d *driver) { d.cancel(false); d.cancel(true) },
	"refund-insufficient":           (*driver).insufficient,
	"manual-refund":                 (*driver).platformRefundSuccess,
	"manual-refund-failure":         (*driver).platformRefundFailure,
	"late-payment":                  (*driver).latePayment,
	"settle-refunds":                (*driver).settleRefunds,
	"refund-before-release":         func(d *driver) { d.refund(false) },
	"refund-after-release":          func(d *driver) { d.refund(true) },
	"dispute":                       (*driver).dispute,
	"dispute-refund-before-release": func(d *driver) { d.disputeRefund(false) },
	"dispute-refund-after-release":  func(d *driver) { d.disputeRefund(true) },
}

func (d *driver) releasedTrade(copies int) {
	t := d.trade("担保", "v1")
	t.paid(copies)
	t.notify()
	t.release()
}

func (d *driver) run(s string) {
	var complete bool
	if s == "settle-refunds" {
		scenarios[s](d)
		return
	}
	if d.read("finished/"+d.scope, &complete) && complete {
		if s == livePhase {
			d.disableLiveEPay()
		}
		return
	}
	if isLedgerScenario(s) {
		d.liveStep("Ledger staff sessions", func() {
			staff := []string{"finance", "approver1", "approver3"}
			if s == ledgerReadOnlyExit {
				staff = []string{"risk", "approver1", "approver2", "approver3"}
			}
			for _, n := range staff {
				d.login(n)
			}
		})
	} else {
		d.orderSessions(s)
	}
	scenarios[s](d)
	d.put("finished/"+d.scope, true)
}

func (d *driver) orderSessions(s string) {
	d.liveStep("场景会话与行情", func() {
		d.required("seller-account")
		d.required("merchant-account")
		d.login("seller")
		d.login("operations")
		// IAM ends an idle Telegram session after 30 minutes. A merchant logs in
		// again with /start, which is idempotent for an existing registration.
		reply := d.bot(fmt.Sprintf("session/%s/%d", s, time.Now().UnixNano()), "/start")
		if !strings.Contains(reply, "注册或登录已完成") {
			// IAM counts every /start for this user (setup and earlier scenarios
			// included), so the driver's local estimate can be short. Retry once
			// after a full registration window.
			_, window := startPolicy(d.env("iam"))
			d.trace(fmt.Sprintf("商户 /start 被拒绝，等待一个完整的注册窗口 %s 后重试一次", window+startMargin))
			d.sleep(window + startMargin)
			reply = d.bot(fmt.Sprintf("session/%s/%d", s, time.Now().UnixNano()), "/start")
		}
		require(strings.Contains(reply, "注册或登录已完成"), "merchant Telegram login refused")
		d.refreshMarket()
	})
}

// This branch can resume after an independently authorized spend of the recipient funds.
func (d *driver) insufficient() {
	t := d.refundTrade("余额不足样本", "v2")
	t.paid(1)
	t.release()
	t.step("可用不足时不先退法币", func() {
		balance := d.bot("insufficient/balance/"+id(), "/balance")
		available := micro(capture(`(?m)^可用 ([0-9]+\.[0-9]{6})$`, balance))
		hold := d.ledgerTrade(t.order)
		n := num(hold, "recipient_usdt")
		d.evidence("required_N", n)
		d.evidence("merchant_available", available)
		require(str(hold, "status") == "RELEASED", "negative sample must still be released")
		if available >= n {
			stop("缺样本：本单已放币；请在商户独立支用余额至低于 N 后续跑负例")
		}
		_, reply := d.signedEPay("v2", "/api/pay/refund", t.refundParams())
		require(num(reply, "code") == -1, "expected negative EPay refund receipt")
		switch reply["msg"] {
		case "当前状态不允许此操作":
			// Payment maps a definitive ledger refusal to FailedPrecondition.
		case "退款已受理，等待处理":
			require(reply["out_refund_no"] == t.number, "wrong reserving refund receipt")
			d.evidence("accepted_refund_id", str(reply, "refund_no"))
		default:
			stop("unexpected EPay refund refusal")
		}
		d.evidence("epay_reply", reply["msg"])
		var refused object
		waitFor("definitive refund reserve refusal", time.Minute, func() bool {
			rows := d.rows("payment", "拒绝退款预留", `SELECT f.id,f.status,f.stage,a.action,
				f.data ? 'reservation' AS reserved,f.data ? 'upstream_refund_id' AS sent
				FROM payment_refunds f JOIN payment_audit_logs a ON a.target_type='refund' AND a.target_id=f.id::text
				WHERE f.order_id=$1 AND f.out_refund_no=$2 AND f.mode='manual' AND a.action='refund.reserve_rejected_FailedPrecondition' AND a.result='failed'`, t.order, t.number)
			if len(rows) == 0 {
				return false
			}
			refused = oneFact(rows, "refused refund")
			d.evidence("refused_reservation", refused)
			return true
		})
		require(refused["stage"] == "stopped" && num(refused, "status") == 1 && refused["reserved"] == false && refused["sent"] == false, "refund advanced past failed reservation")
		if reply["refund_no"] != nil {
			require(reply["refund_no"] == refused["id"], "refusal is for a different refund")
		}
		require(len(t.reservations()) == 0, "unexpected debit reservation")
		require(len(d.facts("payment", "卖方退款凭证", "SELECT id FROM payment_seller_refund_evidence WHERE refund_id=$1", str(refused, "id"))) == 0, "seller evidence exists for a refused reservation")
		t.noUpstreamRefund()
		end := d.chainEvidence(t.order)
		require(end["status"] == "RELEASED" && end["latest_seq"] == hold["latest_seq"], "reservation refusal changed the trade")
	})
}
