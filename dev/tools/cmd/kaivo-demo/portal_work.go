package main

import (
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"os"
	"time"
)

// The reauthentication grant binds the RPC command (including its idempotency
// key), not the HTTP JSON. Both encodings have published v0.15 test vectors.
type portalCommand struct {
	path, template, permission, key string
	body                            object
	digest                          [32]byte
}

func commandPrefix(method, key string) []byte {
	return webCommandPrefix("/aipay.payment.v1."+method, key)
}

func webCommandPrefix(fullMethod, key string) []byte {
	return appendField(appendField(appendField(nil, "aipay.web.command.v1"), fullMethod), key)
}

func onlineCommand(account, channel, key, reason string, version int64, online bool) portalCommand {
	b := appendField(commandPrefix("SellerPortalService/SetSellerChannelOnline", key), channel)
	flag := byte(0)
	if online {
		flag = 1
	}
	b = append(b, 1, flag) // optional bool is present, including when false
	b = binary.BigEndian.AppendUint64(b, uint64(version))
	return portalCommand{"/accounts/" + account + "/channels/" + channel + "/online", "/accounts/:seller_account_id/channels/:id/online", "payment.channel.online", key,
		object{"online": online, "expected_seller_online_version": version, "reason": reason}, sha256.Sum256(appendField(b, reason))}
}

func requeueCommand(kind, target, key, reason string, version int64) portalCommand {
	b := appendField(appendField(commandPrefix("PaymentAdminService/RequeueArchivedWork", key), kind), target)
	b = binary.BigEndian.AppendUint64(b, uint64(version))
	return portalCommand{"/archived-work/" + kind + "/" + target + "/requeue", "/archived-work/:kind/:object_id/requeue", "payment.work.requeue", key,
		object{"expected_version": version, "reason": reason}, sha256.Sum256(appendField(b, reason))}
}

func (b *browser) grant(c portalCommand) string {
	b.d.login(b.name)
	scope := object{"type": "platform"}
	if b.name == "seller" {
		scope = object{"type": "account", "account_type": "personal", "account_id": b.d.required("seller-account")}
	}
	b.d.awaitMFA(b.name)
	begin := b.post("/auth/reauth", object{"password": b.d.password(b.name), "target": object{"acting_scope": scope,
		"binding": object{"http_method": "POST", "http_path": b.prefix + c.template, "permission": c.permission, "body_sha256": b64.EncodeToString(c.digest[:])}}})
	require(begin["challenge_purpose"] == "reauthentication", "expected command reauthentication challenge")
	reply := b.verifyMFA(begin)
	require(reply["state"] == "authenticated" && obj(reply["session"])["user_id"] == b.d.required("user/"+b.name), "reauthenticated actor mismatch")
	return str(obj(reply["reauthentication"]), "reauthentication_id")
}

func channelState(seller, platform object, account, channel string, online bool, version, control int64) object {
	cfg := obj(platform["configuration"])
	require(seller["seller_account_id"] == account && seller["channel_account_id"] == channel && cfg["seller_account_id"] == account && cfg["channel_account_id"] == channel, "channel owner or ID mismatch")
	require(seller["online"] == online && platform["seller_online"] == online && seller["platform_enabled"] == true && cfg["enabled"] == true, "seller or platform channel state mismatch")
	require(num(seller, "seller_online_version") == version && num(platform, "seller_online_version") == version && num(platform, "control_version") == control && num(seller, "control_version") == control, "seller or platform version mismatch")
	require(seller["seller_online_changed_at"] == platform["seller_online_changed_at"], "seller and platform change times differ")
	return object{"channel_account_id": channel, "online": online, "seller_online_version": version, "control_version": control, "changed_at": seller["seller_online_changed_at"]}
}

func (d *driver) sellerOffline() {
	seller, op := d.browser("seller"), d.browser("operations")
	amount, code := scenarioOrder("seller-offline", d.gatewayMode())
	account, ch := d.required("seller-account"), d.required(channelKey(code, "uuid/channel"))
	path := "/accounts/" + account + "/channels/" + ch
	var initial object
	baseline := "唯一演示通道"
	if code == epayChannel {
		baseline = "EPay 卖方通道"
	}
	d.step(baseline, func() {
		var platform object
		if code == epayChannel {
			platform = op.api("GET", "/channel-accounts/"+ch, "", nil)
		} else {
			list := op.api("GET", "/channel-accounts?limit=2", "", nil)
			items, ok := list["items"].([]any)
			require(ok && len(items) == 1 && list["next_cursor"] == nil, "expected exactly one demo channel")
			platform = obj(items[0])
		}
		require(obj(platform["configuration"])["channel_code"] == code, "unexpected seller channel code")
		initial = channelState(seller.api("GET", path, "", nil), platform, account, ch, true, num(platform, "seller_online_version"), num(platform, "control_version"))
		d.put("offline/baseline", initial)
		d.evidence("baseline", initial)
	})
	d.read("offline/baseline", &initial)
	version, control := num(initial, "seller_online_version"), num(initial, "control_version")
	t := d.trade("在途", "v2")
	change := func(c portalCommand, grant string, online bool, want int64) string {
		reply := seller.apiGrant("POST", c.path, c.key, c.body, grant)
		platform := op.api("GET", "/channel-accounts/"+ch, "", nil)
		channelState(reply, platform, account, ch, online, want, control)
		state := channelState(seller.api("GET", path, "", nil), platform, account, ch, online, want, control)
		d.evidence("seller_and_platform", state)
		return str(state, "changed_at")
	}
	off := onlineCommand(account, ch, d.key("offline"), "暂停演示通道接单", version, false)
	// Obtain the TOTP grant before paying so waiting for a new TOTP time step
	// cannot consume the trade's twenty-second risk window.
	var grant string
	if d.data["step/"+d.scope+"/卖方下线"] == nil {
		d.liveStep("下线命令近期认证", func() { grant = seller.grant(off) })
	}
	t.paid(1)
	d.step("卖方下线", func() {
		d.put("offline/changed_at", change(off, grant, false, version+1))
	})
	d.step("下线期间拒绝新订单", func() {
		number := d.key("offline/rejected")
		code, r := d.signedEPay("v2", "/api/pay/create", d.createParams(number, amount))
		require(code == 200 && num(r, "code") == -1 && r["msg"] == "支付通道不可用" && r["pay_info"] == nil, "expected signed no-channel rejection")
		rows := d.rows("payment", "payment_orders", "SELECT id FROM payment_orders WHERE application_id=$1 AND out_trade_no=$2", d.required("app/v2"), number)
		require(len(rows) == 0, "offline order was inserted")
		d.evidence("rejection", object{"out_trade_no": number, "code": -1, "message": r["msg"], "payment_order_count": len(rows)})
	})
	t.release()
	d.step("卖方重新上线", func() {
		c := onlineCommand(account, ch, d.key("online"), "恢复演示通道接单", version+1, true)
		d.put("online/changed_at", change(c, seller.grant(c), true, version+2))
	})
	d.step("在途付款与放币跨越下线时刻", func() {
		offTime, onTime := d.required("offline/changed_at"), d.required("online/changed_at")
		row := oneFact(d.facts("ledger", "release_journal", `SELECT r.order_id,r.paid_verified_at,t.seq,t.recorded_at,
            (r.paid_verified_at <= $2::timestamptz AND t.recorded_at BETWEEN $2 AND $3::timestamptz) AS spans_offline
            FROM ledger_trade_reservations r JOIN ledger_transactions t ON t.seq=r.released_seq WHERE r.order_id=$1`, t.order, offTime, onTime), "在途分录")
		require(row["spans_offline"] == true, "order was not paid before and released after going offline")
	})
	resumed := d.trade("上线后新单", "v2")
	resumed.paid(1)
	resumed.release()
}

const requeueReason = "核对模拟上游后恢复演示订单查询"

func (d *driver) archivedWork() {
	d.step("开通平台运维", func() { d.invite("sre", "sre"); d.login("sre") })
	b := d.browser("sre")
	t := d.trade("归档样本", "v2")
	t.step("持续返回未知查单结果", func() {
		if t.channel == epayChannel {
			t.setScenario(object{"api_fault": "malformed"})
		} else {
			t.setScenario(object{"query_unknown": true})
		}
	})
	d.step("平台列出本单归档任务", func() {
		budget := 3 * time.Hour
		if v := os.Getenv("AIPAY_DEMO_ARCHIVE_WAIT"); v != "" {
			var err error
			budget, err = time.ParseDuration(v)
			require(err == nil && budget >= 0, "invalid AIPAY_DEMO_ARCHIVE_WAIT")
		}
		end := time.Now().Add(budget)
		var sample object
		var firstFailure []object
		for {
			sample = oneFact(d.facts("payment", "sample_work", `SELECT object_id,attempts,available_at,archived_at,completed_at FROM payment_work WHERE kind='order' AND object_id=$1`, t.order), "演示订单任务")
			if t.channel == epayChannel && len(firstFailure) == 0 {
				firstFailure = d.facts("payment", "首次查单失败", `SELECT exchange_id,occurred_at,category,error_code
					FROM payment_gateway_executions WHERE order_id=$1 AND operation='query_payment'
					AND category='unknown' AND error_code='upstream_unknown' AND responses>0 ORDER BY occurred_at LIMIT 1`, t.order)
			}
			d.report()
			if sample["archived_at"] != nil || sample["completed_at"] != nil || !time.Now().Before(end) {
				break
			}
			d.sleep(min(10*time.Second, time.Until(end)))
		}
		d.login("sre")
		path := "/archived-work?kind=order&page_size=100"
		next := ""
		seenTokens := map[string]bool{}
		for {
			page := b.api("GET", path+next, "", nil)
			items, ok := page["items"].([]any)
			require(ok, "invalid archived task list")
			if row := archivedOrder(items, t.order); row != nil {
				require(t.channel != epayChannel || len(firstFailure) == 1, "archived EPay order has no failed upstream query")
				require(sample["archived_at"] == nil || sameInstant(row["archived_at"], sample["archived_at"]), "portal archived time differs from work row")
				d.put("archive/original", row)
				d.evidence("archived", row)
				return
			}
			token, _ := page["next_page_token"].(string)
			if token == "" {
				break
			}
			require(!seenTokens[token], "archived list repeated a pagination token")
			seenTokens[token] = true
			next = "&page_token=" + url.QueryEscape(token)
		}
		require(sample["archived_at"] == nil, "payment_work 已归档，但平台归档清单缺少同一任务")
		stop("缺样本：本单尚未出现在归档清单。保持 payment worker 和模拟上游运行，到期后重跑 archived-work 将沿用同一单。")
	})
	var original object
	d.read("archive/original", &original)
	t.step("上游恢复与运维重新入队", func() {
		t.setScenario(object{})
		c := requeueCommand("order", t.order, d.key("requeue/"+t.order), requeueReason, num(original, "version"))
		r := b.apiGrant("POST", c.path, c.key, c.body, b.grant(c))
		require(r["object_id"] == t.order && r["kind"] == "order" && r["archived_at"] == nil && num(r, "attempts") == 0 && num(r, "version") == num(original, "version")+1 && r["last_error_code"] == original["last_error_code"], "unexpected requeue result")
		d.evidence("restored", r)
	})
	t.step("恢复审计与 worker 再次领取", func() {
		audit := oneFact(d.facts("payment", "requeue_audit", `SELECT id,actor_id,occurred_at,changes#>>'{metadata,reason}' AS reason,
          changes#>>'{before,last_error_code}' AS last_error_code,(changes#>>'{before,attempts}')::int AS attempts
          FROM payment_audit_logs WHERE action='payment.admin.RequeueArchivedWork' AND result='accepted' AND target_type='payment_work'
          AND target_id=$1 AND actor_type='user' AND changes#>>'{metadata,kind}'='order' AND (changes#>>'{before,version}')::bigint=$2`, t.order, num(original, "version")), "恢复审计")
		require(audit["actor_id"] == d.required("user/sre") && audit["reason"] == requeueReason && audit["attempts"] == original["attempts"] && audit["last_error_code"] == original["last_error_code"], "requeue audit mismatch")
		waitFor("payment worker reclaimed restored task", 90*time.Second, func() bool {
			row := oneFact(d.facts("payment", "worker_after_requeue", `SELECT version,attempts,completed_at,archived_at,
                completed_at >= $2::timestamptz AS completed_after FROM payment_work WHERE kind='order' AND object_id=$1`, t.order, str(audit, "occurred_at")), "恢复后任务")
			if t.channel == epayChannel {
				// A successful pending poll can reset attempts before we observe the claim.
				queried := d.facts("payment", "恢复后的查单", `SELECT exchange_id,occurred_at FROM payment_gateway_executions
					WHERE order_id=$1 AND operation='query_payment' AND category='succeeded' AND occurred_at >= $2 ORDER BY occurred_at LIMIT 1`,
					t.order, str(audit, "occurred_at"))
				return num(row, "version") == num(original, "version")+1 && len(queried) > 0
			}
			return reclaimedWork(row, num(original, "version"))
		})
	})
	t.step("关闭已验收的未付样本", func() {
		d.login("seller")
		d.login("operations")
		d.refreshMarket()
		if t.channel == epayChannel {
			// Restoring an old order can itself register the A140 system intent.
			order := oneFact(d.facts("payment", "恢复后的订单",
				"SELECT close_requested,close_reason FROM payment_orders WHERE id=$1", t.order), "恢复后的订单")
			if order["close_requested"] == true {
				t.terminal("CANCELLED")
				t.setScenario(object{})
				return
			}
			t.backdateUnpaid()
		}
		d.epay("v2", "/api/pay/close", url.Values{"out_trade_no": {t.number}})
		t.terminal("CANCELLED")
		if t.channel == epayChannel {
			t.setScenario(object{})
		}
	})
}

func archivedOrder(items []any, order string) object {
	for _, item := range items {
		r := obj(item)
		if r["kind"] != "order" || r["object_id"] != order {
			continue
		}
		require(r["object_type"] == "order" && num(r, "attempts") > 0 && num(r, "version") > 0, "invalid archived work")
		str(r, "archived_at")
		str(r, "last_error_code")
		return r
	}
	return nil
}

func reclaimedWork(row object, archivedVersion int64) bool {
	return num(row, "version") == archivedVersion+1 && (num(row, "attempts") > 0 || row["completed_after"] == true)
}
