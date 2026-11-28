package main

import (
	"fmt"
	"time"
)

const (
	riskExtensionPlatform             = "risk-extension-platform"
	riskExtensionSellerRejected       = "risk-extension-seller-rejected"
	riskExtensionSuperseded           = "risk-extension-superseded"
	mismatchReverify                  = "mismatch-reverify"
	mismatchRefund                    = "mismatch-refund"
	mismatchRefundFailed              = "mismatch-refund-failed"
	p34OrderMinor               int64 = 200
	extensionSeconds            int64 = 600
)

// A fresh run gets a fresh order, policy and command keys. Losing a later
// checkpoint still replays the original command with its original body.
func recoveryScenario(run func(*driver)) func(*driver) {
	return func(d *driver) {
		require(d.native() && d.gatewayMode() && d.env("reconciliation")["AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS"] != "", "recovery scenarios require the native trade and verification gateways")
		d.step("Identify the recovery run", func() { d.evidence("run_id", id()) })
		base := d.scope
		d.scope = base + "/" + str(d.active.Evidence, "run_id")
		defer func() { d.scope = base }()
		run(d)
	}
}

func (d *driver) recoveryTrade(extension bool) tradeRun {
	number := d.key(d.scope + "/EPay")
	t := tradeRun{d: d, name: "EPay", number: number, proto: "v2", channel: epayChannel, amount: "2.00"}
	channel := d.required("uuid/" + channelKey(epayChannel, "channel"))
	var policy string
	if extension {
		policy = t.extensionPolicy(channel)
	}
	if !extension && d.history.Scenario == mismatchReverify {
		t.baseline()
	}
	created := t.step("Create the order on the simulator channel", func() {
		d.refreshMarket()
		receipt := d.epay("v2", "/api/pay/create", d.createParams(t.number, t.amount))
		row := oneFact(d.rows("payment", "locked order quote", `SELECT id,trade_no,channel_account_id,channel_code,
			data#>>'{snapshot,trade,risk_policy_version}' AS policy,
			(data#>>'{snapshot,trade,hold_duration_seconds}')::bigint AS hold,
			(data#>>'{snapshot,trade,quote,fiat_amount}')::bigint AS cents
			FROM payment_orders WHERE account_id=$1 AND application_id=$2 AND out_trade_no=$3`,
			d.required("merchant-account"), d.required("app/v2"), t.number), "merchant order")
		require(row["trade_no"] == receipt["trade_no"] && row["channel_code"] == epayChannel &&
			row["channel_account_id"] == channel && num(row, "cents") == p34OrderMinor, "unexpected simulator order binding")
		require(!extension || row["policy"] == policy && num(row, "hold") == 20, "order did not lock the approved risk policy")
		link := str(receipt, "pay_info")
		d.cashier(link, false)
		d.put("cashier/"+t.number, link)
		d.evidence("order", row)
	})
	t.order = str(obj(created.Evidence["order"]), "id")
	t.link = d.required("cashier/" + t.number)
	if extension {
		t.restoreChannelRisk(channel, policy)
	}
	return t
}

func (d *driver) prepareRiskApprovers() {
	for _, person := range []string{"risk", approvers[0], approvers[1]} {
		d.login(person)
		d.awaitMFA(person)
	}
}

func (t tradeRun) extensionPolicy(channel string) string {
	d := t.d
	s := t.step("Approve the one-hour extension cap", func() {
		d.prepareRiskApprovers()
		label := "risk-policy/" + t.number
		var current object
		if !d.read(label+"/previous", &current) {
			current = oneFact(d.rows("payment", "channel risk policy", `SELECT control_version,data FROM payment_configuration_versions
				WHERE scope=$1 ORDER BY control_version DESC LIMIT 1`, "risk/"+channel), "current risk policy")
			d.put(label+"/previous", current)
		}
		approved := d.approveRiskVersion(label, d.key(label), channel, time.Now().UTC().Add(90*time.Second).Format(time.RFC3339),
			num(current, "control_version"), 3600)
		require(num(approved, "hold_duration_seconds") == 20 && num(approved, "exceptional_extension_seconds") == 3600, "unexpected approved risk policy")
		d.evidence("version", str(approved, "risk_policy_version"))
		d.evidence("effective_at", str(approved, "effective_at"))
	})
	d.sleep(time.Until(coverageTime(s.Evidence, "effective_at")))
	return str(s.Evidence, "version")
}

// The order has locked its version. Restore the original channel terms for
// subsequent orders unless another approved version has already replaced ours.
func (t tradeRun) restoreChannelRisk(channel, version string) {
	d := t.d
	t.step("Restore the shared channel policy for subsequent orders", func() {
		current := oneFact(d.rows("payment", "latest risk policy", `SELECT control_version,version_id FROM payment_configuration_versions
			WHERE scope=$1 ORDER BY control_version DESC LIMIT 1`, "risk/"+channel), "current risk policy")
		if current["version_id"] != version {
			d.evidence("current_policy", current["version_id"])
			return
		}
		var previous object
		require(d.read("risk-policy/"+t.number+"/previous", &previous), "missing previous channel policy")
		terms := obj(previous["data"])
		label := "restore-risk/" + t.number
		change := object{"risk_policy_version": d.key(label), "channel_account_id": channel,
			"hold_duration_seconds":            units(terms, "hold_duration_seconds"),
			"exceptional_extension_seconds":    units(terms, "exceptional_extension_seconds"),
			"dispute_handling_timeout_seconds": units(terms, "dispute_handling_timeout_seconds"),
			"expected_control_version":         current["control_version"]}
		d.prepareRiskApprovers()
		change["effective_at"] = time.Now().UTC().Add(90 * time.Second).Format(time.RFC3339)
		approved := d.browser("risk").approve(label, "payment", "/risk-policies/requests", "/risk-policies", object{"change": change})
		d.evidence("restored_policy", obj(approved["risk_policy"])["risk_policy_version"])
	})
}

func (t tradeRun) reservation() object {
	return oneFact(t.d.rows("ledger", "trade reservation", `SELECT order_id,escrow_reservation_id,status,control_version,
		paid_verified_at,risk_release_at,risk_extension_id,risk_extension_pending_until,refund_id,dispute_id,released_seq
		FROM ledger_trade_reservations WHERE order_id=$1`, t.order), "ledger reservation")
}

func (t tradeRun) releaseAt(deadline time.Time) {
	d := t.d
	t.step("Match the release authorization and ledger execution to the deadline", func() {
		d.sleep(time.Until(deadline))
		d.login("operations")
		d.evidence("expected_release_at", deadline)
		d.evidence("release_schedule_at_deadline", d.rows("reconciliation", "release schedule at deadline",
			"SELECT reason,next_attempt_at,due_at FROM reconciliation_release_schedule WHERE order_id=$1", t.order))
		latest := deadline.Add(3 * time.Minute)
		d.waitFor("release of "+t.order, time.Until(latest), func() bool { return t.reservation()["status"] == "RELEASED" })
		auth := oneFact(d.facts("ledger", "executed release", `SELECT authorization_id,effective_at,executed_at,posting_seq
			FROM ledger_trade_authorizations WHERE order_id=$1 AND event_type='TradeReleaseAuthorized' AND result_status='RELEASED'`, t.order), "executed release")
		require(coverageTime(auth, "effective_at").Equal(deadline), "release effective_at differs from the applicable risk deadline")
		executed := coverageTime(auth, "executed_at")
		require(!executed.Before(deadline) && !executed.After(latest), "ledger release executed outside the three-minute window")
		require(num(auth, "posting_seq") == num(t.reservation(), "released_seq"), "ledger release posting mismatch")
		row := oneFact(d.facts("reconciliation", "issued release", `SELECT authorization_id,issued_at FROM reconciliation_authorizations
			WHERE order_id=$1 AND event_type='TradeReleaseAuthorized'`, t.order), "independent release authorization")
		require(row["authorization_id"] == auth["authorization_id"] && !coverageTime(row, "issued_at").Before(deadline), "independent release mismatch")
		t.awaitOrderStatus("completed")
	})
}

func (t tradeRun) orderPath(suffix string) string { return "/orders/" + t.order + "/" + suffix }

func (t tradeRun) scenarioPath() string {
	return "/__test/scenarios/" + simulatorAccount(t.channel) + "/" + t.order
}

func (t tradeRun) merchantUnpaid() {
	query := t.d.epay("v2", "/api/pay/query", map[string][]string{"out_trade_no": {t.number}})
	require(query["out_trade_no"] == t.number && num(query, "status") == 0, "merchant query reported a paid order")
	t.d.evidence("merchant_status", query["status"])
}

func requireRecoveryApproval(r object, kind, order, requester string) object {
	a := obj(r["approval"])
	m := obj(a["material"])
	require(m["kind"] == kind && m["requested_by"] == requester && obj(obj(m[kind])["trade"])["order_id"] == order,
		fmt.Sprintf("unexpected %s approval for order %s", kind, order))
	return a
}
