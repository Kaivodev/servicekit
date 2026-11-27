package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"maps"
	"strings"
	"time"
)

const coveragePath = "/coverage/attestations"
const coverageModeHint = "文件覆盖模式：请运行 stack.py coverage attestation 并重启 reconciliation"

func (d *driver) coverageStatus() object {
	d.login("approver1")
	return d.browser("approver1").api("GET", "/coverage/status", "", nil)
}

func (d *driver) coverage() {
	d.requireNative("coverage")
	var status object
	d.liveStep("核对覆盖证明模式", func() {
		status = d.coverageStatus()
		d.evidence("coverage_status", status)
		// GetCoverageStatus reports the registry even when issuance uses the development file.
		require(d.env("reconciliation")["AIPAY_RECONCILIATION_COVERAGE_DEVELOPMENT_FILE"] == "" &&
			status["source"] != "development" && status["attestation_id"] != "development",
			coverageModeHint)
	})
	d.step("清理上一份有效证明", func() {
		switch status["state"] {
		case "valid", "low_margin", "not_covered":
			attID := str(status, "attestation_id")
			label := "revoke/" + attID
			const reason = "Reset the previous attestation for the native coverage demo."
			r := d.browser("approver1").write(label, coveragePath+"/"+attID+"/revocation", func() object {
				key := d.key("write/" + d.scope + "/" + label)
				hash := coverageRevocationChallenge(d.required("user/approver1"), key, attID, raw(str(status, "request_digest")), reason)
				return object{"reason": reason, "assertion": d.assert("approver1", hash[:])}
			})
			require(r["status"] == "revoked", "previous coverage attestation was not revoked")
			status = d.coverageStatus()
			require(status["state"] == "revoked" && status["attestation_id"] == attID, "revocation status differs from the previous attestation")
		}
		requireCoverageDenied(status, nil)
		d.evidence("coverage_status", status)
	})

	first := d.trade("覆盖前付款", "v2")
	first.paid(1)
	first.coverageDenied(nil)

	address := demoCoverageAddress()
	d.step("登记演示冷钱包", func() { d.registerCoverageAddress(address) })
	d.step("提交观测与双人批准", func() { d.approveCoverage(address) })
	approved := obj(d.active.Evidence["coverage_status"])
	first.step("有效证明允许原单放币", func() {
		first.terminal("RELEASED")
		rows := first.coverageAuthorizations()
		d.evidence("release_authorizations", rows)
		require(len(rows) == 1, "expected exactly one TradeReleaseAuthorized for the first order")
		require(rows[0]["attestation_id"] == approved["attestation_id"] &&
			bytes.Equal(standard(str(rows[0], "attestation_sha256")), raw(str(approved, "request_digest"))),
			"release authorization evidence does not match the approved coverage attestation")
	})

	d.step("等待同一证明到期", func() {
		expires := coverageTime(approved, "expires_at")
		d.sleep(time.Until(expires.Add(time.Second)))
		expired := d.coverageStatus()
		requireCoverageDenied(expired, approved)
		d.evidence("coverage_status", expired)
	})
	d.liveStep("到期后刷新行情与交易会话", func() {
		requireCoverageDenied(d.coverageStatus(), approved)
		d.refreshMarket()
		d.login("seller")
		d.login("operations")
		reply := d.bot("expired/session/"+id(), "/start")
		require(strings.Contains(reply, "注册或登录已完成"), "merchant Telegram login refused after attestation expiry")
	})
	second := d.trade("覆盖到期后付款", "v2")
	second.paid(1)
	second.coverageDenied(approved)
}

func requireCoverageDenied(status, expired object) {
	state := str(status, "state")
	require((state == "none" || state == "expired" || state == "revoked") && status["releases_allowed"] == false,
		"expected coverage denial, got "+state)
	if expired != nil {
		require(state == "expired" && status["attestation_id"] == expired["attestation_id"] && status["request_digest"] == expired["request_digest"],
			"expected the approved coverage attestation to be expired")
	}
}

func coverageTime(m object, field string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, str(m, field))
	require(err == nil, "invalid timestamp for "+field)
	return t
}

func (t tradeRun) coverageAuthorizations() []object {
	return t.d.rows("reconciliation", "reconciliation_authorizations", `SELECT authorization_id, order_id, issued_at,
		convert_from(evidence_material,'UTF8')::jsonb #>> '{Review,Evidence,CoverageAttestationID}' AS attestation_id,
		convert_from(evidence_material,'UTF8')::jsonb #>> '{Review,Evidence,CoverageAttestationSHA256}' AS attestation_sha256
		FROM reconciliation_authorizations WHERE order_id=$1 AND event_type='TradeReleaseAuthorized'`, t.order)
}

func (t tradeRun) coverageDenied(expired object) {
	d := t.d
	t.step("风控到期仍拒绝放币", func() {
		deadline := riskReleaseAt(d.ledgerTrade(t.order))
		// Jobs revisit pending OrderPaid each tick (1s by default). Also require a
		// post-deadline paid review so a stopped or lagging worker cannot pass.
		d.sleep(time.Until(deadline.Add(5 * time.Second)))
		waitFor("independent paid verification after risk_release_at for "+t.order, 75*time.Second, func() bool {
			rows := d.rows("reconciliation", "reconciliation_verification_evidence", `SELECT id, verified_at
				FROM reconciliation_verification_evidence WHERE order_id=$1 AND verified_at >= $2 AND eligible
				AND operation='query_payment' AND convert_from(record_json,'UTF8')::jsonb->>'Outcome'='paid'
				ORDER BY verified_at DESC LIMIT 1`, t.order, deadline)
			if len(rows) == 0 {
				return false
			}
			d.evidence("post_deadline_paid_review", rows[0])
			return true
		})
		status := d.coverageStatus()
		d.evidence("coverage_status", status)
		requireCoverageDenied(status, expired)
		h := d.ledgerTrade(t.order)
		rows := t.coverageAuthorizations()
		d.evidence("ledger_reservation", h)
		d.evidence("release_authorizations", rows)
		for _, r := range rows {
			require(r["attestation_id"] != "development", coverageModeHint)
		}
		require(h["status"] == "RESERVED" && h["released_seq"] == nil && len(rows) == 0,
			fmt.Sprintf("order %s after risk deadline: reservation=%v, release authorizations=%d", t.order, h["status"], len(rows)))
	})
}

func (d *driver) registerCoverageAddress(address string) {
	require(validCoverageAddress(address), "demo cold address failed TRON Base58Check")
	const registry = "coverage-addresses"
	run := func(action string, decl object) []object {
		path := d.declaration("coverage-address-"+action, decl)
		var rows []object
		decode(d.owner("reconciliation", "AIPAY_RECONCILIATION_REGISTRY_DATABASE_URL", "registry", registry, action, "--file", path), &rows)
		return rows
	}
	decl := object{"chain": "TRON", "address": address, "role": "cold", "label": "demo-cold", "witness": "demo-witness", "source": "demo-generated"}
	var found object
	for _, row := range run("list", object{}) {
		if row["chain"] == "TRON" && row["address"] == address {
			found = row
			break
		}
	}
	if found == nil {
		reg := maps.Clone(decl)
		reg["id"], reg["ceremony"] = d.key(d.scope+"/address"), "demo-coverage"
		rows := run("register", reg)
		require(len(rows) == 1 && rows[0]["id"] == reg["id"], "coverage registration returned an unexpected record")
		found = rows[0]
	}
	require(matchesProposal(found, decl) && found["revoked_at"] == nil, "demo cold address has different or revoked registry bindings")
	d.evidence("registered_address", found)
}

func (d *driver) approveCoverage(address string) {
	const proposer = "approver1"
	d.login(proposer)
	user := d.required("user/" + proposer)
	b := d.browser(proposer)
	// Preserve ambiguous writes, including their exact assertion bytes. A proposal
	// left pending past its signed lifetime needs a fresh observation and key.
	attemptKey := d.scope + "/submission"
	attempt := d.value(attemptKey, id)
	var previous object
	if d.read("write/"+d.scope+"/"+attempt+"/result", &previous) {
		m := obj(obj(obj(previous["approval"])["material"])["coverage_attestation"])
		if !time.Now().Before(coverageTime(m, "expires_at")) {
			detail := b.api("GET", coveragePath+"/"+str(m, "attestation_id"), "", nil)
			if detail["status"] == "pending" || detail["status"] == "approval_expired" {
				attempt = id()
				d.put(attemptKey, attempt)
			}
		}
	}
	r := b.write(attempt, coveragePath, func() object {
		return coverageSubmission(address, time.Now().Add(-3*time.Second), random(sha256.Size))
	})
	a := obj(r["approval"])
	digest := challenge("reconciliation", user, a)
	aid := str(obj(a["approval_request"]), "id")
	m := obj(obj(a["material"])["coverage_attestation"])
	var body object
	require(d.read("write/"+d.scope+"/"+attempt+"/body", &body), "missing submitted coverage observation")
	checkCoverageSubmission(body, m)
	attID := str(m, "attestation_id")
	for _, person := range approvers {
		d.login(person)
		r = d.browser(person).write("approve/"+aid+"/"+person, coveragePath+"/approvals/"+aid+"/assertions", func() object {
			return object{"assertion": d.assert(person, digest)}
		})
		require(bytes.Equal(challenge("reconciliation", user, obj(r["approval"])), digest), "coverage approval material changed between signatures")
	}
	require(r["status"] == "current", "two approvals did not produce a current coverage attestation")
	votes, _ := obj(r["approval"])["approvals"].([]any)
	require(len(votes) == 2, "expected both coverage approval records")
	for _, person := range approvers {
		matched := false
		for _, v := range votes {
			record := obj(v)
			if record["request_id"] == aid && record["approver_id"] == d.required("uuid/person/"+person) &&
				obj(record["assertion"])["credential_id"] == b64.EncodeToString(d.credential(person).ID) {
				matched = true
			}
		}
		require(matched, "missing coverage approval from "+person)
	}
	status := d.coverageStatus()
	require(status["attestation_id"] == attID && status["request_digest"] == b64.EncodeToString(digest),
		"current coverage status does not identify the signed approval")
	ledger := obj(m["ledger"])
	d.evidence("approval_request_id", aid)
	d.evidence("coverage_status", status)
	require(status["result"] == m["result"] && status["counted_asset_units"] == m["counted_asset_units"] &&
		status["user_liability_units"] == ledger["user_liability_units"] && status["margin_units"] == m["margin_units"] &&
		sameInstant(status["expires_at"], m["expires_at"]), "coverage status differs from the signed totals or expiry")
	if status["state"] == "not_covered" {
		// A later operator retry after funding must submit a new ledger snapshot.
		d.put(attemptKey, id())
		stop("stack funding: not_covered, wallet B=%s, unmatched U_L=%s, liabilities L=%s, counted assets=%s, margin=%s (USDT micro)",
			str(ledger, "customer_wallet_units"), str(ledger, "unmatched_receipt_units"), str(ledger, "user_liability_units"),
			str(status, "counted_asset_units"), str(status, "margin_units"))
	}
	require((status["state"] == "valid" || status["state"] == "low_margin") && status["releases_allowed"] == true,
		"expected valid or low_margin coverage after approval, got "+str(status, "state"))
}

func checkCoverageSubmission(body, material object) {
	sent, _ := body["observations"].([]any)
	signed, _ := material["observations"].([]any)
	require(len(sent) == 1 && len(signed) == 1, "expected a single demo observation")
	observation := maps.Clone(obj(sent[0]))
	hash := sha256.Sum256(appendField(appendField(nil, "aipay.reconciliation.coverage_evidence.v1"), str(observation, "evidence")))
	delete(observation, "evidence")
	observation["evidence_sha256"], observation["role"] = b64.EncodeToString(hash[:]), "cold"
	require(matchesProposal(obj(signed[0]), observation), "signed observation differs from demo submission")
	for _, k := range []string{"unrecorded_inflows", "window_outflows"} {
		items, ok := material[k].([]any)
		require(ok && len(items) == 0, "unexpected transfers in signed coverage material")
	}
}
