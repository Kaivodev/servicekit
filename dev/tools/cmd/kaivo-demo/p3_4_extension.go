package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"google.golang.org/protobuf/proto"
)

func extensionBody(escrow string, version int64, seller bool) object {
	code, reason := "platform_review", "Review the payment before releasing escrow."
	if seller {
		code, reason = "seller_funds_frozen", "The seller's receiving bank is reviewing this payment."
	}
	return object{"escrow_reservation_id": escrow, "expected_control_version": version, "extension_seconds": extensionSeconds,
		"reason_code": code, "reason": reason}
}

func sellerExtensionCommand(account, order, escrow, key string, version int64) portalCommand {
	body := extensionBody(escrow, version, true)
	b := appendField(appendField(commandPrefix("SellerPortalService/SubmitSellerRiskExtension", key), order), escrow)
	b = binary.BigEndian.AppendUint64(b, uint64(version))
	b = binary.BigEndian.AppendUint64(b, uint64(extensionSeconds))
	b = binary.BigEndian.AppendUint32(b, uint32(pay.RiskExtensionReason_RISK_EXTENSION_REASON_SELLER_FUNDS_FROZEN))
	return portalCommand{"/accounts/" + account + "/orders/" + order + "/risk-extension-requests",
		"/accounts/:seller_account_id/orders/:order_id/risk-extension-requests", "payment.risk_extension.request", key,
		body, sha256.Sum256(appendField(b, str(body, "reason")))}
}

func (t tradeRun) extensionView(id, state string) object {
	d := t.d
	d.login("risk")
	var found object
	d.waitFor("extension "+state, 2*time.Minute, func() bool {
		page := d.browser("risk").api("GET", t.orderPath("risk-extensions"), "", nil)
		items, ok := page["extensions"].([]any)
		require(ok, "missing order extension list")
		for _, item := range items {
			x := obj(item)
			if x["extension_id"] == id && x["order_id"] == t.order && x["state"] == state {
				found = x
				return true
			}
		}
		return false
	})
	return found
}

func (t tradeRun) pendingExtension(seller bool) object {
	d := t.d
	start := t.step("Identify the unpaid reservation", func() {
		h := t.reservation()
		require(h["status"] == "RESERVED" && h["paid_verified_at"] == nil, "expected an unpaid reservation")
		d.evidence("escrow", h["escrow_reservation_id"])
		d.evidence("version", h["control_version"])
	})
	escrow := str(start.Evidence, "escrow")
	// OrderPaid advances the version once. Bind seller MFA before payment
	// so the next TOTP time step cannot consume the 20-second hold.
	version := num(normalized(start.Evidence), "version") + 1
	cmd := sellerExtensionCommand(d.required("seller-account"), t.order, escrow, d.key("extension/"+t.number), version)
	step := t.step("Pay and submit the extension", func() {
		d.login("risk")
		d.login(approvers[0])
		var grant string
		if seller {
			grant = d.browser("seller").grant(cmd)
		}
		t.payA145Cashier()
		d.waitFor("ledger OrderPaid", time.Minute, func() bool { return t.reservation()["paid_verified_at"] != nil })
		var response object
		if seller {
			response = d.browser("seller").apiGrant("POST", cmd.path, cmd.key, cmd.body, grant)
		} else {
			response = obj(d.browser("risk").write("extend/"+t.order, t.orderPath("risk-extension-requests"), func() object {
				return extensionBody(escrow, version, false)
			})["extension"])
		}
		id := str(response, "extension_id")
		origin, person := "platform", "risk"
		if seller {
			origin, person = "seller", "seller"
		}
		require(response["order_id"] == t.order && response["origin"] == origin && response["requested_by"] == d.required("user/"+person) && num(response, "extension_seconds") == extensionSeconds, "unexpected extension receipt")
		x := t.extensionView(id, "pending_approval")
		h := t.reservation()
		require(h["status"] == "RESERVED" && h["risk_extension_id"] == id && num(h, "control_version") == version+1 &&
			sameInstant(h["risk_extension_pending_until"], x["pending_until"]) && sameInstant(h["risk_release_at"], x["previous_risk_release_at"]),
			"extension did not hold the original paid reservation at the next version")
		t.awaitOrderStatus("risk_held")
		d.evidence("extension", x)
		d.evidence("held_version", h["control_version"])
	})
	return obj(step.Evidence["extension"])
}

func (t tradeRun) extensionApproval(x object) object {
	d := t.d
	id := str(x, "approval_request_id")
	d.login(approvers[0])
	detail := d.browser(approvers[0]).api("GET", "/approvals/payment/"+id, "", nil)
	h, op := obj(detail["request"]), obj(detail["risk_extension"])
	require(detail["owner_service"] == "payment" && h["id"] == id && h["kind"] == "risk_extension" && h["requested_by"] == x["requested_by"] &&
		op["extension_id"] == x["extension_id"] && op["origin"] == "platform" && op["reason_code"] == "platform_review" &&
		obj(op["trade"])["order_id"] == t.order && num(op, "extension_seconds") == extensionSeconds && num(op, "policy_extension_cap_seconds") == 3600 &&
		sameInstant(op["current_risk_release_at"], x["previous_risk_release_at"]) && sameInstant(op["requested_risk_release_at"], x["requested_risk_release_at"]),
		"approval inbox differs from the pending extension")
	m := object{"approval_request_id": id, "risk_extension": op}
	for _, k := range []string{"kind", "requested_by", "requested_at", "expires_at"} {
		m[k] = h[k]
	}
	return object{"approval_request": h, "material": m, "approvals": detail["approvals"]}
}

func (t tradeRun) extensionNotice(x object, merchant bool) {
	d := t.d
	eventType := "SellerRiskExtensionNotice"
	if merchant {
		eventType = "MerchantRiskExtensionNotice"
	}
	t.step("Check the "+eventType+" outbox event", func() {
		d.waitFor(eventType, time.Minute, func() bool {
			rows := d.rows("payment", eventType, `SELECT event_id,sequence,encode(payload,'hex') AS wire FROM payment_outbox
				WHERE stream='payment.account_notices' AND event_type=$1 AND schema_version=1 AND sequence IS NOT NULL
				AND position(convert_to($2,'UTF8') in payload)>0`, eventType, t.order)
			for _, row := range rows {
				wire, err := hex.DecodeString(str(row, "wire"))
				check(err)
				if merchant {
					var m pay.MerchantRiskExtensionNotice
					check(proto.Unmarshal(wire, &m))
					if m.OrderId != t.order || m.OutTradeNo != t.number || m.AccountId != d.required("merchant-account") ||
						!m.RiskReleaseAt.AsTime().Equal(coverageTime(x, "requested_risk_release_at")) {
						continue
					}
				} else {
					var m pay.SellerRiskExtensionNotice
					check(proto.Unmarshal(wire, &m))
					if m.OrderId != t.order || m.ExtensionId != x["extension_id"] || m.SellerAccountId != d.required("seller-account") ||
						m.Kind != pay.RiskExtensionNoticeKind_RISK_EXTENSION_NOTICE_KIND_REJECTED {
						continue
					}
				}
				d.evidence("event_id", row["event_id"])
				d.evidence("sequence", row["sequence"])
				return true
			}
			return false
		})
	})
}

func (d *driver) runRiskExtensionPlatform() {
	t := d.recoveryTrade(true)
	x := t.pendingExtension(false)
	old := coverageTime(x, "previous_risk_release_at")
	t.step("Check the pending barrier after the original deadline", func() {
		d.sleep(time.Until(old))
		h := t.reservation()
		require(h["status"] == "RESERVED" && h["risk_extension_id"] == x["extension_id"] && h["released_seq"] == nil, "ledger released during pending review")
		require(d.browser("operations").api("GET", "/orders/"+t.order, "", nil)["status"] == "risk_held" && len(t.coverageAuthorizations()) == 0,
			"payment or reconciliation released during pending review")
		d.waitFor("reconciliation pending-hold schedule", time.Minute, func() bool {
			rows := d.facts("reconciliation", "pending release schedule", `SELECT reason,due_at,next_attempt_at,updated_at FROM reconciliation_release_schedule WHERE order_id=$1`, t.order)
			if len(rows) != 1 || !sameInstant(rows[0]["due_at"], x["pending_until"]) {
				return false
			}
			// A first observation before the original deadline uses not_due.
			require(rows[0]["reason"] == "risk_extension_pending" || rows[0]["reason"] == "not_due" && coverageTime(rows[0], "updated_at").Before(old), "unexpected release deferral")
			require(coverageTime(rows[0], "next_attempt_at").Before(coverageTime(x, "pending_until")), "reconciliation postponed its next ledger read until hold expiry")
			return true
		})
	})
	t.step("Refuse the requester and obtain two independent approvals", func() {
		r := t.extensionApproval(x)
		requester := d.required("user/risk")
		digest := challenge("payment", requester, r)
		id := str(x, "approval_request_id")
		path := "/risk-extensions/approvals/" + id + "/assertions"
		d.login("risk")
		require(refusedWrite(path, 403, func() {
			d.browser("risk").write("self/"+id, path, func() object { return object{"assertion": d.assert("risk", digest)} })
		}), "requester approval was accepted")
		require(len(d.rows("payment", "requester signatures", "SELECT approver_id FROM payment_admin_approvals WHERE request_id=$1 AND approver_id=$2", id, requester)) == 0, "requester signature was recorded")
		d.approveExisting("apply/"+id, "payment", requester, "/risk-extensions", r)
	})
	newDeadline := old.Add(time.Duration(extensionSeconds) * time.Second)
	t.step("Verify the applied extension", func() {
		t.extensionView(str(x, "extension_id"), "applied")
		h := t.reservation()
		require(riskReleaseAt(h).Equal(newDeadline) && h["risk_extension_id"] == nil && h["risk_extension_pending_until"] == nil, "ledger did not apply exactly 600 seconds and clear the pending hold")
		d.evidence("new_deadline", newDeadline)
	})
	t.extensionNotice(x, true)
	t.releaseAt(newDeadline)
}

func (d *driver) runRiskExtensionSellerRejected() {
	t := d.recoveryTrade(true)
	x := t.pendingExtension(true)
	id := str(x, "extension_id")
	t.step("Reject the seller request and withdraw the ledger hold", func() {
		d.login(approvers[0])
		r := d.browser(approvers[0]).write("reject/"+id, "/risk-extensions/"+id+"/rejection", func() object { return object{"reason": "No further review is needed."} })
		require(r["state"] == "rejected" && r["extension_id"] == id, "wrong rejection receipt")
		d.waitFor("withdrawn ledger hold", time.Minute, func() bool {
			h := t.reservation()
			if h["risk_extension_id"] != nil {
				return false
			}
			require(sameInstant(h["risk_release_at"], x["previous_risk_release_at"]), "rejection changed the risk deadline")
			return len(d.facts("ledger", "withdrawal", `SELECT action,expected_version FROM ledger_trade_risk_extensions
				WHERE order_id=$1 AND extension_id=$2 AND action='WITHDRAWN'`, t.order, id)) == 1
		})
	})
	t.step("Refuse a second seller request", func() {
		h := t.reservation()
		cmd := sellerExtensionCommand(d.required("seller-account"), t.order, str(h, "escrow_reservation_id"), d.key("repeat/"+id), num(h, "control_version"))
		requireRefusedWrite(cmd.path, 409, "RISK_EXTENSION_LIMIT_REACHED", func() { d.browser("seller").submitRecent(cmd) })
	})
	t.extensionNotice(x, false)
	t.releaseAt(coverageTime(x, "previous_risk_release_at"))
	t.checkMerchantExtensionScope()
}

func (d *driver) runRiskExtensionSuperseded() {
	require(d.env("payment")["AIPAY_PAYMENT_REFUND_OBJECTION_WINDOW"] == "0s", "native recovery requires a zero objection window")
	t := d.recoveryTrade(true)
	x := t.pendingExtension(false)
	id := str(x, "extension_id")
	t.registerDispute(false)
	dispute := d.required("dispute/" + t.order)
	t.step("Check the superseded extension on disputed escrow", func() {
		t.extensionView(id, "superseded")
		h := t.reservation()
		require(h["status"] == "DISPUTED" && h["dispute_id"] == dispute && h["risk_extension_id"] == id &&
			sameInstant(h["risk_extension_pending_until"], x["pending_until"]), "dispute lost the superseded hold")
		d.evidence("pending_until", x["pending_until"])
	})
	ruling := t.approveRefundRuling(dispute)
	refund := t.checkRefundHandoff(false, dispute, ruling)
	hasLedgerOutcome := func(want string) bool {
		row := oneFact(d.facts("payment", "superseded extension outcome", `SELECT id,ledger_outcome FROM payment_risk_extensions
			WHERE id=$1 AND order_id=$2`, id, t.order), "superseded extension")
		return row["ledger_outcome"] == want
	}
	t.step("Verify the pre-release refund took over escrow with the hold still recorded", func() {
		h := t.reservation()
		require(h["status"] == "REFUND_PENDING" && h["refund_id"] == refund && h["risk_extension_id"] == id &&
			sameInstant(h["risk_extension_pending_until"], x["pending_until"]), "refund did not take over the held escrow")
		handoff := oneFact(d.facts("ledger", "refund handoff time", `SELECT occurred_at FROM ledger_audit_logs
			WHERE actor_id='payment' AND result='succeeded' AND action='ledger.reserve_refund' AND target_id=$1`, t.order), "refund handoff")
		require(coverageTime(handoff, "occurred_at").Before(coverageTime(x, "pending_until")), "refund handoff occurred after the hold expired")
		require(hasLedgerOutcome(""), "payment resolved the extension before the refund settled")
		d.evidence("reservation", h)
	})
	t.manualRefund(refund)
	t.step("Confirm the refund posting and the refunded order", func() {
		t.proveRefundExecution(false, dispute, ruling, refund)
		t.awaitOrderStatus("refunded")
	})
	t.step("Confirm payment recorded the superseded hold as moot", func() {
		// Payment rechecks superseded holds every ten minutes.
		d.waitFor("moot extension", 11*time.Minute, func() bool {
			return hasLedgerOutcome("moot")
		})
	})
}

// The only account-scoped extension write is on the seller listener. Ask
// for the exact command grant with the merchant account as the acting scope.
func (t tradeRun) checkMerchantExtensionScope() {
	d := t.d
	t.step("Refuse the extension grant for the merchant account scope", func() {
		seller, merchant := d.required("seller-account"), d.required("merchant-account")
		require(seller != merchant, "seller and merchant must be different accounts")
		d.login("seller")
		h := t.reservation()
		c := sellerExtensionCommand(seller, t.order, str(h, "escrow_reservation_id"), d.key("merchant-scope/"+t.order), num(h, "control_version"))
		b := d.browser("seller")
		require(refusedWrite("/auth/reauth", 403, func() {
			b.post("/auth/reauth", object{"password": d.password("seller"), "target": object{
				"acting_scope": object{"type": "account", "account_type": "personal", "account_id": merchant},
				"binding":      object{"http_method": "POST", "http_path": b.prefix + c.template, "permission": c.permission, "body_sha256": b64.EncodeToString(c.digest[:])}}})
		}), "portal granted the extension command for the merchant acting scope")
		d.evidence("merchant_scope_refusal", object{"account_id": merchant, "business_code": 403, "permission": c.permission})
	})
}
