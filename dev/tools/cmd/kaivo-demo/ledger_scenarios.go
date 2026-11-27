package main

import (
	"maps"
	"time"
)

func (d *driver) submitLedgerExit(b *browser, label, episodeReason string, c portalCommand) ledgerProposal {
	reply := b.submitLedgerCommand(c)
	requestID := str(obj(reply["approval_request"]), "id")
	// Submission may cut a due checkpoint. Read the immutable snapshot for this
	// request instead of sampling a moving head before or after the self-check.
	rows := d.rows("ledger", "ledger_read_only_exit_requests", `SELECT head_seq, encode(head_hash,'hex') AS head_hash, last_checkpoint_id
		FROM ledger_read_only_exit_requests WHERE request_id=$1`, requestID)
	require(len(rows) == 1, "missing ledger exit snapshot")
	expected := rows[0]
	expected["note"] = c.body["note"]
	expected["read_only_reason"] = episodeReason
	expected["read_only_since"] = d.required(d.scope + "/since")
	return d.recordLedgerProposal(label, b.name, "read_only_exit", 2, reply, expected)
}

func (d *driver) runLedgerReadOnlyExit() {
	risk, third := d.browser("risk"), d.browser("approver3")
	first, second := d.browser("approver1"), d.browser("approver2")
	status := func() object { return risk.api("GET", exitPath, "", nil) }

	d.step("Check initial ledger mode", func() {
		view := status()
		require(view["mode"] == "normal" && len(ledgerList(view, "pending")) == 0, "expected normal ledger with no pending exits")
		d.evidence("status", view)
	})
	d.step("Enter read-only mode", func() {
		var drill object
		decode(d.owner("ledger", "AIPAY_DATABASE_URL", "dev", "enter-read-only", "--reason", "drill"), &drill)
		require(drill["changed"] == true && drill["mode"] == "read_only" && drill["reason"] == "dev_drill:drill", "ledger did not enter the requested drill")
		d.put(d.scope+"/since", str(drill, "since"))
		d.evidence("drill", drill)
	})
	d.step("Check read-only episode", func() {
		view := status()
		require(view["mode"] == "read_only" && view["read_only_reason"] == "dev_drill:drill" &&
			sameInstant(view["mode_since"], d.required(d.scope+"/since")), "portal shows a different read-only episode")
		d.evidence("status", view)
	})

	c := exitCommand(d.key(d.scope+"/risk"), "Reconciled the journal and verified the drill")
	d.step("Submit and replay the risk exit request", func() {
		p := d.submitLedgerExit(risk, risk.name, "dev_drill:drill", c)
		replay := risk.apiGrant("POST", c.path, c.key, c.body, risk.grant(c))
		replayedID := str(obj(replay["approval_request"]), "id")
		require(replayedID == p.ID, "exit replay returned a different request")
		d.evidence("replayed_id", replayedID)
		changed := exitCommand(c.key, "Changed investigation note")
		d.expectLedgerRefusal("changed_note", c.path, "", func() { risk.submitLedgerCommand(changed) }, 409)
	})
	p := d.ledgerProposal("risk")
	d.step("Reject self-approval of an exit", func() {
		own := d.submitLedgerExit(third, third.name, "dev_drill:drill", exitCommand(d.key(d.scope+"/approver3"), "Independently reviewed the drill"))
		require(own.ID != p.ID, "expected distinct exit requests")
		d.expectLedgerRefusal("self_approval", own.path(exitPath), "APPROVAL_SELF_APPROVAL", func() {
			own.approve(third, exitPath, "self")
		}, 403)
	})
	leftover := d.ledgerProposal("approver3")
	d.step("Deny exit approval to risk", func() {
		d.expectLedgerRefusal("iam_denial", p.path(exitPath), "Forbidden", func() { p.approve(risk, exitPath, "iam") }, 403)
	})
	d.step("Record the first exit approval", func() {
		d.checkLedgerApproval(p, p.approve(first, exitPath, "approve"), 1, "pending")
		view := status()
		pending := ledgerList(view, "pending")
		require(view["mode"] == "read_only", "first approval exited read-only mode")
		riskRow := listedLedgerRequest(pending, p)
		otherRow := listedLedgerRequest(pending, leftover)
		records := ledgerList(riskRow, "approvals")
		require(obj(riskRow["approval_request"])["status"] == "pending" && len(records) == 1 &&
			obj(records[0])["approver_id"] == d.key("person/approver1"), "missing first approval on the pending risk request")
		require(obj(otherRow["approval_request"])["status"] == "pending" && len(ledgerList(otherRow, "approvals")) == 0, "unexpected approval on the other exit request")
		d.evidence("mode", view["mode"])
		d.evidence("pending_ids", []string{p.ID, leftover.ID})
		d.evidence("risk_approvals", records)
	})
	d.step("Reject duplicate exit approver", func() {
		d.expectLedgerRefusal("duplicate", p.path(exitPath), "APPROVAL_DUPLICATE_APPROVER", func() {
			p.approve(first, exitPath, "duplicate")
		}, 403)
	})
	d.step("Execute the exit with a second approver", func() {
		d.checkLedgerApproval(p, p.approve(second, exitPath, "approve"), 2, "executed")
		view := status()
		require(view["mode"] == "normal" && view["last_exit_request_id"] == p.ID && len(ledgerList(view, "pending")) == 0,
			"executed exit did not restore normal mode and clear pending exits")
		d.evidence("status", view)
	})
	d.step("Reject approval from the previous episode", func() {
		d.expectLedgerRefusal("stale_episode", leftover.path(exitPath), "READ_ONLY_EPISODE_MISMATCH", func() {
			leftover.approve(first, exitPath, "stale")
		}, 409)
	})
}

func (d *driver) runLedgerCarryover() {
	const account = "unmatched_receipts:USDT:BSC"
	finance, third := d.browser("finance"), d.browser("approver3")
	period := d.value(d.scope+"/period", func() string { return time.Now().In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01") })
	view := func() object {
		page := finance.api("GET", carryoverPath+"?period_id="+period, "", nil)
		require(page["period_id"] == period, "ledger returned the wrong period")
		return page
	}
	submit := func(b *browser, reason string) ledgerProposal {
		c := carryoverCommand(d.key(d.scope+"/"+b.name), period, account, -5, reason)
		return d.recordLedgerProposal(b.name, b.name, "carryover", 1, b.submitLedgerCommand(c), maps.Clone(c.body))
	}
	d.step("Read the current carryover period", func() {
		page := view()
		require(page["status"] == "open" && page["ended"] == false, "expected the current open ledger period")
		d.evidence("period", object{"id": period, "status": page["status"], "ended": page["ended"], "balances": ledgerList(page, "balances")})
	})
	d.step("Submit a finance carryover", func() { submit(finance, "Investigated unmatched receipts") })
	p := d.ledgerProposal("finance")
	d.step("Reject self-approval of a carryover", func() {
		own := submit(third, "Reviewed a separate unmatched receipt")
		require(own.ID != p.ID, "expected distinct carryover requests")
		d.expectLedgerRefusal("self_approval", own.path(carryoverPath), "APPROVAL_SELF_APPROVAL", func() {
			own.approve(third, carryoverPath, "self")
		}, 403)
	})
	d.step("Deny carryover approval to finance", func() {
		d.expectLedgerRefusal("iam_denial", p.path(carryoverPath), "Forbidden", func() { p.approve(finance, carryoverPath, "iam") }, 403)
	})
	d.step("Execute the finance carryover", func() {
		d.checkLedgerApproval(p, p.approve(d.browser("approver1"), carryoverPath, "approve"), 1, "executed")
	})
	d.step("Verify the executed note against balances", func() {
		page := view()
		row := listedLedgerRequest(ledgerList(page, "requests"), p)
		records := ledgerList(row, "approvals")
		require(obj(row["approval_request"])["status"] == "executed" && len(records) == 1 && obj(records[0])["approver_id"] == d.key("person/approver1"),
			"executed finance carryover or approver missing")
		balances := ledgerList(page, "balances")
		for _, item := range balances {
			balance := obj(item)
			if balance["account_code"] == account {
				require(units(balance, "units") != -5, "the drill requires an account balance different from -5")
				require(balance["carryover_approval_request_id"] == nil || balance["carryover_approval_request_id"] == "", "balance unexpectedly has a matching note")
			}
		}
		d.evidence("executed_request", p.ID)
		d.evidence("approvals", records)
		d.evidence("balances", balances)
	})
	d.step("Reject invalid carryover inputs", func() {
		nonSuspense := "fx_gain:USDT"
		var seller string
		if d.read("seller-account", &seller) && seller != "" {
			nonSuspense = "user_available:USDT:" + seller
		}
		for _, tc := range []struct {
			label, period, account string
			units                  int64
			codes                  []int
		}{
			{"non_suspense", period, nonSuspense, -5, []int{400, 409}},
			{"zero_units", period, account, 0, []int{400}},
			{"invalid_period", "2026-13", account, -5, []int{400}},
		} {
			c := carryoverCommand(d.key(d.scope+"/"+tc.label), tc.period, tc.account, tc.units, "Invalid carryover drill")
			d.expectLedgerRefusal(tc.label, c.path, "", func() { finance.submitLedgerCommand(c) }, tc.codes...)
		}
	})
}
