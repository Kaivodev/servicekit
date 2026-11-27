package main

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"strconv"
)

func (d *driver) submitAdjustment(b *browser, label string, a adjustmentInput) ledgerProposal {
	c := a.command(d.key(d.scope + "/" + label))
	reply := b.submitLedgerCommand(c)
	m := a.material()
	files := evidenceMetadata(m)
	require(reflect.DeepEqual(ledgerList(reply, "evidence_files"), files), "stored evidence differs from the upload manifest")
	d.evidence("evidence_files", files)
	return d.recordLedgerProposal(label, b.name, "adjustment", 2, reply, adjustmentFields(m))
}

func (p ledgerProposal) adjustmentDetail(b *browser, status string, approvals int) object {
	view := b.api("GET", adjustmentPath+"/"+p.ID, "", nil)
	r := obj(view["approval_request"])
	require(r["status"] == status && len(ledgerList(view, "approvals")) == approvals, "unexpected adjustment detail state")
	require(bytes.Equal(ledgerChallenge("adjustment", r, p.Expected), p.Digest), "adjustment detail challenge changed")
	require(matchesProposal(obj(view["material"]), p.Expected), "adjustment detail material changed")
	return view
}

func (d *driver) runLedgerAdjustment() {
	const amount int64 = 1_000_000
	finance, third := d.browser("finance"), d.browser("approver3")
	first, second := d.browser("approver1"), d.browser("approver2")
	seller := d.required("seller-account")
	account := "user_available:USDT:" + seller
	available := func() int64 { return units(d.sellerBalance(), "available_usdt_micro") }
	fundsRows := func() []object {
		return d.rows("ledger", "ledger_accounts", `SELECT COALESCE(b.balance_units,0) AS units
			FROM ledger_accounts a LEFT JOIN ledger_balances b ON b.account_id=a.id WHERE a.code=$1`, fundsLoss)
	}
	var baseline struct {
		Seller, Funds int64
		FundsExisted  bool
	}
	d.step("Record seller and loss account balances", func() {
		require(finance.api("GET", exitPath, "", nil)["mode"] == "normal", "adjustment drill requires normal mode")
		baseline.Seller = available()
		rows := fundsRows()
		baseline.FundsExisted = len(rows) == 1
		if baseline.FundsExisted {
			baseline.Funds = num(rows[0], "units")
		}
		require(baseline.Seller >= 0 && baseline.Seller <= math.MaxInt64-amount && baseline.Funds <= math.MaxInt64-amount, "baseline exceeds the adjustment range")
		d.put(d.scope+"/baseline", baseline)
		d.evidence("baseline", baseline)
	})
	require(d.read(d.scope+"/baseline", &baseline), "missing adjustment baseline")
	input := usdtAdjustment("Record a seller shortfall", fundsLoss, account, amount)
	d.step("Submit adjustment A and check idempotency", func() {
		p := d.submitAdjustment(finance, "A", input)
		exists := len(fundsRows()) == 1
		require(exists == baseline.FundsExisted, "submission changed loss account registration")
		d.evidence("loss_account_exists_after_submit", exists)
		key := d.key(d.scope + "/A")
		replay := finance.submitLedgerCommand(input.command(key))
		require(obj(replay["approval_request"])["id"] == p.ID, "adjustment replay returned a different request")
		d.evidence("replayed_id", p.ID)
		changed := input
		changed.reason = "Changed shortfall reason"
		c := changed.command(key)
		d.expectLedgerRefusal("changed_reason", c.path, "", func() { finance.submitLedgerCommand(c) }, 409)
	})
	a := d.ledgerProposal("A")
	d.step("Reject an unbalanced adjustment without creating a request", func() {
		count := func() int64 {
			return num(d.rows("ledger", "ledger_approval_requests", "SELECT count(*) AS total FROM ledger_approval_requests WHERE kind='adjustment'")[0], "total")
		}
		before := count()
		bad := usdtAdjustment("Unbalanced shortfall", fundsLoss, account, amount)
		bad.lines[1].Units = amount - 1
		c := bad.command(d.key(d.scope + "/unbalanced"))
		d.expectLedgerRefusal("unbalanced", c.path, "UNBALANCED", func() { finance.submitLedgerCommand(c) }, 400)
		require(count() == before, "unbalanced submission created an adjustment request")
		d.evidence("adjustment_count", before)
	})
	d.step("Reject a reservation hold account", func() {
		rows := d.rows("ledger", "ledger_accounts", `SELECT code,currency FROM ledger_accounts WHERE reservation_hold
			ORDER BY (code=$1) DESC, (currency='USDT') DESC, code LIMIT 1`, "trade_escrow:USDT:"+seller)
		require(len(rows) == 1, "no registered reservation hold account")
		hold, currency := str(rows[0], "code"), str(rows[0], "currency")
		bad := usdtAdjustment("Hold account adjustment", hold, "funds_loss:"+currency, amount)
		for _, line := range bad.lines {
			line.Currency = currency
		}
		c := bad.command(d.key(d.scope + "/hold"))
		d.evidence("hold_account", hold)
		d.expectLedgerRefusal("hold_mismatch", c.path, "HOLD_MISMATCH", func() { finance.submitLedgerCommand(c) }, 409)
	})
	d.step("Reject self-approval of adjustment B", func() {
		inputB := input
		inputB.reason = "Review a second seller shortfall"
		b := d.submitAdjustment(third, "B", inputB)
		d.expectLedgerRefusal("self_approval", b.path(adjustmentPath), "APPROVAL_SELF_APPROVAL", func() { b.approve(third, adjustmentPath, "self") }, 403)
		rows := d.rows("ledger", "ledger_approvals", "SELECT id FROM ledger_approvals WHERE request_id=$1", b.ID)
		require(len(rows) == 0, "self-approval inserted an approval")
		d.evidence("stored_approvals", len(rows))
	})
	d.step("Deny adjustment A approval to finance", func() {
		d.expectLedgerRefusal("iam_denial", a.path(adjustmentPath), "Forbidden", func() { a.approve(finance, adjustmentPath, "iam") }, 403)
	})
	d.step("Record the first approval of adjustment A", func() {
		d.checkLedgerApproval(a, a.approve(first, adjustmentPath, "approve"), 1, "pending")
		balance := available()
		require(balance == baseline.Seller, "first approval changed the seller balance")
		d.evidence("seller_available", balance)
	})
	d.step("Reject a duplicate approver for adjustment A", func() {
		d.expectLedgerRefusal("duplicate", a.path(adjustmentPath), "APPROVAL_DUPLICATE_APPROVER", func() { a.approve(first, adjustmentPath, "duplicate") }, 403)
	})
	d.step("Execute adjustment A and verify the posted balances", func() {
		reply := a.approve(second, adjustmentPath, "approve")
		d.checkLedgerApproval(a, reply, 2, "executed")
		tx := obj(reply["transaction"])
		require(tx["idempotency_key"] == "ledger.adjustments:"+a.ID && units(tx, "seq") > 0, "unexpected adjustment posting")
		detail := a.adjustmentDetail(finance, "executed", 2)
		review := obj(detail["review"])
		require(reflect.DeepEqual(review["posted_transaction"], tx), "posted transaction differs from execution")
		ledgerTime(detail, "executed_at")
		rows := fundsRows()
		require(len(rows) == 1 && num(rows[0], "units") == baseline.Funds+amount && available() == baseline.Seller+amount, "unexpected posted balances")
		accounts := ledgerList(review, "accounts")
		require(len(accounts) == 2, "expected the two posting accounts in review")
		for i, want := range []int64{baseline.Funds + amount, baseline.Seller + amount} {
			r := obj(accounts[i])
			signed := want
			if i == 1 {
				signed = -want // The seller account is credit-normal.
			}
			require(r["account_code"] == input.lines[i].AccountCode && r["opens_on_execution"] == false && units(r, "natural_balance_units") == want && units(r, "balance_units") == signed, "unexpected account in executed review")
		}
		d.put(d.scope+"/posted_seq", str(tx, "seq"))
		d.evidence("posted_transaction", tx)
		d.evidence("executed_at", detail["executed_at"])
		d.evidence("review_accounts", accounts)
	})
	d.step("Download the original evidence for adjustment A", func() {
		path := finance.prefix + adjustmentPath + "/" + a.ID + "/evidence/1"
		status, data, headers := finance.sendWithHeaders(finance.request("GET", path, "", nil, nil), path)
		f := input.files[0]
		disposition := headers.Get("Content-Disposition")
		require(status == 200 && bytes.Equal(data, f.Data), "downloaded adjustment evidence differs from the upload")
		require(disposition == fmt.Sprintf(`attachment; filename="%s-1.pdf"`, a.ID) && headers.Get("X-Content-Type-Options") == "nosniff" && headers.Get("Content-Type") == f.ContentType, "invalid attachment headers")
		d.evidence("content_disposition", disposition)
		d.evidence("content_type_options", headers.Get("X-Content-Type-Options"))
		d.evidence("verified_bytes", len(data))
	})
	d.step("Execute correction C and restore the seller balance", func() {
		reversal := usdtAdjustment("Reverse the seller shortfall", account, fundsLoss, amount)
		seq := d.required(d.scope + "/posted_seq")
		n, err := strconv.ParseUint(seq, 10, 64)
		check(err)
		reversal.corrects = n
		c := d.submitAdjustment(finance, "C", reversal)
		d.checkLedgerApproval(c, c.approve(first, adjustmentPath, "approve"), 1, "pending")
		d.checkLedgerApproval(c, c.approve(second, adjustmentPath, "approve"), 2, "executed")
		review := obj(c.adjustmentDetail(finance, "executed", 2)["review"])
		require(obj(review["corrected_transaction"])["seq"] == seq && available() == baseline.Seller, "correction did not reverse adjustment A")
		d.evidence("corrected_seq", seq)
		d.evidence("seller_available", baseline.Seller)
	})
	d.step("Roll back the final approval of underfunded adjustment D", func() {
		require(available() == baseline.Seller, "unexpected seller balance before adjustment D")
		inputD := usdtAdjustment("Attempt an underfunded debit", account, fundsLoss, baseline.Seller+1)
		p := d.submitAdjustment(finance, "D", inputD)
		d.checkLedgerApproval(p, p.approve(first, adjustmentPath, "approve"), 1, "pending")
		d.expectLedgerRefusal("insufficient_balance", p.path(adjustmentPath), "INSUFFICIENT_BALANCE", func() { p.approve(second, adjustmentPath, "underfunded") }, 409)
		detail := p.adjustmentDetail(finance, "pending", 1)
		require(obj(ledgerList(detail, "approvals")[0])["approver_id"] == d.key("person/approver1") && available() == baseline.Seller, "failed posting changed the approval or balance")
		d.evidence("pending_request", p.ID)
		d.evidence("seller_available", baseline.Seller)
	})
	d.step("Page through executed adjustments at one snapshot", func() {
		page := finance.ledgerPages(adjustmentPath+"?status=executed&limit=1", "adjustment", "executed", 1)
		c := d.ledgerProposal("C")
		require(page.requests[a.ID] == "adjustment" && page.requests[c.ID] == "adjustment" && a.ID != c.ID, "missing executed adjustment A or C")
		d.evidence("as_of", page.asOf)
		d.evidence("pages", page.count)
		d.evidence("executed_ids", []string{a.ID, c.ID})
	})
}
