package main

import (
	"bytes"
	"encoding/hex"
	"maps"
	"net/url"
	"reflect"
	"strings"
	"time"

	ledger "github.com/Kaivodev/protobuf/gen/go/aipay/ledger/v1"
	"github.com/Kaivodev/servicekit/approval"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ledgerInboxPath = "/approvals?owner_service=ledger"

type ledgerPages struct {
	asOf     string
	count    int
	requests map[string]string
}

func (b *browser) ledgerPages(path, kind, status string, limit int) ledgerPages {
	inbox := strings.HasPrefix(path, "/approvals?")
	result := ledgerPages{requests: map[string]string{}}
	seen := map[string]bool{}
	next := path
	var previous time.Time
	for {
		page := b.api("GET", next, "", nil)
		source := page
		if inbox {
			sources := obj(page["sources"])
			require(len(sources) == 1, "unexpected owner in ledger inbox")
			source = obj(sources["ledger"])
		}
		at := str(source, "as_of")
		ledgerTime(source, "as_of")
		require(result.count == 0 || result.asOf == at, "ledger page snapshot changed")
		result.asOf = at
		result.count++
		items := ledgerList(page, "items")
		require(len(items) <= limit, "ledger page exceeds the requested limit")
		for _, item := range items {
			row := obj(item)
			field := "approval_request"
			if inbox {
				require(row["owner_service"] == "ledger", "unexpected approval owner")
				field = "request"
			}
			r := obj(row[field])
			id := str(r, "id")
			require(r["status"] == status && (kind == "" || r["kind"] == kind), "ledger page ignored request filters")
			when := ledgerTime(r, "requested_at")
			require(previous.IsZero() || !when.After(previous), "ledger requests out of order")
			require(result.requests[id] == "", "duplicate request in ledger pages")
			previous = when
			result.requests[id] = str(r, "kind")
		}
		if _, ok := page["next_cursor"]; !ok {
			return result
		}
		cursor := str(page, "next_cursor")
		require(!seen[cursor] && len(items) == limit, "ledger cursor failed to advance")
		seen[cursor] = true
		next = path + "&cursor=" + url.QueryEscape(cursor)
	}
}

func inboxMaterial(kind string, m object, adjustment *ledger.AdjustmentMaterial) *ledger.LedgerApprovalMaterial {
	result := &ledger.LedgerApprovalMaterial{
		ApprovalRequestId: str(m, "approval_request_id"), Kind: kind, RequestedBy: str(m, "requested_by"),
		RequestedAt: timestamppb.New(ledgerTime(m, "requested_at")), ExpiresAt: timestamppb.New(ledgerTime(m, "expires_at")),
	}
	switch kind {
	case "adjustment":
		result.Operation = &ledger.LedgerApprovalMaterial_Adjustment{Adjustment: adjustment}
	case "carryover":
		result.Operation = &ledger.LedgerApprovalMaterial_Carryover{Carryover: &ledger.CarryoverMaterial{
			PeriodId: str(m, "period_id"), AccountCode: str(m, "account_code"), Units: units(m, "units"), Reason: str(m, "reason"),
		}}
	case "usd_rate_policy":
		result.Operation = &ledger.LedgerApprovalMaterial_UsdRatePolicy{UsdRatePolicy: &ledger.UsdRatePolicyMaterial{
			Version: ledgerUint(m, "version"), ExpectedVersion: ledgerUint(m, "expected_version"), Reason: str(m, "reason"),
			ThresholdPpm: ledgerUint32(m, "threshold_ppm"), CeilingPpm: ledgerUint32(m, "ceiling_ppm"),
		}}
	case "read_only_exit":
		hash, err := hex.DecodeString(str(m, "head_hash"))
		check(err)
		result.Operation = &ledger.LedgerApprovalMaterial_ReadOnlyExit{ReadOnlyExit: &ledger.ReadOnlyExitSnapshot{
			ReadOnlyReason: str(m, "read_only_reason"), ReadOnlySince: timestamppb.New(ledgerTime(m, "read_only_since")),
			Note: str(m, "note"), HeadSeq: ledgerUint(m, "head_seq"), HeadHash: hash, LastCheckpointId: ledgerUint(m, "last_checkpoint_id"),
		}}
	default:
		stop("unknown ledger inbox kind")
	}
	return result
}

func checkInboxDetail(view object, p ledgerProposal, kind string, adjustment *ledger.AdjustmentMaterial) {
	require(view["owner_service"] == "ledger", "unexpected detail owner")
	r := obj(view["request"])
	digest := approval.Digest(ledgerRequestBytes(kind, r, p.Expected))
	require(r["id"] == p.ID && r["status"] == "pending" && bytes.Equal(digest[:], p.Digest) &&
		bytes.Equal(raw(str(r, "request_digest")), p.Digest), "inbox request differs from the submitted proposal")
	var canonical ledger.LedgerApprovalMaterial
	check(protojson.Unmarshal([]byte(str(view, "canonical_material_json")), &canonical))
	require(proto.Equal(&canonical, inboxMaterial(kind, p.Expected, adjustment)), "canonical inbox material differs from the submitted proposal")
	branches := obj(view["ledger"])
	require(len(branches) == 1, "expected exactly one ledger detail branch")
	got := obj(branches[kind])
	expected := maps.Clone(p.Expected)
	if kind == "adjustment" {
		expected["evidence_files"] = evidenceMetadata(adjustment)
		review := obj(got["review"])
		accounts := ledgerList(review, "accounts")
		require(len(accounts) == len(adjustment.Lines) && review["posted_transaction"] == nil && review["corrected_transaction"] == nil, "unexpected pending adjustment review")
		for i, line := range adjustment.Lines {
			account := obj(accounts[i])
			require(account["account_code"] == line.AccountCode && account["currency"] == line.Currency && account["owner_kind"] == "platform", "incorrect platform account in adjustment review")
		}
		got = maps.Clone(got)
		delete(got, "review")
	}
	require(len(got) == len(expected) && matchesProposal(got, expected), "typed inbox material differs from the submitted proposal")
}

func (d *driver) runLedgerApprovalsInbox() {
	first, second := d.browser("approver1"), d.browser("approver2")
	finance, risk := d.browser("finance"), d.browser("risk")
	input := usdtAdjustment("Reconcile platform capital", fundsLoss, "platform_capital:USDT", 1)
	input.files = adjustmentEvidence()
	d.step("Read all three approval sources", func() {
		sources := obj(first.api("GET", "/approvals", "", nil)["sources"])
		for _, owner := range []string{"payment", "reconciliation", "ledger"} {
			ledgerTime(obj(sources[owner]), "as_of")
		}
		d.evidence("sources", sources)
	})
	d.step("Deny the unfiltered approval inbox to finance", func() {
		f, refused := portalMethodRefusal("GET", "/approvals", func() { finance.api("GET", "/approvals", "", nil) }, 403)
		require(refused, "finance accessed the unfiltered inbox")
		d.evidence("iam_denial", object{"http_status": f.httpStatus, "business_code": f.businessCode})
	})
	d.step("Submit platform adjustment H and record one approval", func() {
		h := d.submitAdjustment(finance, "H", input)
		d.checkLedgerApproval(h, h.approve(first, adjustmentPath, "approve"), 1, "pending")
	})
	h := d.ledgerProposal("H")
	d.step("Enter the inbox read-only episode", func() {
		var drill object
		decode(d.owner("ledger", "AIPAY_DATABASE_URL", "dev", "enter-read-only", "--reason", "inbox"), &drill)
		require(drill["mode"] == "read_only" && drill["reason"] == "dev_drill:inbox", "unexpected read-only episode")
		d.put(d.scope+"/since", str(drill, "since"))
		d.put(d.scope+"/episode_version", num(drill, "version"))
		d.evidence("episode", drill)
	})
	d.step("Verify adjustment writes and reads in read-only mode", func() {
		other := input
		other.reason = "Submit during the inbox episode"
		c := other.command(d.key(d.scope + "/read-only"))
		d.expectLedgerRefusal("submit", c.path, "READ_ONLY", func() { finance.submitLedgerCommand(c) }, 409)
		d.expectLedgerRefusal("approval", h.path(adjustmentPath), "READ_ONLY", func() { h.approve(second, adjustmentPath, "read-only") }, 409)
		view := h.adjustmentDetail(finance, "pending", 1)
		d.evidence("read_as_of", view["as_of"])
	})
	d.step("Request read-only exit E", func() {
		c := exitCommand(d.key(d.scope+"/E"), "Verified the journal for the inbox drill")
		d.submitLedgerExit(risk, "E", "dev_drill:inbox", c)
	})
	d.step("Record current-period carryover F", func() {
		period := d.value(d.scope+"/period", func() string {
			return time.Now().In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01")
		})
		c := carryoverCommand(d.key(d.scope+"/F"), period, "unmatched_receipts:USDT:BSC", -7, "Reviewed unmatched receipts for the inbox drill")
		d.recordLedgerProposal("F", finance.name, "carryover", 1, finance.submitLedgerCommand(c), maps.Clone(c.body))
	})
	d.step("Request USD rate policy G at the effective threshold", func() {
		current := risk.api("GET", ratePolicyPath, "", nil)
		var version uint64
		if current["current"] != nil {
			version = ledgerUint(obj(current["current"]), "version")
		}
		c := ratePolicyCommand(d.key(d.scope+"/G"), version, ledgerUint32(current, "effective_ppm"), "Retain the effective USD threshold")
		expected := maps.Clone(c.body)
		expected["version"] = version + 1
		expected["ceiling_ppm"] = current["ceiling_ppm"]
		d.recordLedgerProposal("G", risk.name, "usd_rate_policy", 2, risk.submitLedgerCommand(c), normalized(expected))
	})

	e, f, g := d.ledgerProposal("E"), d.ledgerProposal("F"), d.ledgerProposal("G")
	proposals := []struct {
		kind string
		p    ledgerProposal
	}{{"adjustment", h}, {"read_only_exit", e}, {"carryover", f}, {"usd_rate_policy", g}}
	d.step("Check pending ledger requests and exclude earlier exits", func() {
		all := first.ledgerPages(ledgerInboxPath, "", "pending", 20)
		for _, want := range proposals {
			require(all.requests[want.p.ID] == want.kind, "missing pending ledger "+want.kind)
		}
		var version int64
		require(d.read(d.scope+"/episode_version", &version), "missing read-only episode version")
		stale := d.rows("ledger", "ledger_read_only_exit_requests", "SELECT request_id FROM ledger_read_only_exit_requests WHERE read_only_version<>$1", version)
		for _, row := range stale {
			require(all.requests[str(row, "request_id")] == "", "an earlier read-only episode appears in the inbox")
		}
		only := first.ledgerPages(ledgerInboxPath+"&kind=adjustment&limit=1", "adjustment", "pending", 1)
		require(only.requests[h.ID] == "adjustment", "missing platform adjustment in filtered inbox")
		d.evidence("pending_ids", []string{h.ID, e.ID, f.ID, g.ID})
		d.evidence("excluded_exits", len(stale))
		d.evidence("adjustment_pages", only.count)
		d.evidence("adjustment_as_of", only.asOf)
	})
	for _, want := range proposals {
		d.step("Verify inbox detail for "+want.kind, func() {
			view := first.api("GET", "/approvals/ledger/"+want.p.ID, "", nil)
			checkInboxDetail(view, want.p, want.kind, input.material())
			d.evidence("verified_request", want.p.ID)
			d.evidence("request_digest", hex.EncodeToString(want.p.Digest))
			if want.kind == "adjustment" {
				d.evidence("review_accounts", obj(obj(obj(view["ledger"])[want.kind])["review"])["accounts"])
			}
		})
	}
	d.step("Execute exit E and confirm normal mode", func() {
		d.checkLedgerApproval(e, e.approve(first, exitPath, "approve"), 1, "pending")
		d.checkLedgerApproval(e, e.approve(second, exitPath, "approve"), 2, "executed")
		status := risk.api("GET", exitPath, "", nil)
		require(status["mode"] == "normal" && status["last_exit_request_id"] == e.ID, "exit E did not restore normal mode")
		d.evidence("mode", status["mode"])
	})
	d.step("Execute platform adjustment H", func() {
		d.checkLedgerApproval(h, h.approve(second, adjustmentPath, "approve"), 2, "executed")
	})
	d.step("Execute carryover F", func() {
		d.checkLedgerApproval(f, f.approve(first, carryoverPath, "approve"), 1, "executed")
	})
	d.step("Execute policy G and verify the effective version", func() {
		d.checkLedgerApproval(g, g.approve(first, ratePolicyPath, "approve"), 1, "pending")
		reply := g.approve(second, ratePolicyPath, "approve")
		d.checkLedgerApproval(g, reply, 2, "executed")
		view := risk.api("GET", ratePolicyPath, "", nil)
		version := obj(view["current"])
		require(reflect.DeepEqual(reply["version"], version) && version["approval_request_id"] == g.ID &&
			version["version"] == g.Expected["version"] && version["threshold_ppm"] == g.Expected["threshold_ppm"] &&
			view["effective_ppm"] == g.Expected["threshold_ppm"], "unexpected effective USD rate policy")
		d.evidence("current_policy", version)
	})
	d.step("Verify executed requests have left the pending inbox", func() {
		all := first.ledgerPages(ledgerInboxPath, "", "pending", 20)
		for _, want := range proposals {
			require(all.requests[want.p.ID] == "", "executed "+want.kind+" remains in the inbox")
		}
		d.evidence("absent_ids", []string{h.ID, e.ID, f.ID, g.ID})
		d.evidence("as_of", all.asOf)
	})
}
