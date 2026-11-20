package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Kaivodev/servicekit/dev/tools/internal/collection"
)

func (d *driver) duplicateEnvelope() {
	p := filepath.Join(d.dir, "overlap.json")
	var spec object
	decode(file(filepath.Join(d.root, "deposits/scenario.json")), &spec)
	key, op := "normal", "replay"
	delta := int64(0)
	if sample, ok := obj(spec["receipts"])["duplicate-delivery"]; ok {
		key, op = "duplicate-delivery", "add"
		delta = num(obj(sample), "units")
	}
	d.step("并发投递基线", func() {
		head := strings.Fields(string(d.stack("head")))
		require(len(head) == 2, "invalid collection head")
		seq, e := strconv.ParseInt(head[0], 10, 64)
		check(e)
		receipt := obj(obj(spec["receipts"])[key])
		rows := d.rows("ledger", "ledger_trade_unmatched_receipts", "SELECT posting_seq FROM ledger_trade_unmatched_receipts WHERE chain='BSC' AND transaction_id=$1 AND transfer_index=$2", str(receipt, "chain_transaction_id"), num(receipt, "transfer_index"))
		require((op == "add" && len(rows) == 0) || (op == "replay" && len(rows) == 1), "duplicate sample does not match existing deposit history")
		d.put("overlap-start", time.Now().UTC().Format(time.RFC3339Nano))
		d.put("overlap-base", object{"next": seq + 1, "wallet": d.wallet(d.required("wallet")), "seller": units(d.sellerBalance(), "available_usdt_micro"), "previous_postings": rows})
	})
	var base object
	d.read("overlap-base", &base)
	seq := num(base, "next")
	d.step("两台 ledger 拉取同一签名信封", func() {
		d.stack("ledger-reader", "on")
		defer d.stack("ledger-reader", "off")
		check(atomic(p, encoded(object{"sequence": seq, "expires": time.Now().Add(2 * time.Minute)})))
		defer os.Remove(p)
		// A crash after Append may leave the event at its assigned sequence.
		rows := d.rows("devcollection", "devcollection_outbox", "SELECT event_id FROM devcollection_outbox WHERE stream='collection.deposits' AND sequence=$1", seq)
		var eid string
		if len(rows) == 0 {
			eid = strings.TrimSpace(string(d.stack("receipt", op, key)))
		} else {
			eid = str(rows[0], "event_id")
		}
		matches := d.rows("devcollection", "devcollection_outbox", "SELECT event_id FROM devcollection_outbox WHERE stream='collection.deposits' AND sequence=$1 AND event_id=$2 AND payload_digest=(SELECT payload_digest FROM devcollection_outbox WHERE receipt_key=$3)", seq, eid, key)
		require(len(matches) == 1, "overlap event differs from the selected receipt")
		d.evidence("event_id", eid)
		waitFor("two authenticated ledger readers of the same immutable event", 90*time.Second, func() bool {
			b, e := os.ReadFile(p + ".proof")
			if os.IsNotExist(e) {
				return false
			}
			check(e)
			var proof collection.OverlapProof
			decode(b, &proof)
			if proof.EventID != eid || proof.Sequence != uint64(seq) {
				return false
			}
			require(proof.Readers == 2 && len(proof.SHA256) == 64, "incomplete overlap proof")
			d.evidence("collection_rpc", proof)
			return true
		})
		waitFor("applied envelope and one wallet effect", 90*time.Second, func() bool {
			inbox := d.rows("ledger", "ledger_inbox", "SELECT event_id,sequence,status FROM ledger_inbox WHERE event_id=$1 AND sequence=$2 AND status='applied'", eid, seq)
			if len(inbox) != 1 {
				return false
			}
			sb := d.sellerBalance()
			wallet := d.wallet(d.required("wallet"))
			if wallet != num(base, "wallet")+delta || units(sb, "available_usdt_micro") != num(base, "seller")+delta {
				return false
			}
			receipt := obj(obj(spec["receipts"])[key])
			post := d.rows("ledger", "ledger_trade_unmatched_receipts/ledger_trade_deposits", "SELECT u.posting_seq AS wallet_seq,d.posting_seq AS seller_seq FROM ledger_trade_unmatched_receipts u JOIN ledger_trade_deposits d USING(chain,transaction_id,transfer_index) WHERE u.transaction_id=$1 AND u.transfer_index=$2", str(receipt, "chain_transaction_id"), num(receipt, "transfer_index"))
			if len(post) != 1 {
				return false
			}
			d.evidence("ledger_inbox", inbox)
			d.evidence("ledger_posting", post)
			d.evidence("before", base)
			d.evidence("after", object{"wallet": wallet, "seller_portal": sb})
			return true
		})
		// The loser must have actually verified the server's page. An RPC observed
		// by the producer alone cannot establish that it reached both consumers.
		waitFor("ledger consumer concurrent cursor check", 15*time.Second, func() bool {
			for _, svc := range []string{"ledger", "ledger-reader"} {
				if movedCursor(filepath.Join(d.root, "logs", svc, "runtime.log"), d.required("overlap-start")) {
					d.evidence("concurrent_reader_log", "logs/"+svc+"/runtime.log")
					return true
				}
			}
			return false
		})
	})
}
func movedCursor(path, since string) bool {
	f, e := os.Open(path)
	if os.IsNotExist(e) {
		return false
	}
	check(e)
	defer f.Close()
	t, e := time.Parse(time.RFC3339Nano, since)
	check(e)
	s := bufio.NewScanner(io.LimitReader(f, 128<<20))
	for s.Scan() {
		line := s.Bytes()
		if !bytes.Contains(line, []byte("event stream cursor moved concurrently")) {
			continue
		}
		var v struct {
			Time   time.Time
			Stream string
		}
		if json.Unmarshal(line, &v) == nil && v.Stream == "collection.deposits" && !v.Time.Before(t) {
			return true
		}
	}
	check(s.Err())
	return false
}
func (d *driver) staleAuthorization() {
	d.step("暂缓授权拉取", func() { d.stack("ledger-matches", "pause") })
	t := d.trade("旧授权", "v1")
	t.paid(1)
	t.step("签发后推进冻结版本", func() {
		var old object
		waitFor("signed release still awaiting ledger", 2*time.Minute, func() bool {
			rs := d.rows("reconciliation", "reconciliation_authorizations/outbox", "SELECT a.authorization_id,a.control_version,o.sequence FROM reconciliation_authorizations a JOIN reconciliation_outbox o ON o.event_id=a.authorization_id WHERE a.order_id=$1 AND a.event_type='TradeReleaseAuthorized' AND o.sequence IS NOT NULL", t.order)
			if len(rs) != 1 {
				return false
			}
			old = rs[0]
			return true
		})
		d.put("stale-authorization", old)
		d.evidence("signed_release", old)
		h := d.ledgerTrade(t.order)
		dispute := d.browser("operations").write("stale-dispute", "/disputes", func() object {
			require(h["status"] == "RESERVED" && num(h, "control_version") == num(old, "control_version"), "release already executed or changed")
			msg := d.bot("stale-order", "/order "+d.required("app/v1")+" "+t.order)
			return object{"order_id": t.order, "escrow_reservation_id": str(h, "escrow_reservation_id"), "expected_control_version": num(old, "control_version"), "reason": "演示原授权签发后的争议屏障", "evidence": object{"recipient_evidence": b64.EncodeToString([]byte(msg)), "investigation": "核对收款方原单"}}
		})
		h = d.ledgerTrade(t.order)
		require(h["status"] == "DISPUTED" && num(h, "control_version") > num(old, "control_version"), "dispute did not advance escrow control")
		d.put("stale-held", h)
		d.put("stale-dispute", str(dispute, "dispute_id"))
		d.evidence("dispute_id", str(dispute, "dispute_id"))
		d.evidence("seller_hold", h)
	})
	t.step("旧授权投递与资金核对", func() {
		d.stack("ledger-matches", "resume")
		var auth, held object
		d.read("stale-authorization", &auth)
		d.read("stale-held", &held)
		waitFor("quarantined superseded release", 60*time.Second, func() bool {
			rows := d.rows("ledger", "ledger_inbox", "SELECT event_id,sequence,status,quarantine_reason FROM ledger_inbox WHERE event_id=$1", str(auth, "authorization_id"))
			if len(rows) != 1 || rows[0]["status"] != "quarantined" {
				return false
			}
			require(num(rows[0], "sequence") == num(auth, "sequence") && strings.Contains(str(rows[0], "quarantine_reason"), "control version mismatch"), "quarantine unrelated to version")
			d.evidence("ledger_inbox", rows)
			return true
		})
		current := d.ledgerTrade(t.order)
		require(current["status"] == "DISPUTED" && current["latest_seq"] == held["latest_seq"] && current["released_seq"] == nil, "stale release changed ledger")
		d.chainEvidence(t.order)
		var before object
		d.read("balances/"+d.scope+"/"+t.name, &before)
		after := normalized(d.balanceSnapshot("stale/after/" + id()))
		require(num(after, "seller") == num(before, "seller")-num(held, "escrow_usdt") && num(after, "merchant") == num(before, "merchant") && num(after, "ledger_fee_accounts") == num(before, "ledger_fee_accounts"), "stale release affected balances")
		d.evidence("after", after)
	})
	t.step("当前版本裁决收尾", func() {
		p := "/disputes/" + d.required("stale-dispute")
		d.browser("risk").approve("stale-resolution", "payment", p+"/rulings", "/dispute-rulings", object{"outcome": "release_to_original_recipient", "expected_control_version": num(d.ledgerTrade(t.order), "control_version"), "reason": "已确认旧授权隔离，按当前争议裁决交付"})
		t.terminal("RELEASED")
		applied := d.rows("ledger", "ledger_trade_authorizations", "SELECT source_event_id,posting_seq FROM ledger_trade_authorizations WHERE order_id=$1", t.order)
		var old object
		d.read("stale-authorization", &old)
		require(len(applied) == 1 && applied[0]["source_event_id"] != old["authorization_id"], "expected only the new authorization to post")
		t.finish(true)
	})
}
