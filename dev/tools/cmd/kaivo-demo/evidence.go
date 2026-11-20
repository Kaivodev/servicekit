package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/jackc/pgx/v5"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// All owner evidence is read inside a PostgreSQL-enforced read-only transaction.
// Callers select named public facts. Never return row payloads, credentials or DSNs.
func (d *driver) rows(owner, source, query string, args ...any) []object {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	role := owner + "-migrate"
	if owner == "devcollection" {
		role = owner
	}
	cfg, e := pgx.ParseConfig(d.env(role)["AIPAY_DATABASE_URL"])
	require(e == nil, "invalid "+owner+" evidence connection")
	c, e := pgx.ConnectConfig(ctx, cfg)
	require(e == nil, owner+" evidence connection failed")
	defer c.Close(ctx)
	tx, e := c.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require(e == nil, "cannot begin read-only evidence transaction")
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, "SELECT to_jsonb(facts) FROM ("+query+") AS facts", args...)
	require(e == nil, "read-only evidence query failed: "+source)
	defer rows.Close()
	out := []object{}
	for rows.Next() {
		var b []byte
		check(rows.Scan(&b))
		var v object
		decode(b, &v)
		out = append(out, v)
	}
	require(rows.Err() == nil, "evidence read failed: "+source)
	return out
}
func (d *driver) bootstrapSealed(manifest string) bool {
	rows := d.rows("iam", "iam_bootstrap_seal", "SELECT ceremony_id,encode(manifest_sha256,'hex') AS digest FROM iam_bootstrap_seal")
	if len(rows) == 0 {
		return false
	}
	require(len(rows) == 1 && rows[0]["digest"] == fmt.Sprintf("%x", sha256.Sum256(file(manifest))), "IAM already sealed by a different ceremony")
	return true
}
func (d *driver) sellerBalance() object {
	a := d.required("seller-account")
	b := d.browser("seller").api("GET", "/accounts/"+a+"/balance", "", nil)
	require(str(b, "seller_account_id") == a && str(b, "currency") == "USDT", "seller balance identity mismatch")
	return b
}
func units(v object, k string) int64 { n, e := strconv.ParseInt(str(v, k), 10, 64); check(e); return n }
func (d *driver) wallet(code string) int64 {
	rows := d.rows("ledger", "ledger_accounts/ledger_balances", "SELECT COALESCE(b.balance_units,0)::bigint AS units FROM ledger_accounts a LEFT JOIN ledger_balances b ON b.account_id=a.id WHERE a.code=$1", code)
	require(len(rows) == 1, "wallet account missing")
	return num(rows[0], "units")
}
func (d *driver) checkDepositRate(receipt object) {
	confirmedAt, err := time.Parse(time.RFC3339, str(receipt, "confirmed_at"))
	check(err)
	rows := d.rows("ledger", "ledger_usd_rates", `SELECT version, observed_at, rate FROM ledger_usd_rates
		WHERE asset='USDT' AND observed_at <= $1
		ORDER BY observed_at DESC, created_at DESC, version DESC LIMIT 1`, confirmedAt)
	if len(rows) == 0 {
		stop("ledger 缺少截至回执确认时间 %s 的 USDT/USD 汇率。请运行 refresh-market 并确认 ledger 已加载 AIPAY_LEDGER_DEV_USD_RATES_FILE。若旧回执早于首条观测，请在新隔离栈先刷新行情再生成转账", confirmedAt.UTC().Format(time.RFC3339))
	}
	d.evidence("ledger_usd_rate", rows[0])
}
func (d *driver) deposits() {
	a := d.required("seller-account")
	d.step("预存开户", func() {
		d.stack("down")
		d.stack("deposits-on", "--seller-account-id", a)
		var spec object
		decode(file(filepath.Join(d.root, "deposits/scenario.json")), &spec)
		wallet := str(spec, "wallet_account_code")
		p := d.declaration("wallet", object{"type": "collection_wallet", "currency": "USDT", "chain": "BSC", "wallet_id": str(spec, "address_id"), "wallet_account_code": wallet, "reason": "阶段 2 演示", "declared_by": "demo-ledger"})
		d.owner("ledger", "AIPAY_LEDGER_WALLETS_DATABASE_URL", "wallets", "register", p)
		d.put("wallet", wallet)
		d.stack("up")
	})
	wallet := d.required("wallet")
	d.step("预存基线", func() {
		d.login("seller")
		sb := d.sellerBalance()
		d.evidence("seller_portal", sb)
		d.put("deposit-base", []int64{d.wallet(wallet), units(sb, "available_usdt_micro")})
	})
	var base []int64
	d.read("deposit-base", &base)
	var spec object
	decode(file(filepath.Join(d.root, "deposits/scenario.json")), &spec)
	samples := obj(spec["receipts"])
	normal := num(obj(samples["normal"]), "units")
	late := num(obj(samples["unfinalized"]), "units")
	checkBalances := func(delta int64) bool {
		return d.wallet(wallet) == base[0]+delta && units(d.sellerBalance(), "available_usdt_micro") == base[1]+delta
	}
	d.step("正常预存", func() {
		d.checkDepositRate(obj(samples["normal"]))
		d.login("seller")
		eid := strings.TrimSpace(string(d.stack("receipt", "add", "normal")))
		waitFor("verified seller deposit", 90*time.Second, func() bool { return checkBalances(normal) })
		d.evidence("collection_event_id", eid)
		d.evidence("wallet_units", d.wallet(wallet))
		d.evidence("seller_portal", d.sellerBalance())
	})
	d.step("预存重放", func() {
		d.login("seller")
		eid := strings.TrimSpace(string(d.stack("receipt", "replay", "normal")))
		waitFor("ledger replay processing", 60*time.Second, func() bool {
			rows := d.rows("ledger", "ledger_inbox", "SELECT event_id,sequence,status FROM ledger_inbox WHERE event_id=$1 AND status='applied'", eid)
			if len(rows) == 1 {
				d.evidence("ledger_inbox", rows)
				return true
			}
			return false
		})
		require(checkBalances(normal), "replay changed deposit balance")
	})
	d.step("核实事件先到", func() {
		d.checkDepositRate(obj(samples["unfinalized"]))
		d.stack("down")
		d.stack("deposits-on", "--seller-account-id", a, "--finalized", "3", "--delay-ledger-collection")
		d.stack("up")
		d.login("seller")
		d.stack("receipt", "add", "unfinalized")
		waitFor("pending SellerDepositVerified before receipt", 90*time.Second, func() bool {
			matches := d.rows("reconciliation", "recon_seller_deposit_matches", "SELECT outbox_event_id FROM recon_seller_deposit_matches WHERE chain_transaction_id=$1 AND seller_account_id=$2", str(obj(samples["unfinalized"]), "chain_transaction_id"), a)
			if len(matches) != 1 {
				return false
			}
			rows := d.rows("ledger", "ledger_inbox", "SELECT sequence,event_id FROM ledger_inbox WHERE stream='reconciliation.matches' AND event_type='SellerDepositVerified' AND status='pending' AND event_id=$1", str(matches[0], "outbox_event_id"))
			if len(rows) == 1 {
				d.evidence("pending_ledger_inbox", rows)
				return true
			}
			return false
		})
		require(checkBalances(normal), "out-of-order deposit posted early")
	})
	d.step("原回执补到", func() {
		d.stack("down")
		d.stack("deposits-on", "--seller-account-id", a, "--finalized", "3")
		d.stack("up")
		d.login("seller")
		waitFor("original receipt and reclassification", 90*time.Second, func() bool { return checkBalances(normal + late) })
		d.evidence("seller_portal", d.sellerBalance())
		d.evidence("wallet_units", d.wallet(wallet))
		rows := d.rows("ledger", "ledger_trade_deposits", "SELECT d.source_event_id,d.source_sequence,d.posting_seq,d.unmatched_seq,u.posting_seq AS wallet_posting FROM ledger_trade_deposits d JOIN ledger_trade_unmatched_receipts u USING(chain,transaction_id,transfer_index) WHERE d.wallet_account_code=$1 ORDER BY d.source_sequence", wallet)
		require(len(rows) == 2, "expected two original transfers")
		for _, r := range rows {
			require(r["unmatched_seq"] == r["wallet_posting"], "deposit journal reference mismatch")
		}
		d.evidence("ledger_trade_deposits", rows)
	})
}
func (d *driver) ledgerTrade(order string) object {
	seller := d.required("seller-account")
	list := d.browser("seller").api("GET", "/accounts/"+seller+"/holds?order_id="+order, "", nil)
	items, _ := list["items"].([]any)
	if len(items) == 0 {
		return nil
	}
	require(len(items) == 1, "ambiguous seller hold")
	hold := obj(items[0])
	require(hold["order_id"] == order && hold["seller_account_id"] == seller, "seller hold scope mismatch")
	var snapshot object
	if !d.read("trade-snapshot/"+order, &snapshot) {
		view := d.browser("operations").api("GET", "/orders/"+order, "", nil)
		trade := obj(obj(view["snapshot"])["trade"])
		require(trade["order_id"] == order && trade["seller_account_id"] == seller && trade["account_id"] == d.required("merchant-account"), "platform order scope mismatch")
		quote := obj(trade["quote"])
		snapshot = object{"account_id": trade["account_id"]}
		for _, k := range []string{"escrow_usdt", "recipient_usdt", "platform_fee_usdt"} {
			m := obj(quote[k])
			require(m["currency"] == "USDT", "unexpected quote currency")
			snapshot[k] = units(m, "amount_minor")
		}
		d.put("trade-snapshot/"+order, snapshot)
	}
	for k, v := range snapshot {
		hold[k] = v
	}
	require(units(hold, "amount_usdt_micro") == num(normalized(snapshot), "escrow_usdt"), "portal escrow differs from locked quote")
	hold["status"] = strings.ToUpper(str(hold, "status"))
	rows := d.rows("ledger", "ledger_trade_reservations", "SELECT paid_verified_at,released_seq FROM ledger_trade_reservations WHERE order_id=$1", order)
	require(len(rows) == 1, "missing ledger posting evidence")
	for k, v := range rows[0] {
		hold[k] = v
	}
	return normalized(hold)
}
func (d *driver) balanceSnapshot(label string) object {
	b := d.bot("snap/"+label+"/balance", "/balance")
	require(strings.HasPrefix(b, "账户 "+d.required("merchant-account")+"\n"), "merchant scope mismatch")
	s := d.sellerBalance()
	fees := d.rows("ledger", "ledger_balances (three fee accounts)", "SELECT COALESCE(sum(b.balance_units),0)::bigint AS units FROM ledger_accounts a JOIN ledger_balances b ON b.account_id=a.id WHERE a.code IN ('merchant_trade_fee_revenue:USDT','channel_trade_fee_revenue:USDT','trade_spread_revenue:USDT')")
	return object{"merchant_bot": b, "merchant": micro(capture(`(?m)^可用 ([0-9]+\.[0-9]{6})$`, b)), "seller_portal": s, "seller": units(s, "available_usdt_micro"), "ledger_fee_accounts": num(fees[0], "units"), "orders_bot": d.bot("snap/"+label+"/orders", "/orders")}
}
func (d *driver) chainEvidence(order string) {
	d.evidence("seller_hold_platform_quote_and_ledger_posting", d.ledgerTrade(order))
	d.evidence("payment_outbox", d.rows("payment", "payment_outbox", "SELECT event_type,event_id,sequence FROM payment_outbox WHERE order_id=$1 ORDER BY sequence", order))
	d.evidence("ledger_trade_authorizations", d.rows("ledger", "ledger_trade_authorizations", "SELECT source_event_id,source_sequence,expected_version,event_type,result_status,posting_seq FROM ledger_trade_authorizations WHERE order_id=$1 ORDER BY source_sequence", order))
	d.evidence("reconciliation_verification_evidence", d.rows("reconciliation", "reconciliation_verification_evidence", "SELECT id,operation,category,verified_at FROM reconciliation_verification_evidence WHERE order_id=$1 ORDER BY verified_at", order))
	d.evidence("ledger_trade_refunds", d.rows("ledger", "ledger_trade_refunds", "SELECT refund_id,branch,reserved_usdt,control_version,reserve_seq FROM ledger_trade_refunds WHERE order_id=$1", order))
}
func normalized(v object) object { var r object; decode(encoded(v), &r); return r }
