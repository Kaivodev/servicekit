package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func hexDigest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

const postingTables = ` FROM ledger_transactions t JOIN ledger_lines l ON l.seq=t.seq JOIN ledger_accounts a ON a.id=l.account_id `
const merchantLines = ` WHERE l.units>0 AND a.currency='USDT' AND (
    (a.owner_kind='account' AND a.normal_side='C' AND a.owner_id=$1)
    OR (a.type='payout_in_transit' AND EXISTS (SELECT FROM ledger_reservations r WHERE r.hold_account_id=a.id
        AND r.owner_account_id=$1 AND r.purpose='withdrawal' AND (r.reserve_seq=t.seq OR r.final_seq=t.seq)))) `
const reportDates = `SELECT to_char(s.business_date,'YYYY-MM-DD') AS date,s.checkpoint_id,encode(s.manifest_sha256,'hex') AS manifest_sha256
    FROM ledger_merchant_statements s JOIN ledger_daily_closes c USING(business_date,checkpoint_id)
    WHERE c.status='succeeded' AND s.scope='ACCOUNT' AND s.account_id=$1 AND s.target_id=s.account_id ORDER BY s.business_date DESC LIMIT 20`

func (d *driver) statement() {
	account := d.required("merchant-account")
	d.ensureGroup()
	eligibleDays := func() []object {
		return d.rows("ledger", "商户入账日", `SELECT DISTINCT to_char(t.recorded_at AT TIME ZONE 'Asia/Shanghai','YYYY-MM-DD') AS date`+postingTables+merchantLines+`
            AND NOT EXISTS (SELECT FROM ledger_daily_closes c WHERE c.status='succeeded'
                AND c.business_date=(t.recorded_at AT TIME ZONE 'Asia/Shanghai')::date) ORDER BY date`, account)
	}
	// A fresh merchant needs a real movement. Keep this decision on retry even
	// if the first run stopped between release and the balance assertion.
	seed := d.value("statement/seed", func() string {
		if len(d.rows("ledger", "published dates", reportDates, account)) == 0 && len(eligibleDays()) == 0 {
			return "yes"
		}
		return "no"
	})
	if seed == "yes" {
		t := d.trade("对账入账", "v2")
		t.paid(1)
		t.release()
	}
	d.step("等待商户日结文件", func() {
		selectFile := func() bool {
			rows := d.rows("ledger", "ledger_merchant_statements", reportDates, account)
			if len(rows) == 0 {
				return false
			}
			d.put("statement/published", rows[0])
			d.evidence("published", rows[0])
			return true
		}
		if selectFile() {
			return
		}
		days := eligibleDays()
		if len(days) == 0 && selectFile() {
			return
		} // close may have committed between reads
		require(len(days) > 0, "没有可发布的商户分录，历史业务日可能已在升级前结清")
		date := str(days[0], "date")
		day, err := time.ParseInLocation(time.DateOnly, date, time.FixedZone("UTC+8", 8*3600))
		check(err)
		cutoff := day.AddDate(0, 0, 1)
		d.evidence("eligible_business_date", date)
		d.evidence("close_eligible_at", cutoff.Format(time.RFC3339))
		d.report()
		if delay := time.Until(cutoff); delay > 0 {
			d.sleep(delay)
		}
		waitFor("已结束业务日的商户日结（检查日结任务与迁移 000016）", 2*time.Minute, func() bool {
			if selectFile() {
				return true
			}
			closes := d.facts("ledger", "daily_close", `SELECT status,failed_step,checkpoint_id FROM ledger_daily_closes WHERE business_date=$1::date`, date)
			require(len(closes) == 0 || closes[0]["status"] != "failed", "ledger daily close failed; see failed_step")
			return false
		})
	})
	var published object
	d.read("statement/published", &published)
	date := str(published, "date")
	d.step("私聊列出已发布业务日", func() {
		require(strings.Contains(d.bot("statement-session/"+id(), "/start"), "注册或登录已完成"), "merchant session was not refreshed after daily close")
		m := d.telegram("dates/"+id(), merchantUser, func() string { return "/statements" })
		require(m.Chat == merchantUser && slices.Contains(strings.Split(m.Text, "\n"), date), "published UTC+8 date missing from private list")
		d.evidence("business_date", date)
		d.evidence("message_id", m.ID)
	})
	d.step("私聊下载、验签与逐行对账", func() {
		m := d.telegram("document/"+date, merchantUser, func() string { return "/statement " + date })
		doc := m.Document
		require(m.Chat == merchantUser && doc != nil && doc.Filename == "statement-"+date+".zip", "private statement document missing or misnamed")
		manifestHash := str(published, "manifest_sha256")
		require(doc.Caption == "业务日 "+date+"\nmanifest_sha256 "+manifestHash, "document caption differs from published manifest")
		require(len(doc.SHA256) == 64 && filepath.Base(doc.SHA256) == doc.SHA256, "invalid stored document digest")
		archive := d.fixtureRecord("documents/" + doc.SHA256)
		require(len(archive) == doc.Size && hexDigest(archive) == doc.SHA256, "received document size or digest mismatch")
		d.evidence("document", doc)
		journal := d.rows("ledger", "ledger_lines", `SELECT t.seq,l.line_no,t.tx_id AS transaction_id,t.recorded_at,
            CASE a.type WHEN 'user_available' THEN 'available' WHEN 'trade_escrow' THEN 'order_escrow' WHEN 'user_risk_held' THEN 'risk_held'
            WHEN 'refund_reserved' THEN 'refund_reserved' WHEN 'payout_in_transit' THEN 'payout_in_flight' END AS balance_category,
            CASE l.direction WHEN 'C' THEN l.units ELSE -l.units END AS change_usdt,
            coalesce(tr.order_id::text,'') AS order_id,coalesce(tr.snapshot->>'account_id',$1) AS account_id,
            coalesce(tr.snapshot->>'business_id','') AS business_id,coalesce(tr.snapshot->>'application_id','') AS application_id`+postingTables+`
            LEFT JOIN LATERAL (
                SELECT order_id FROM ledger_trade_reservations WHERE reserve_seq=t.seq
                UNION SELECT order_id FROM ledger_trade_authorizations WHERE posting_seq=t.seq
                UNION SELECT order_id FROM ledger_trade_refunds WHERE t.kind='trade_refund_reserved' AND branch='POST_RELEASE' AND reserve_seq=t.seq
                UNION SELECT order_id FROM ledger_trade_released_disputes WHERE reserve_seq=t.seq AND t.kind='trade_released_dispute_held'
                    OR close_seq=t.seq AND t.kind='trade_released_dispute_released') ref ON true
            LEFT JOIN ledger_trade_reservations tr ON tr.order_id=ref.order_id`+merchantLines+`
            AND (t.recorded_at AT TIME ZONE 'Asia/Shanghai')::date=$2::date ORDER BY t.recorded_at,t.seq,l.line_no`, account, date)
		key := d.input("handoff/ledger-report-public.pem")
		checked := verifyStatement(archive, key, account, date, d.env("ledger")["AIPAY_LEDGER_REPORT_KEY_ID"], manifestHash, num(published, "checkpoint_id"), journal)
		d.evidence("verification", checked)
	})
	d.step("群内引导私聊", func() {
		for _, cmd := range []string{"/statements", "/statement " + date} {
			label := "group/" + cmd + "/" + id()
			m := d.telegram(label, demoGroup, func() string { return cmd })
			require(m.Chat == demoGroup && m.Text == "请在本人私聊中操作", "missing private-chat guidance in bound group")
			var update delivery
			d.read("telegram/"+d.scope+"/"+label, &update)
			for _, msg := range d.messages() {
				require(msg.ID <= update.After || msg.Document == nil, "group command unexpectedly sent a document")
			}
			d.evidence(cmd, m.ID)
		}
	})
}

func verifyStatement(data, public []byte, account, date, kid, wantHash string, cp int64, journal []object) object {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require(err == nil && len(z.File) == 4, "expected statement ZIP with four entries")
	files := map[string][]byte{}
	names := []string{"manifest.json", "transactions.json", "transactions.csv", "summary.json"}
	const limit = 96 << 20
	remaining := int64(limit)
	for _, f := range z.File {
		require(slices.Contains(names, f.Name) && files[f.Name] == nil && f.UncompressedSize64 <= uint64(remaining), "unexpected, duplicate or oversized ZIP entry")
		r, err := f.Open()
		check(err)
		body, err := io.ReadAll(io.LimitReader(r, remaining+1))
		r.Close()
		require(err == nil && len(body) > 0 && int64(len(body)) <= remaining, "invalid statement ZIP entry")
		remaining -= int64(len(body))
		files[f.Name] = body
	}
	var manifest struct {
		Statement json.RawMessage
		Signature []byte
	}
	require(hexDigest(files["manifest.json"]) == wantHash && json.Unmarshal(files["manifest.json"], &manifest) == nil, "published manifest mismatch")
	block, rest := pem.Decode(public)
	require(block != nil && block.Type == "PUBLIC KEY" && len(bytes.TrimSpace(rest)) == 0, "invalid published report public key")
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	pk, ok := key.(*ecdsa.PublicKey)
	sum := sha256.Sum256(manifest.Statement)
	require(err == nil && ok && pk.Curve == elliptic.P256() && ecdsa.VerifyASN1(pk, sum[:], manifest.Signature), "invalid statement signature")
	var body object
	decode(manifest.Statement, &body)
	require(body["account_id"] == account && body["target_id"] == account && body["scope"] == "ACCOUNT" && body["business_date"] == date && kid != "" && body["key_id"] == kid && num(body, "version") == 1 && num(body, "checkpoint_id") == cp, "signed statement has different identity, scope, date, key or checkpoint")
	hashes := obj(body["files_sha256"])
	require(len(hashes) == 3, "expected three signed file hashes")
	for _, name := range names[1:] {
		require(hashes[name] == hexDigest(files[name]), "statement hash mismatch for "+name)
	}
	checkStatementLines(files["transactions.json"], files["transactions.csv"], journal)
	return object{"key_id": kid, "public_spki_sha256": hexDigest(block.Bytes), "manifest_sha256": wantHash, "checkpoint_id": cp, "files_sha256": hashes, "matched_journal_lines": len(journal), "first_seq": num(journal[0], "seq"), "last_seq": num(journal[len(journal)-1], "seq")}
}

func checkStatementLines(detail, csvBytes []byte, journal []object) {
	var lines []object
	decode(detail, &lines)
	records, err := csv.NewReader(bytes.NewReader(csvBytes)).ReadAll()
	require(err == nil && len(journal) > 0 && len(lines) == len(journal) && len(records) == len(lines)+1, "CSV, JSON and owner journal line counts differ")
	columns := map[string]int{}
	for i, col := range records[0] {
		_, exists := columns[col]
		require(!exists, "duplicate CSV column")
		columns[col] = i
	}
	for i, row := range journal {
		l := lines[i]
		for _, k := range []string{"seq", "line_no", "transaction_id", "recorded_at", "balance_category", "change_usdt", "order_id", "account_id", "business_id", "application_id"} {
			col, ok := columns[k]
			require(ok && l[k] != nil, "missing statement journal field "+k)
			match := row[k] == l[k]
			if k == "recorded_at" {
				match = sameInstant(row[k], l[k])
			}
			require(match && records[i+1][col] == fmt.Sprint(l[k]), "statement differs from journal at line "+strconv.Itoa(i+1)+" field "+k)
		}
	}
}
