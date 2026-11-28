package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRound11ScenarioReports(t *testing.T) {
	for _, name := range []string{"seller-offline", "archived-work", "bot-notices", "statement"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			check(atomic(filepath.Join(root, "env/backend.env"), nil))
			out := filepath.Join(root, "report.md")
			err := execute([]string{root, "", "run", name, "-o", out})
			if err == nil || !strings.Contains(err.Error(), "seller-account") {
				t.Fatalf("unexpected prerequisite: %v", err)
			}
			result := string(file(out))
			checks, notes := round11Plan(name)
			if scenarios[name] == nil || len(checks) == 0 || len(notes) == 0 || !strings.Contains(result, checks[0]) || !strings.Contains(result, notes[0]) {
				t.Fatal("missing scenario report")
			}
		})
	}
	d := newDriver(t.TempDir(), "", "archived-work")
	expectFailure(t, func() { d.step("归档清单", func() { stop("缺样本：本单尚未归档") }) })
	if d.history.Steps[0].Status != "缺样本" || d.data["finished/archived-work"] != nil {
		t.Fatal("missing sample marked as complete")
	}
}

func TestCommandGrants(t *testing.T) {
	const key = "019a3142-4000-7000-8000-00000000000a"
	const target = "019a3142-4000-7000-8000-00000000000b"
	// Published vectors from protobuf/testvectors/payment_web_command_v1.json.
	for _, tc := range []struct {
		c    portalCommand
		want string
	}{
		{onlineCommand("seller", target, key, "人工核查", 4294967297, true), "6334fddb131e523833cfbce9b7bd673c716d6ebc7c8af598597e07838b9820ec"},
		{onlineCommand("seller", target, key, "人工核查", 4294967297, false), "22a37816aa2da4be59457f89521e3affc1a2e5a4104855900419c725b09b26ae"},
		{requeueCommand("order", target, key, "人工核查", 4294967297), "3ffebbfbb0768c4947292385e7fd021910d599ca627c1b2ad21c3aa83a49a9bb"},
	} {
		if fmt.Sprintf("%x", tc.c.digest) != tc.want {
			t.Fatal(tc.c.permission, "digest mismatch")
		}
	}
}

func TestPortalReauthenticationHeaders(t *testing.T) {
	for _, name := range []string{"seller", "sre"} {
		t.Run(name, func(t *testing.T) {
			d := newDriver(t.TempDir(), "", "grant-test")
			d.origins = readPortalOrigins(map[string]string{"AIPAY_PLATFORM_ORIGIN": "https://admin.custom.test"})
			d.put("user/"+name, "actor")
			d.put("session-until/"+name, time.Now().Add(time.Minute))
			d.put("seller-account", "account")
			b := d.browser(name)
			c := requeueCommand("order", "sample-id", "original-key", "核对样本", 2)
			b.cookies["__Host-kaivo_platform_session"] = "initial"
			if name == "seller" {
				b.cookies["__Host-kaivo_seller_session"] = "initial"
				d.put("totp/seller", "JBSWY3DPEHPK3PXP")
				c = onlineCommand("account", "channel", "original-key", "暂停接单", 2, false)
			}
			var begun, verified, applied bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, b.prefix)
				reply := object{}
				var body object
				if r.Method == "POST" {
					buf, err := io.ReadAll(r.Body)
					check(err)
					decode(buf, &body)
				}
				if path != c.path && r.Header.Get("X-Reauthentication-ID") != "" {
					t.Error("grant sent to unrelated path")
				}
				switch path {
				case "/auth/csrf":
					reply = object{"token": "private-csrf"}
				case "/auth/reauth":
					binding := obj(obj(body["target"])["binding"])
					if binding["http_path"] != b.prefix+c.template || binding["permission"] != c.permission || binding["body_sha256"] != b64.EncodeToString(c.digest[:]) {
						t.Error("grant not bound to target")
					}
					begun = true
					reply = object{"challenge_id": "private-challenge", "challenge_purpose": "reauthentication"}
				case "/auth/challenges/private-challenge":
					reply = object{"options_json": b64.EncodeToString(encoded(object{"rpId": d.origins.rpID(), "challenge": b64.EncodeToString([]byte("challenge"))}))}
				case "/auth/challenges/private-challenge/verify":
					if !begun || (name == "sre" && body["assertion"] == nil) || (name == "seller" && body["method"] != "totp") {
						t.Error("missing recent MFA")
					}
					verified = true
					reply = object{"state": "authenticated", "session": object{"user_id": "actor"}, "reauthentication": object{"reauthentication_id": "private-grant"}}
				case c.path:
					applied = verified && r.Header.Get("X-Reauthentication-ID") == "private-grant" && r.Header.Get("Idempotency-Key") == c.key && r.Header.Get("X-CSRF-Token") == "private-csrf" && r.Header.Get("Origin") == b.origin && matchesProposal(body, normalized(c.body))
				default:
					t.Error("unexpected path", path)
				}
				json.NewEncoder(w).Encode(object{"code": 200, "data": reply})
			}))
			defer srv.Close()
			b.addr = strings.TrimPrefix(srv.URL, "http://")
			d.step("写命令", func() { b.apiGrant("POST", c.path, c.key, c.body, b.grant(c)) })
			if !applied {
				t.Fatal("command or grant missing from authorized write")
			}
			report := string(file(filepath.Join(d.dir, "reports", "grant-test.md")))
			for _, secret := range []string{"private-csrf", "private-grant", "private-challenge", d.password(name)} {
				if strings.Contains(report, secret) {
					t.Fatal("report contains auth material")
				}
			}
		})
	}
}

func TestChannelVersionsAndWorkerClaim(t *testing.T) {
	s := normalized(object{"seller_account_id": "seller", "channel_account_id": "ch", "online": false, "platform_enabled": true, "seller_online_version": 2, "control_version": 5, "seller_online_changed_at": "instant"})
	p := normalized(object{"configuration": object{"seller_account_id": "seller", "channel_account_id": "ch", "enabled": true}, "seller_online": false, "seller_online_version": 2, "control_version": 5, "seller_online_changed_at": "instant"})
	channelState(s, p, "seller", "ch", false, 2, 5)
	for k, v := range (object{"seller_online": true, "seller_online_version": 1, "control_version": 6, "seller_online_changed_at": "stale"}) {
		bad := normalized(p)
		bad[k] = v
		expectFailure(t, func() { channelState(s, normalized(bad), "seller", "ch", false, 2, 5) })
	}
	for _, tc := range []struct {
		version, attempts int
		completed, want   bool
	}{{1, 11, false, false}, {2, 0, false, false}, {2, 1, false, true}, {2, 0, true, true}} {
		if reclaimedWork(normalized(object{"version": tc.version, "attempts": tc.attempts, "completed_after": tc.completed}), 1) != tc.want {
			t.Fatal(tc)
		}
	}
}

func TestArchivedOrderSelection(t *testing.T) {
	target := normalized(object{"object_type": "order", "object_id": "mine", "kind": "order", "attempts": 11, "version": 1, "last_error_code": "pending", "archived_at": "time"})
	wrong := normalized(target)
	wrong["kind"] = "refund"
	foreign := normalized(target)
	foreign["object_id"] = "foreign"
	if archivedOrder([]any{wrong, foreign}, "mine") != nil {
		t.Fatal("selected unrelated task")
	}
	if row := archivedOrder([]any{wrong, foreign, target}, "mine"); row["last_error_code"] != "pending" {
		t.Fatal("missed matching task")
	}
	target["attempts"] = json.Number("0")
	expectFailure(t, func() { archivedOrder([]any{target}, "mine") })
}

func TestNoticeEvidenceSelection(t *testing.T) {
	expected := "已收款\n平台单号 12345\n商户单号 abcde\n金额 1.00 CNY"
	p := message{ID: 2, Chat: merchantUser, Text: expected}
	g := message{ID: 3, Chat: demoGroup, Text: expected}
	rows := []message{{ID: 1, Chat: merchantUser, Text: "已收款\n平台单号 other"}, p, g}
	selectRows := func(ms []message) map[int64]int64 { return noticeCopies(ms, "已收款", "12345", "abcde", expected) }
	ids := selectRows(rows)
	if len(ids) != 2 || ids[merchantUser] != 2 || ids[demoGroup] != 3 {
		t.Fatal(ids)
	}
	for _, extra := range []message{p, {ID: 4, Chat: 42, Text: expected}, {ID: 5, Chat: demoGroup, Text: strings.Replace(expected, "1.00", "2.00", 1)}} {
		expectFailure(t, func() { selectRows(append(rows, extra)) })
	}
	if !accountNoticeText(expected) || !accountNoticeText("收款方式 alipay 审核结果：通过") || accountNoticeText("已上传 V2 公钥") {
		t.Fatal("notice misidentified as command response")
	}
	private := normalized(object{"chat_id": merchantUser, "status": "sent", "attempts": 1})
	group := normalized(object{"chat_id": demoGroup, "status": "sent", "attempts": 1})
	if sentToBoth([]object{private}) || !sentToBoth([]object{group, private}) {
		t.Fatal("missing destination check")
	}
	group["status"] = "pending"
	if sentToBoth([]object{group, private}) {
		t.Fatal("accepted pending")
	}
	group["status"] = "failed"
	expectFailure(t, func() { sentToBoth([]object{private, group}) })
}

func TestMultipartDocument(t *testing.T) {
	f := fixtures{dir: t.TempDir(), token: "private-token"}
	payload := []byte("private attachment bytes")
	send := func(chat string, copies int, extra bool) int {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		check(w.WriteField("chat_id", chat))
		check(w.WriteField("caption", "业务日 2026-11-24"))
		for i := 0; i < copies; i++ {
			part, err := w.CreateFormFile("document", "statement-2026-11-24.zip")
			check(err)
			_, err = part.Write(payload)
			check(err)
		}
		if extra {
			check(w.WriteField("private_key", "sensitive-field"))
		}
		check(w.Close())
		req := httptest.NewRequest("POST", "/bot"+f.token+"/sendDocument", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		res := httptest.NewRecorder()
		f.bot(res, req)
		if res.Code == 200 && !strings.Contains(res.Body.String(), `"message_id":1`) {
			t.Fatal("missing Bot API message ID")
		}
		return res.Code
	}
	for _, tc := range []struct {
		chat  string
		n     int
		extra bool
	}{{"oops", 1, false}, {"0", 1, false}, {"42", 2, false}, {"42", 0, false}, {"42", 1, true}} {
		if send(tc.chat, tc.n, tc.extra) != 400 {
			t.Fatal("accepted malformed upload")
		}
	}
	if send("42", 1, false) != 200 {
		t.Fatal("upload failed")
	}
	raw := file(filepath.Join(f.dir, "messages.json"))
	if bytes.Contains(raw, payload) || bytes.Contains(raw, []byte(f.token)) || bytes.Contains(raw, []byte("sensitive-field")) {
		t.Fatal("record contains private material")
	}
	var msgs []message
	decode(raw, &msgs)
	doc := msgs[0].Document
	if len(msgs) != 1 || msgs[0].Chat != 42 || doc.Filename != "statement-2026-11-24.zip" || doc.Caption != "业务日 2026-11-24" || doc.Size != len(payload) || doc.SHA256 != hexDigest(payload) {
		t.Fatal("document metadata mismatch")
	}
	path := filepath.Join(f.dir, "documents", doc.SHA256)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 || !bytes.Equal(file(path), payload) {
		t.Fatal("private content mismatch")
	}
}

func TestSignedStatementJournal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	public := func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		check(err)
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	row := normalized(object{"recorded_at": "2026-11-23T16:00:00Z", "seq": 9, "line_no": 1, "transaction_id": "tx", "balance_category": "available", "change_usdt": 12345, "order_id": "order", "account_id": "account", "business_id": "business", "application_id": "app"})
	journal := []object{row}
	files := map[string][]byte{"transactions.json": encoded(journal), "summary.json": []byte("{}"), "transactions.csv": []byte("seq,line_no,transaction_id,recorded_at,balance_category,change_usdt,order_id,account_id,business_id,application_id\n9,1,tx,2026-11-23T16:00:00Z,available,12345,order,account,business,app\n")}
	hashes := map[string]string{}
	for name, b := range files {
		hashes[name] = hexDigest(b)
	}
	statement := encoded(object{"version": 1, "scope": "ACCOUNT", "target_id": "account", "account_id": "account", "business_date": "2026-11-24", "key_id": "report", "checkpoint_id": 4, "files_sha256": hashes})
	sum := sha256.Sum256(statement)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	check(err)
	var raw json.RawMessage = statement
	files["manifest.json"] = encoded(object{"statement": raw, "signature": sig})
	hash := hexDigest(files["manifest.json"])
	zipBytes := func() []byte {
		var b bytes.Buffer
		w := zip.NewWriter(&b)
		for n, f := range files {
			e, err := w.Create(n)
			check(err)
			_, err = e.Write(f)
			check(err)
		}
		check(w.Close())
		return b.Bytes()
	}
	verify := func(archive, pem []byte, journal []object) {
		verifyStatement(archive, pem, "account", "2026-11-24", "report", hash, 4, journal)
	}
	data := zipBytes()
	verify(data, public(key), journal)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	expectFailure(t, func() { verify(data, public(other), journal) })
	expectFailure(t, func() { verifyStatement(data, public(key), "other", "2026-11-24", "report", hash, 4, journal) })
	expectFailure(t, func() { verify(data, public(key), nil) })
	wrong := normalized(row)
	wrong["change_usdt"] = json.Number("-12345")
	expectFailure(t, func() { verify(data, public(key), []object{wrong}) })
	changedCSV := bytes.Replace(files["transactions.csv"], []byte("12345"), []byte("12344"), 1)
	expectFailure(t, func() { checkStatementLines(files["transactions.json"], changedCSV, journal) })
	files["summary.json"] = []byte("{ }")
	expectFailure(t, func() { verify(zipBytes(), public(key), journal) })
}
