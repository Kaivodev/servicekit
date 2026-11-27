package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"github.com/Kaivodev/servicekit/approval"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

type user []wa.Credential

func (user) WebAuthnID() []byte                     { return []byte("test-user") }
func (user) WebAuthnName() string                   { return "test user" }
func (user) WebAuthnDisplayName() string            { return "test user" }
func (u user) WebAuthnCredentials() []wa.Credential { return u }
func TestWebAuthn(t *testing.T) {
	d := newDriver(t.TempDir(), "", "setup")
	a := d.credential("alice")
	b := d.credential("bob")
	if bytes.Equal(a.cose(), b.cose()) || bytes.Equal(a.ID, b.ID) {
		t.Fatal("shared authenticator")
	}
	provider, e := wa.New(&wa.Config{RPID: rp, RPDisplayName: "Demo", RPOrigins: []string{adminOrigin}, AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}})
	if e != nil {
		t.Fatal(e)
	}
	var u user
	creation, session, e := provider.BeginRegistration(u)
	if e != nil {
		t.Fatal(e)
	}
	att := a.register(options(b64.EncodeToString(encoded(creation.Response))))
	outer := object{"id": att["credential_id"], "rawId": att["credential_id"], "type": "public-key", "response": object{"attestationObject": att["attestation_object"], "clientDataJSON": att["client_data_json"], "transports": []string{"internal"}}}
	parsed, e := protocol.ParseCredentialCreationResponseBytes(encoded(outer))
	if e != nil {
		t.Fatal(e)
	}
	cred, e := provider.CreateCredential(u, *session, parsed)
	if e != nil {
		t.Fatal(e)
	}
	u = append(u, *cred)
	for counter := 1; counter <= 2; counter++ {
		d = newDriver(d.root, "", "setup")
		opt, s, e := provider.BeginLogin(u)
		if e != nil {
			t.Fatal(e)
		}
		assert := d.assert("alice", opt.Response.Challenge)
		outer["response"] = object{"authenticatorData": assert["authenticator_data"], "clientDataJSON": assert["client_data_json"], "signature": assert["signature"]}
		parsed, e := protocol.ParseCredentialRequestResponseBytes(encoded(outer))
		if e != nil {
			t.Fatal(e)
		}
		next, e := provider.ValidateLogin(u, *s, parsed)
		if e != nil {
			t.Fatal(e)
		}
		if next.Authenticator.SignCount != uint32(counter) {
			t.Fatal("counter")
		}
		u[0] = *next
	}
}
func TestChallenges(t *testing.T) {
	for owner, want := range map[string]string{"payment": "c2fc0044e01a6c6a0ce35fb7bb3d205f14991ef41e55e7f9173712372d33d108", "reconciliation": "9ced728651db16a51c203b3984ca6d1ed8f486fdc80e1e21a31422101955d457"} {
		if fmt.Sprintf("%x", emergencyChallenge(owner, "user", "key", "plugin", 4, "stop")) != want {
			t.Fatal(owner)
		}
	}
	m := normalized(object{"approval_request_id": "id", "kind": "payment_method", "requested_by": "user", "requested_at": "1970-01-01T00:00:01Z", "expires_at": "1970-01-01T00:00:02Z", "payment_method": object{"payment_method": "alipay", "name": "Demo", "enabled": true, "expected_control_version": 0}})
	b := materialBytes(appendField(nil, "aipay.payment.admin.v1"), (&pay.PaymentApprovalMaterial{}).ProtoReflect().Descriptor(), m)
	h, _ := hex.DecodeString("c8b8edaf221c52eb46168168b3bda89ec9a7d4d3fa1e80a6e1d67d527861acd3")
	r := normalized(object{"id": "id", "kind": "payment_method", "required_approvals": 2, "requested_by": "user", "requested_at": m["requested_at"], "expires_at": m["expires_at"], "request_bytes": b64.EncodeToString(b), "request_digest": b64.EncodeToString(h)})
	if !bytes.Equal(challenge("payment", "user", object{"material": m, "approval_request": r}), h) {
		t.Fatal("method challenge")
	}
	obj(m["payment_method"])["enabled"] = false
	expectFailure(t, func() { challenge("payment", "user", object{"material": m, "approval_request": r}) })
}
func expectFailure(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if _, ok := recover().(failure); !ok {
			t.Fatal("expected driver refusal")
		}
	}()
	f()
}

func TestRiskApprovalRequester(t *testing.T) {
	for _, tc := range []struct {
		name, requester string
		env             demoEnvironment
		holdSeconds     int64
		resume          bool
	}{
		{"native", "risk", nativeEnvironment{}, 20, false},
		{"kubernetes", "risk", &kubeEnvironment{}, 120, false},
		{"kubernetes with saved policy", "risk", &kubeEnvironment{}, 20, true},
		{"wrong requester", "operations", nativeEnvironment{}, 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(t.TempDir(), "", "setup")
			d.demoEnvironment = tc.env
			d.active = &result{Evidence: object{}}
			d.put("write/setup/risk/body", object{"change": object{"hold_duration_seconds": 0}})
			channel := id()
			const effectiveAt = "2026-11-19T00:01:00Z"
			change := object{"risk_policy_version": d.key("risk"), "channel_account_id": channel, "hold_duration_seconds": tc.holdSeconds,
				"exceptional_extension_seconds": 60, "dispute_handling_timeout_seconds": 120,
				"effective_at": effectiveAt, "expected_control_version": 0}
			if tc.resume {
				d.put("write/setup/risk/risk/body", object{"change": change})
			}
			aid, user := id(), d.key("iam/"+tc.requester)
			material := normalized(object{"kind": "risk_policy", "risk_policy": change, "approval_request_id": aid,
				"requested_by": user, "requested_at": "2026-11-19T00:00:00Z", "expires_at": "2026-11-19T01:00:00Z"})
			raw := materialBytes(appendField(nil, "aipay.payment.admin.v1"), (&pay.PaymentApprovalMaterial{}).ProtoReflect().Descriptor(), material)
			hash := approval.Digest(raw)
			header := object{"id": aid, "kind": "risk_policy", "required_approvals": 2, "requested_by": user,
				"requested_at": material["requested_at"], "expires_at": material["expires_at"],
				"request_bytes": b64.EncodeToString(raw), "request_digest": b64.EncodeToString(hash[:]), "status": "pending"}
			var signatures []object
			people := map[string]string{}
			for _, n := range approvers {
				people[n] = d.key("person/" + n)
			}
			const session = "__Host-kaivo_platform_session"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					io.WriteString(w, `{"code":200,"data":{"token":"csrf"}}`)
					return
				}
				c, err := r.Cookie(session)
				if err != nil {
					t.Error("missing platform session")
					http.Error(w, "missing session", 401)
					return
				}
				switch r.URL.Path {
				case "/api/v1/platform/risk-policies/requests":
					if c.Value != "risk" {
						t.Error("risk policy submitted by", c.Value)
					}
				case "/api/v1/platform/risk-policies/approvals/" + aid + "/assertions":
					var body object
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || people[c.Value] == "" {
						t.Error("unexpected approval")
						return
					}
					signatures = append(signatures, object{"request_id": aid, "approver_id": people[c.Value], "assertion": object{"credential_id": obj(body["assertion"])["credential_id"]}})
					if len(signatures) == 2 {
						header["status"] = "approved"
					}
				default:
					t.Error("unexpected path", r.URL.Path)
				}
				json.NewEncoder(w).Encode(object{"code": 200, "data": object{"approval_request": header, "material": material, "approvals": signatures}})
			}))
			defer srv.Close()
			for _, n := range []string{"risk", "operations", "approver1", "approver2"} {
				b := d.browser(n)
				b.addr = strings.TrimPrefix(srv.URL, "http://")
				b.cookies[session] = n
				d.put("user/"+n, d.key("iam/"+n))
				d.put("session-until/"+n, time.Now().Add(time.Minute))
			}
			submit := func() {
				d.approveChannelRisk(md5Channel, channel, effectiveAt)
			}
			if tc.requester == "operations" {
				expectFailure(t, submit)
				if len(signatures) != 0 {
					t.Fatal("signed another user's request")
				}
			} else {
				submit()
				if len(signatures) != 2 || d.active.Evidence["requested_by"] != user {
					t.Fatal("missing approvals or requester evidence")
				}
				if got := d.active.Evidence["hold_duration_seconds"]; got != tc.holdSeconds {
					t.Fatalf("approved hold = %v, want %d seconds", got, tc.holdSeconds)
				}
			}
		})
	}
}

func TestReleaseWaitLimit(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	trade := func(remaining time.Duration) object {
		return object{"risk_release_at": now.Add(remaining).Format(time.RFC3339Nano)}
	}
	for _, tc := range []struct {
		name          string
		env           demoEnvironment
		trade         object
		minimum, want time.Duration
	}{
		{"native fallback", nativeEnvironment{}, nil, 0, 80 * time.Second},
		{"native keeps previous limit", nativeEnvironment{}, nil, 2 * time.Minute, 2 * time.Minute},
		{"kubernetes fallback", &kubeEnvironment{}, object{"risk_release_at": nil}, 2 * time.Minute, 3 * time.Minute},
		{"partly elapsed hold", &kubeEnvironment{}, trade(90 * time.Second), 2 * time.Minute, 150 * time.Second},
		{"previous kubernetes policy", &kubeEnvironment{}, trade(20 * time.Second), 2 * time.Minute, 2 * time.Minute},
		{"extended hold", nativeEnvironment{}, trade(4 * time.Minute), 2 * time.Minute, 5 * time.Minute},
		{"elapsed hold", &kubeEnvironment{}, trade(-time.Minute), 2 * time.Minute, 2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &driver{demoEnvironment: tc.env}
			if got := d.releaseWaitLimit(tc.trade, now, tc.minimum); got != tc.want {
				t.Errorf("release wait limit = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSellerCeremony(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", "setup")
	account, user, email := id(), id(), d.email("seller")
	t.Setenv(sellersDatabase, "ambient")
	t.Setenv("AIPAY_DATABASE_URL", "runtime")
	check(atomic(filepath.Join(root, "env/iam-sellers.env"), []byte(sellersDatabase+"=owner-fixture\n")))
	// The stand-in inspects the actual child environment and reads the declaration
	// from the path passed to IAM. Its list response also covers pre-enrolled sellers.
	bin := filepath.Join(root, "bin/iam")
	check(atomic(bin, []byte(`#!/usr/bin/env python3
import json, os, sys
assert os.environ["AIPAY_IAM_SELLERS_DATABASE_URL"] == "owner-fixture"
assert "AIPAY_DATABASE_URL" not in os.environ
assert sys.argv[1] == "sellers"
with open("declarations/seller.json") as f:
    row = json.load(f)
if sys.argv[2] == "activate":
    assert os.path.samefile(sys.argv[3], "declarations/seller.json")
    print(json.dumps(dict(row, declared_at="2026-11-19T00:00:00Z")))
else:
    assert sys.argv[2:] == ["list"]
    print(json.dumps([row]))
`)))
	check(os.Chmod(bin, 0700))
	want := object{"account_id": account, "user_id": user, "email": email, "verification_ref": "demo/telegram/" + account,
		"declared_by": "demo-operator", "reason": "演示卖方首次开通上游门户"}
	path := filepath.Join(d.dir, "declarations/seller.json")
	for i := 0; i < 2; i++ {
		d = newDriver(root, "", "setup")
		d.liveStep("卖方开通登记", func() { d.activateSeller(account, user, email) })
		if !bytes.Equal(file(path), encoded(want)) {
			t.Fatal("persisted seller declaration changed")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("seller declaration permissions")
		}
		var r report
		decode(file(filepath.Join(d.dir, "reports/setup.json")), &r)
		e := r.Steps[0].Evidence
		if e["demo_declared_by"] != want["declared_by"] || e["demo_verification_ref"] != want["verification_ref"] {
			t.Fatal("report did not identify demo attestation")
		}
	}
	t.Setenv("AIPAY_DEMO_SELLER_ACCOUNT_ID", account)
	t.Setenv("AIPAY_DEMO_SELLER_EMAIL", strings.ToUpper(email))
	d.liveStep("已有登记", d.enrollSeller)
	if d.required("seller-owner") != user || d.required("seller-email") != email {
		t.Fatal("pre-enrolled identity mismatch")
	}
	d.put("seller-email", "another@demo.aipay.test")
	expectFailure(t, func() { d.liveStep("已有登记", d.enrollSeller) })
}
func TestBrowserTOTP(t *testing.T) {
	secret := qrSecret(file("testdata/iam-rfc6238.png"))
	if totp(secret, time.Unix(59, 0)) != "287082" {
		t.Fatal("RFC 6238 SHA1 vector")
	}
}
func TestBotAndWebhook(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", "setup")
	f := fixtures{dir: d.dir, token: "test-token", webhook: "https://merchant.aipay.test/telegram/webhook"}
	call := func(token, method string, body object) (int, object) {
		r := httptest.NewRequest("POST", "/bot"+token+"/"+method, bytes.NewReader(encoded(body)))
		w := httptest.NewRecorder()
		f.bot(w, r)
		var m object
		if w.Code == 200 {
			decode(w.Body.Bytes(), &m)
		}
		return w.Code, m
	}
	if code, _ := call("bad", "sendMessage", object{}); code != 404 {
		t.Fatal(code)
	}
	_, info := call(f.token, "getWebhookInfo", object{})
	if obj(info["result"])["url"] != f.webhook {
		t.Fatal("webhook URL")
	}
	_, member := call(f.token, "getChatMember", object{"chat_id": demoGroup, "user_id": merchantUser})
	if obj(member["result"])["status"] != "member" {
		t.Fatal("group membership")
	}
	check(atomic(filepath.Join(root, "env/backend.env"), []byte("AIPAY_TELEGRAM_WEBHOOK_SECRET=demo-secret\n")))
	var updates []int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != "demo-secret" || r.URL.Path != "/telegram/webhook" {
			t.Error("webhook headers/path")
		}
		var u object
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		decode(buf.Bytes(), &u)
		updates = append(updates, num(u, "update_id"))
		msg := obj(u["message"])
		chat := obj(msg["chat"])
		actor := num(obj(msg["from"]), "id")
		if actor != merchantUser || (chat["type"] == "private") != (num(chat, "id") == actor) {
			t.Error("Telegram sender/chat")
		}
		call(f.token, "sendMessage", object{"chat_id": chat["id"], "text": "reply"})
	}))
	defer srv.Close()
	d.browser("merchant").addr = strings.TrimPrefix(srv.URL, "http://")
	for i, chat := range []int64{merchantUser, demoGroup} {
		label := fmt.Sprint(i)
		reply := d.telegram(label, chat, func() string { return "/balance" })
		if reply.Chat != chat || reply.Text != "reply" {
			t.Fatal(reply)
		}
		d.telegram(label, chat, func() string { panic("replayed operation") })
	}
	if len(updates) != 2 || updates[1] <= updates[0] {
		t.Fatal(updates)
	}
	call(f.token, "deleteMessage", object{"chat_id": merchantUser, "message_id": 1})
	ms := d.messages()
	if !ms[0].Deleted || ms[0].Text != "" || ms[1].Deleted {
		t.Fatal(ms)
	}
}
func TestMerchantReceipt(t *testing.T) {
	f := fixtures{dir: t.TempDir()}
	check(atomic(filepath.Join(f.dir, "merchant-key.json"), encoded(object{"PID": "10001", "Key": "demo"})))
	v := url.Values{"pid": {"10001"}, "trade_no": {"T"}, "out_trade_no": {"M"}, "money": {"1.00"}, "trade_status": {"TRADE_SUCCESS"}, "sign_type": {"MD5"}}
	// Independent MD5 vector over the decoded, sorted V1 fields.
	v.Set("sign", "d61b4870d2598c0dee4b4d1320fefaba")
	send := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", notifyOrigin+"/notify", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.notify(w, r)
		return w
	}
	if w := send(); w.Code != 200 || w.Body.String() != "success" {
		t.Fatal(w.Code, w.Body)
	}
	v.Set("money", "2.00")
	if send().Code != 403 {
		t.Fatal("mutated signed money")
	}
	v.Add("money", "1.00")
	if send().Code != 403 {
		t.Fatal("duplicate money")
	}
	rs, e := readRecords[receipt](filepath.Join(f.dir, "notifications.json"))
	if e != nil || len(rs) != 1 || rs[0].MerchantOrder != "M" {
		t.Fatal(rs, e)
	}
	req := httptest.NewRequest("CONNECT", "http://localhost", nil)
	req.Host = "127.0.0.1:5432"
	w := httptest.NewRecorder()
	tunnel(w, req)
	if w.Code != 403 {
		t.Fatal("unapproved proxy port")
	}
}
func TestResumeAndReport(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", "setup")
	count := 0
	once := func() { count++; d.evidence("proof", "ok") }
	d.step("first", once)
	expectFailure(t, func() { d.step("second", func() { d.trace("POST /safe → HTTP 403"); stop("denied") }) })
	next := newDriver(root, "", "setup")
	next.step("first", once)
	next.step("second", once)
	if count != 2 {
		t.Fatal(count)
	}
	for _, file := range []string{"state.json", "reports/setup.md", "reports/setup.json"} {
		s, e := os.Stat(filepath.Join(d.dir, file))
		if e != nil || s.Mode().Perm() != 0600 {
			t.Fatal(file, e)
		}
	}
}

func TestBrowserOriginCookieRotation(t *testing.T) {
	d := newDriver(t.TempDir(), "", "setup")
	b := d.browser("admin1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != rp {
			t.Error("unexpected host")
		}
		if r.Method == "GET" {
			http.SetCookie(w, &http.Cookie{Name: "__Host-csrf", Value: "nonce", Path: "/", Secure: true, HttpOnly: true})
			io.WriteString(w, `{"code":200,"data":{"token":"bound"}}`)
			return
		}
		c, e := r.Cookie("__Host-csrf")
		if e != nil || c.Value != "nonce" || r.Header.Get("Origin") != adminOrigin || r.Header.Get("X-CSRF-Token") != "bound" || r.Header.Get("Idempotency-Key") != "stable" {
			t.Error("browser context mismatch")
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-session", Value: "result", Path: "/", Secure: true, HttpOnly: true})
		io.WriteString(w, `{"code":200,"data":{"state":"authenticated"}}`)
	}))
	defer server.Close()
	b.addr = strings.TrimPrefix(server.URL, "http://")
	b.api("POST", "/auth/login", "stable", object{"email": "a@example.test", "password": "example"})
	if d.browser("admin2").cookies["__Host-session"] != "" || newDriver(d.root, "", "setup").browser("admin1").cookies["__Host-session"] != "result" {
		t.Fatal("cookie scope/persistence")
	}
}

// The owners and the backend command digest accept only sorted, compact
// manifests; pluginctl writes struct order. Integers must stay verbatim.
func TestCanonicalManifest(t *testing.T) {
	raw := []byte("{\n  \"type\": \"payment\",\n  \"code\": \"sim\",\n  \"abi_version\": 2,\n  \"domains\": [\"a<b\"],\n  \"public_keys\": []\n}\n")
	want := `{"abi_version":2,"code":"sim","domains":["a<b"],"public_keys":[],"type":"payment"}`
	if got := string(canonicalManifest(raw)); got != want {
		t.Fatalf("canonical manifest = %s", got)
	}
	if got := canonicalManifest([]byte(want)); string(got) != want {
		t.Fatal("canonical manifest is not idempotent")
	}
}

func TestProposalTimestampsCompareAsInstants(t *testing.T) {
	sent := object{"effective_at": "2026-11-20T05:51:22Z", "hold_duration_seconds": json.Number("20")}
	echoed := object{"effective_at": "2026-11-20T05:51:22.000000Z", "hold_duration_seconds": json.Number("20")}
	if !matchesProposal(echoed, sent) {
		t.Fatal("same instant at different precision must match")
	}
	echoed["effective_at"] = "2026-11-20T05:51:23.000000Z"
	if matchesProposal(echoed, sent) {
		t.Fatal("a different instant must not match")
	}
	if sameInstant("20", "20.0") {
		t.Fatal("non-time strings must not compare as instants")
	}
}
