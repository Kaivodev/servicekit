package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	ledgerTestID   = "01890f3e-1234-7000-8000-000000000001"
	ledgerTestUser = "01890f3e-1234-7000-8000-000000000002"
)

// Fixed wire fixtures were encoded separately with Python struct.pack and UUID.bytes.
func TestLedgerChallenge(t *testing.T) {
	const header = "01890f3e1234700080000000000000010000002430313839306633652d313233342d373030302d383030302d3030303030303030303030320000000042f6940000004e94d4459400"
	for _, tc := range []struct {
		kind, wire, digest string
		fields, edits      object
	}{
		{"read_only_exit", "0000001e61697061792e6c65646765722e726561645f6f6e6c795f657869742e7631" + header +
			"0000000f6465765f6472696c6c3a6472696c6c00000000270025680000000a45786974206472696c6c000000000000000300000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000002",
			"ad0ecfb97715016e5bc6e15382d01759775267432dd3a59263d04d886ba8f097",
			object{"read_only_reason": "dev_drill:drill", "read_only_since": "1970-01-01T00:00:00.654321Z", "note": "Exit drill", "head_seq": json.Number("3"),
				"head_hash": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "last_checkpoint_id": json.Number("2")},
			object{"read_only_reason": "changed", "read_only_since": "1970-01-01T00:00:00.654322Z", "note": "Edited", "head_seq": json.Number("4"), "head_hash": strings.Repeat("ff", 32), "last_checkpoint_id": json.Number("3")}},
		{"usd_rate_policy", "0000001f61697061792e6c65646765722e7573645f726174655f706f6c6963792e7631" + header + "000000010000000100000001000000000000c350000124f80000000c506f6c696379206472696c6c",
			"d9e0b243564f64d56aa186012b64b3f6c10ad5dd4c036f7f549defd39687a655",
			normalized(object{"version": uint64(4294967297), "expected_version": uint64(4294967296), "threshold_ppm": 50000, "ceiling_ppm": 75000, "reason": "Policy drill"}),
			normalized(object{"version": 2, "expected_version": 1, "threshold_ppm": uint64(1)<<32 + 50000, "ceiling_ppm": 75001, "reason": "Edited policy"})},
		{"carryover", "0000001961697061792e6c65646765722e63617272796f7665722e7631" + header +
			"00000007323032362d31310000001b756e6d6174636865645f72656365697074733a555344543a425343fffffffffffffffb0000000b4361727279206472696c6c",
			"09aebb65db7dd732af8167254fbbf1bfdfca0522a57b2a586a3a1e78a0f996a0",
			object{"period_id": "2026-11", "account_code": "unmatched_receipts:USDT:BSC", "units": "-5", "reason": "Carry drill"},
			object{"period_id": "2026-12", "account_code": "other", "units": "5", "reason": "Edited"}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			request := object{"kind": tc.kind, "id": ledgerTestID, "requested_by": ledgerTestUser, "requested_at": "1970-01-01T00:00:01.123456Z", "expires_at": "1970-01-02T00:00:01.123456Z",
				"request_bytes": b64.EncodeToString(wire), "request_digest": tc.digest}
			tc.fields["requested_by"] = ledgerTestUser
			tc.fields["approval_request_id"] = ledgerTestID
			tc.fields["requested_at"], tc.fields["expires_at"] = request["requested_at"], request["expires_at"]
			if got := hex.EncodeToString(ledgerChallenge(tc.kind, request, tc.fields)); got != tc.digest {
				t.Fatal("wrong challenge", got)
			}
			tc.edits["requested_by"] = ledgerTestID
			tc.edits["approval_request_id"] = ledgerTestUser
			tc.edits["requested_at"] = "1970-01-01T00:00:01Z"
			tc.edits["expires_at"] = "1970-01-02T00:00:01Z"
			for field, value := range tc.edits {
				t.Run(field, func(t *testing.T) {
					expected := maps.Clone(tc.fields)
					expected[field] = value
					expectFailure(t, func() { ledgerChallenge(tc.kind, request, expected) })
				})
			}
			for field, value := range (object{"kind": "other", "id": ledgerTestUser, "requested_by": ledgerTestID, "requested_at": "1970-01-01T00:00:01Z",
				"expires_at": "1970-01-02T00:00:01Z", "request_digest": strings.ToUpper(tc.digest)}) {
				r := maps.Clone(request)
				r[field] = value
				expectFailure(t, func() { ledgerChallenge(tc.kind, r, tc.fields) })
			}
			wire = append(wire, 0)
			request["request_bytes"] = b64.EncodeToString(wire)
			request["request_digest"] = fmt.Sprintf("%x", sha256.Sum256(append([]byte("AIPAY-APPROVAL-V1"), wire...)))
			expectFailure(t, func() { ledgerChallenge(tc.kind, request, tc.fields) })
		})
	}
}

func TestLedgerCommandDigests(t *testing.T) {
	for _, tc := range []struct {
		method, hash string
		cmd          portalCommand
	}{
		{"RequestReadOnlyExit", "c5f3b67e076cdbe5ff044e49fad178c20c53907e7ad71c002e1145bac7103c0d", exitCommand(ledgerTestID, "Exit drill")},
		{"RecordCarryover", "7623968b10297026be531999f6d4a3077e1b3d0b6043839c865b7c70a4131ddd", carryoverCommand(ledgerTestID, "2026-11", "unmatched_receipts:USDT:BSC", -5, "Carry drill")},
	} {
		var wire bytes.Buffer
		field := func(s string) {
			if err := binary.Write(&wire, binary.BigEndian, uint32(len(s))); err != nil {
				t.Fatal(err)
			}
			wire.WriteString(s)
		}
		field("aipay.web.command.v1")
		field("/aipay.ledger.v1.LedgerControlService/" + tc.method)
		field(ledgerTestID)
		if tc.method == "RequestReadOnlyExit" {
			field("Exit drill")
		} else {
			field("2026-11")
			field("unmatched_receipts:USDT:BSC")
			if err := binary.Write(&wire, binary.BigEndian, int64(-5)); err != nil {
				t.Fatal(err)
			}
			field("Carry drill")
			if tc.cmd.body["units"] != "-5" {
				t.Fatal("units must travel as decimal text")
			}
		}
		want := sha256.Sum256(wire.Bytes())
		if hex.EncodeToString(want[:]) != tc.hash || tc.cmd.digest != want {
			t.Errorf("wrong command digest for %s", tc.method)
		}
	}
}

func TestLedgerSubmitBindsLocalDigest(t *testing.T) {
	d := newDriver(t.TempDir(), "", ledgerCarryover)
	d.active = &result{Evidence: object{}}
	b := d.browser("finance")
	carry := carryoverCommand(ledgerTestID, "2026-11", "unmatched_receipts:USDT:BSC", -5, "Carry drill")
	adjust := usdtAdjustment("Test posting", fundsLoss, "platform_capital:USDT", 1).command(ledgerTestID)
	policy := ratePolicyCommand(ledgerTestID, 0, 50_000, "Keep threshold")
	for _, tc := range []struct {
		name                string
		cmd                 portalCommand
		challenge, mismatch bool
	}{
		{"recent login", carry, false, false},
		{"wrong carryover digest", carry, true, true},
		{"matching adjustment digest", adjust, true, false},
		{"wrong adjustment digest", adjust, true, true},
		{"matching policy digest", policy, true, false},
		{"wrong policy digest", policy, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cmd
			grants := 0
			grant := func(got portalCommand) string {
				if got.digest != c.digest || got.path != c.path || got.permission != c.permission {
					t.Fatal("grant bound to a different command")
				}
				grants++
				return fmt.Sprintf("bound-%d", grants)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case b.prefix + "/auth/csrf":
					w.Write(encoded(object{"code": 200, "data": object{"token": "csrf"}}))
				case b.prefix + c.path:
					binding := r.Header.Get("X-Reauthentication-ID")
					if binding == "bound-1" && tc.challenge {
						digest := c.digest
						if tc.mismatch {
							digest[0] ^= 1
						}
						w.Header().Set("X-Command-SHA256", b64.EncodeToString(digest[:]))
						w.Write(encoded(object{"code": 428}))
						return
					}
					if binding != "bound-1" && binding != "bound-2" {
						t.Error("submit without the bound reauthentication")
					}
					w.Write(encoded(object{"code": 200, "data": object{"accepted": true}}))
				default:
					t.Error("unexpected request", r.URL.Path)
				}
			}))
			defer server.Close()
			b.addr = strings.TrimPrefix(server.URL, "http://")
			if tc.mismatch {
				if got := failureText(func() { b.submitLedgerWith(c, grant) }); !strings.Contains(got, "differs from the local command") || grants != 1 {
					t.Fatal("unexpected digest mismatch result", got, grants)
				}
				return
			}
			want := 1
			if tc.challenge {
				want = 2
			}
			if reply := b.submitLedgerWith(c, grant); reply["accepted"] != true || grants != want {
				t.Fatal("bound submit failed", reply, grants)
			}
		})
	}
}

func TestLedgerDevOwnerAllowlist(t *testing.T) {
	root := t.TempDir()
	e := nativeEnvironment{root: root, dir: root}
	check(atomic(filepath.Join(root, "env/ledger-migrate.env"), []byte("AIPAY_DATABASE_URL=owner-db\n")))
	bin := filepath.Join(root, "bin/ledger")
	check(atomic(bin, []byte("#!/bin/sh\nprintf '%s/%s/%s' \"$AIPAY_ENVIRONMENT\" \"$AIPAY_DATABASE_URL\" \"$*\"\n")))
	check(os.Chmod(bin, 0700))
	args := []string{"dev", "enter-read-only", "--reason", "drill"}
	const db = "AIPAY_DATABASE_URL"
	t.Setenv("AIPAY_ENVIRONMENT", "production")
	check(atomic(filepath.Join(root, "env/ledger.env"), []byte("AIPAY_ENVIRONMENT=development\nAIPAY_DATABASE_URL=app-db\n")))
	if got := string(e.owner("ledger", db, args...)); got != "development/owner-db/dev enter-read-only --reason drill" {
		t.Fatal("wrong ledger command environment")
	}
	for _, bad := range [][]string{{"dev"}, {"dev", "archive-work"}, {"dev", "enter-read-only-extra"}} {
		expectFailure(t, func() { e.owner("ledger", db, bad...) })
	}
	expectFailure(t, func() { e.owner("ledger", "AIPAY_LEDGER_APPROVERS_DATABASE_URL", args...) })
	expectFailure(t, func() { new(kubeEnvironment).owner("ledger", db, args...) })
	check(atomic(filepath.Join(root, "env/ledger.env"), []byte("AIPAY_ENVIRONMENT=staging\n")))
	expectFailure(t, func() { e.owner("ledger", db, args...) })
}

func TestLedgerScenarioRegistrationAndEnvironment(t *testing.T) {
	for _, name := range []string{"ledger-read-only-exit", "ledger-carryover", "ledger-adjustment", "ledger-approvals-inbox"} {
		t.Run(name, func(t *testing.T) {
			if scenarios[name] == nil {
				t.Fatal("missing scenario")
			}
			root := t.TempDir()
			t.Setenv("AIPAY_DEMO_TARGET", "k8s")
			err := execute([]string{root, ".", "run", name})
			if err == nil || !strings.Contains(err.Error(), "requires the native development stack") {
				t.Fatal("expected Kubernetes refusal", err)
			}
			t.Setenv("AIPAY_DEMO_TARGET", "native")
			check(atomic(filepath.Join(root, "env/ledger.env"), []byte("AIPAY_ENVIRONMENT=staging\n")))
			err = execute([]string{root, ".", "run", name})
			if err == nil || !strings.Contains(err.Error(), "requires AIPAY_ENVIRONMENT=development") {
				t.Fatal("expected staging refusal", err)
			}
		})
	}
}

func TestLedgerStaffInvitations(t *testing.T) {
	for _, tc := range []struct {
		name  string
		roles []string
	}{
		{"finance", []string{"finance"}}, {"approver3", []string{"approver", "finance", "risk"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(t.TempDir(), "", "setup")
			for _, name := range []string{"admin1", "admin2"} {
				d.put("user/"+name, name)
				d.put("session-until/"+name, time.Now().Add(time.Hour))
				d.browser(name).cookies["__Host-kaivo_platform_session"] = name
			}
			d.put("write/setup/accept/"+tc.name+"/result", object{"user_id": tc.name})
			invID := id()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var data object
				switch strings.TrimPrefix(r.URL.Path, "/api/v1/platform") {
				case "/auth/csrf":
					data = object{"token": "csrf"}
				case "/invitations/platform-staff":
					var body struct {
						Roles []string `json:"platform_roles"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !slices.Equal(body.Roles, tc.roles) {
						t.Error("wrong invitation role list", body.Roles, err)
					}
					data = object{"email": d.email(tc.name), "invited_by": "admin1", "status": "pending_approval", "id": invID, "version": 1}
				case "/invitations/" + invID + "/approvals":
					cookie, err := r.Cookie("__Host-kaivo_platform_session")
					if err != nil || cookie.Value != "admin2" {
						t.Error("missing second administrator")
					}
					data = object{"id": invID, "approved_by": "admin2", "status": "pending"}
				default:
					t.Error("unexpected invitation operation", r.URL.Path)
				}
				w.Write(encoded(object{"code": 200, "data": data}))
			}))
			defer server.Close()
			for _, n := range []string{"admin1", "admin2"} {
				d.browser(n).addr = strings.TrimPrefix(server.URL, "http://")
			}
			d.invite(tc.name, tc.roles...)
			if d.data["write/setup/approve invite/"+tc.name+"/result"] == nil || d.required("user/"+tc.name) != tc.name {
				t.Fatal("missing approval or accepted identity checkpoint")
			}
		})
	}
}

type ledgerOwnerFixture struct {
	demoEnvironment
	run func(service, dbvar string, args ...string) []byte
}

func (e ledgerOwnerFixture) owner(service, dbvar string, args ...string) []byte {
	return e.run(service, dbvar, args...)
}

func TestLedgerRegistrationRecognizesOnlyActiveKeyBindings(t *testing.T) {
	d := newDriver(t.TempDir(), "", "setup")
	d.active = &result{Evidence: object{}}
	d.origins = readPortalOrigins(map[string]string{"AIPAY_PLATFORM_ORIGIN": "https://admin.demo.test"})
	const n = "approver3"
	d.put("user/"+n, ledgerTestUser)
	person := d.key("person/" + n)
	key := d.credential(n)
	cose := key.cose()
	active := object{
		"id": d.key(n + "/ledger"), "approver_id": person, "iam_user_id": ledgerTestUser,
		"credential_id_sha256": fmt.Sprintf("%x", sha256.Sum256(key.ID)), "public_key_sha256": fmt.Sprintf("%x", sha256.Sum256(cose)),
		"revoked_at": nil,
	}
	var rows []object
	for _, field := range []string{"approver_id", "iam_user_id", "credential_id_sha256", "public_key_sha256", "revoked_at"} {
		wrong := maps.Clone(active)
		wrong[field] = "different"
		rows = append(rows, wrong)
	}
	var calls []string
	d.demoEnvironment = ledgerOwnerFixture{d.demoEnvironment, func(service, dbvar string, args ...string) []byte {
		if service != "ledger" || dbvar != "AIPAY_LEDGER_APPROVERS_DATABASE_URL" || args[0] != "approvers" {
			t.Fatal("wrong ledger owner command")
		}
		calls = append(calls, args[1])
		switch args[1] {
		case "list":
			return encoded(rows)
		case "register":
			var decl object
			decode(file(args[2]), &decl)
			if decl["id"] != active["id"] || decl["approver_id"] != person || decl["iam_user_id"] != ledgerTestUser ||
				decl["rp_id"] != "admin.demo.test" || decl["ceremony_ref"] != "demo-approver3" ||
				decl["credential_id"] != b64.EncodeToString(key.ID) || decl["public_key_cose"] != b64.EncodeToString(cose) {
				t.Fatal("incorrect ledger key declaration")
			}
			rows = append(rows, active)
			return encoded(active)
		default:
			t.Fatal("unexpected owner command", args[1])
		}
		return nil
	}}
	d.registerLedgerApprover(n)
	d.registerLedgerApprover(n)
	if !slices.Equal(calls, []string{"list", "register", "list", "list"}) {
		t.Fatalf("unexpected registrar calls %v", calls)
	}
}

func TestLedgerStaffPreambleAndCompletion(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		staff    []string
	}{
		{ledgerReadOnlyExit, []string{"risk", "approver1", "approver2", "approver3"}},
		{ledgerCarryover, []string{"finance", "approver1", "approver3"}},
		{ledgerAdjustment, []string{"finance", "approver1", "approver2", "approver3", "seller"}},
		{ledgerApprovalsInbox, []string{"finance", "risk", "approver1", "approver2"}},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			root := t.TempDir()
			d := newDriver(root, "", tc.scenario)
			for _, n := range tc.staff {
				cookie := "__Host-kaivo_platform_session"
				if n == "seller" {
					cookie = "__Host-kaivo_seller_session"
				}
				d.put("cookies/"+n, map[string]string{cookie: n})
				d.put("session-until/"+n, time.Now().Add(time.Hour))
			}
			run := scenarios[tc.scenario]
			t.Cleanup(func() { scenarios[tc.scenario] = run })
			calls := 0
			scenarios[tc.scenario] = func(d *driver) {
				calls++
				if len(d.browsers) != len(tc.staff) {
					t.Fatal("unexpected number of staff sessions")
				}
				for _, n := range tc.staff {
					if d.browsers[n] == nil {
						t.Fatal("missing staff session", n)
					}
				}
			}
			d.run(tc.scenario)
			resumed := newDriver(root, "", tc.scenario)
			var finished bool
			if !resumed.read("finished/"+tc.scenario, &finished) || !finished {
				t.Fatal("missing finished checkpoint")
			}
			resumed.run(tc.scenario)
			if calls != 1 {
				t.Fatal("completed scenario ran again")
			}
		})
	}
}
