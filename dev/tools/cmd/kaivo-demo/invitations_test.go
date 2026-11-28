package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestInvitationArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"platform"}, {"platform", "p@example.test"},
		{"other", "p@example.test"}, {"seller", "s@example.test", "risk"},
		{"seller", "s@example.test", "-o", "out"},
		{"platform", "p@example.test", "risk", "risk"}, {"platform", "p@example.test", "-o", "out"}} {
		expectFailure(t, func() { parseInvitation(args) })
	}
	for _, email := range []string{"", "a", "@example.test", "user@", "a@b@c", "a b@c", "a\n@b", "a\x7f@b", "a\u2003@b",
		strings.Repeat("é", 126) + "@ab"} {
		expectFailure(t, func() { parseInvitation([]string{"seller", email}) })
	}
	for _, role := range []string{"", "Role", "a-b", "1a", "_a", "a\n", "rôle"} {
		expectFailure(t, func() { parseInvitation([]string{"platform", "p@example.test", role}) })
	}
	email := strings.Repeat("é", 126) + "@b"
	req := parseInvitation([]string{"platform", email, "risk", "custom_role9"})
	if req.Email != email || !slices.Equal(req.Roles, []string{"risk", "custom_role9"}) {
		t.Fatal("valid invitation arguments changed")
	}
}

func TestInvitationPrerequisites(t *testing.T) {
	root := t.TempDir()
	args := []string{root, ".", "invite", "seller", "s@demo.test"}
	t.Setenv("AIPAY_DEMO_TARGET", "k8s")
	if err := execute(args); err == nil || !strings.Contains(err.Error(), "native target") {
		t.Fatal("expected native target refusal")
	}
	t.Setenv("AIPAY_DEMO_TARGET", "native")
	check(atomic(filepath.Join(root, "env/backend.env"), nil))
	if err := execute(args); err == nil || !strings.Contains(err.Error(), "complete demo setup") {
		t.Fatal("expected setup prerequisite")
	}
	check(atomic(filepath.Join(root, "env/backend.env"), []byte("AIPAY_SELLER_ORIGIN=http://portal.example.test")))
	if err := execute(args); err == nil || !strings.Contains(err.Error(), "AIPAY_SELLER_ORIGIN") {
		t.Fatal("expected validation of the prepared backend environment")
	}
	check(atomic(filepath.Join(root, "stack.env"), nil))
	if err := execute(args); err == nil || !strings.Contains(err.Error(), "native process stack") {
		t.Fatal("expected Compose refusal")
	}
}

func TestInvitationFileIsExclusive(t *testing.T) {
	root := t.TempDir()
	dir := invitationDirectory(root)
	initial := invitationFile{InvitationID: id(), Token: "first"}
	path := writeInvitation(dir, initial)
	changed := initial
	changed.Token = "second"
	expectFailure(t, func() { writeInvitation(dir, changed) })
	if !bytes.Equal(file(path), encoded(initial)) {
		t.Fatal("duplicate publication changed the original file")
	}
	changed.InvitationID = "../outside"
	expectFailure(t, func() { writeInvitation(dir, changed) })
	check(os.Chmod(dir, 0755))
	expectFailure(t, func() { invitationDirectory(root) })
}

func TestPartnerSellerRefusesRealTelegramBeforeChanges(t *testing.T) {
	t.Setenv("AIPAY_DEMO_TARGET", "native")
	root := t.TempDir()
	d := newDriver(root, "", "invite")
	d.put("step/setup/"+merchantActivationStep, result{Status: "ok"})
	d.put("seller-account", id())
	d.put("seller-email", "setup@demo.test")
	for _, admin := range []string{"admin1", "admin2"} {
		d.put("user/"+admin, admin)
		d.password(admin)
		d.credential(admin)
	}
	state := filepath.Join(d.dir, "state.json")
	before := file(state)
	saved := localHTTP
	defer func() { localHTTP = saved }()
	localHTTP = &http.Client{Transport: startWebhook(func(*http.Request) (*http.Response, error) {
		t.Fatal("real-mode refusal sent an HTTP request")
		return nil, nil
	})}
	for _, botURL := range []string{"https://api.telegram.org", "", "http://127.0.0.1:9082"} {
		check(atomic(filepath.Join(root, "env/backend.env"), []byte("AIPAY_TELEGRAM_API_BASE_URL="+botURL)))
		err := execute([]string{root, ".", "invite", "seller", "partner@demo.test"})
		if err == nil || !strings.Contains(err.Error(), "requires mock Telegram mode") {
			t.Fatalf("expected mock-mode prerequisite, got %v", err)
		}
		if !bytes.Equal(before, file(state)) {
			t.Fatal("real-mode refusal changed the checkpoint")
		}
		if _, err := os.Stat(filepath.Join(d.dir, "invitations")); !os.IsNotExist(err) {
			t.Fatal("real-mode refusal created the invitation directory")
		}
	}
}

func TestPartnerTelegramIDs(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", "invite")
	first := d.partnerTelegramID("Partner@demo.test")
	d = newDriver(root, "", "invite")
	second := d.partnerTelegramID("another@demo.test")
	d = newDriver(root, "", "invite")
	for _, v := range []int64{first, second} {
		if v <= 0 || v == merchantUser || v == merchantUser+1 {
			t.Fatal("allocated a reserved or invalid Telegram ID")
		}
	}
	if first == second || first != d.partnerTelegramID("partner@demo.test") || second != d.partnerTelegramID("another@demo.test") {
		t.Fatal("partner Telegram IDs collided or changed on retry")
	}
}

type partnerSellerIAM struct {
	demoEnvironment
	activate func(path string) []byte
}

func (iam partnerSellerIAM) owner(service, dbvar string, args ...string) []byte {
	require(service == "iam" && dbvar == sellersDatabase && len(args) == 3 && args[0] == "sellers" && args[1] == "activate",
		"unexpected seller owner operation")
	return iam.activate(args[2])
}

func TestPartnerSellerEnrollmentRetry(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", "invite")
	const email = "partner@demo.test"
	account, user, setupAccount := id(), id(), id()
	check(atomic(filepath.Join(root, "env/iam.env"), nil))
	check(atomic(filepath.Join(root, "env/backend.env"), []byte("AIPAY_TELEGRAM_API_BASE_URL=http://127.0.0.1:9081")))
	var telegramID int64
	var commands []string
	saved := localHTTP
	defer func() { localHTTP = saved }()
	localHTTP = &http.Client{Transport: startWebhook(func(req *http.Request) (*http.Response, error) {
		defer req.Body.Close()
		var update object
		decoder := json.NewDecoder(req.Body)
		decoder.UseNumber()
		check(decoder.Decode(&update))
		msg := obj(update["message"])
		actor := num(obj(msg["from"]), "id")
		if req.URL.Path != "/telegram/webhook" || num(obj(msg["chat"]), "id") != actor {
			t.Fatal("expected a private seller webhook")
		}
		command := str(msg, "text")
		commands = append(commands, command)
		var reply string
		switch command {
		case "/start":
			telegramID = actor
			reply = "注册或登录已完成"
		case "/balance":
			if actor != telegramID {
				t.Fatal("seller identity changed between commands")
			}
			reply = "账户 " + account + "\n"
		default:
			t.Fatal("unexpected seller bot command")
		}
		messages := append(d.messages(), message{ID: int64(len(commands)), Chat: actor, Text: reply})
		check(atomic(filepath.Join(d.dir, "messages.json"), encoded(messages)))
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	lookups := 0
	binding := func(a string, tg int64) string {
		lookups++
		if a != account || tg != telegramID {
			t.Fatal("wrong seller binding lookup")
		}
		return user
	}
	var committed []byte
	calls := 0
	activate := func(path string) []byte {
		calls++
		declaration := file(path)
		var row object
		decode(declaration, &row)
		want := object{"account_id": account, "user_id": user, "email": email, "verification_ref": "demo/telegram/" + account,
			"declared_by": "demo-operator", "reason": "Partner front-end integration"}
		if !reflect.DeepEqual(row, want) || filepath.Base(path) == "seller.json" {
			t.Fatal("incorrect partner declaration or reused setup declaration path")
		}
		if committed == nil {
			committed = declaration
			stop("lost IAM response")
		}
		if !bytes.Equal(committed, declaration) {
			t.Fatal("retry submitted a different activation")
		}
		row["declared_at"] = "2026-11-19T00:00:00Z"
		return encoded(row)
	}
	resume := func() string {
		d = newDriver(root, "", "invite")
		d.demoEnvironment = partnerSellerIAM{d.demoEnvironment, activate}
		return d.partnerSellerAccount("Partner@demo.test", setupAccount, binding)
	}
	if msg := failureText(func() { resume() }); msg != "lost IAM response" {
		t.Fatalf("expected interrupted activation, got %q", msg)
	}
	if resume() != account || resume() != account || lookups != 1 || calls != 2 || !slices.Equal(commands, []string{"/start", "/balance"}) {
		t.Fatal("retry failed to reuse the registration, owner or activation")
	}
}

func TestPartnerInvitationHandoff(t *testing.T) {
	for _, name := range []string{"platform", "setup seller", "partner seller"} {
		t.Run(name, func(t *testing.T) {
			d := newDriver(t.TempDir(), "", "invite")
			d.origins = readPortalOrigins(map[string]string{
				"AIPAY_PLATFORM_ORIGIN": "https://admin.demo.test", "AIPAY_SELLER_ORIGIN": "https://portal.demo.test",
			})
			d.put("step/setup/"+merchantActivationStep, result{Status: "ok"})
			d.put("seller-account", "setup-account")
			setupEmail, sellerAccount := "invitee@demo.test", "setup-account"
			botURL := "https://api.telegram.org"
			if name == "partner seller" {
				setupEmail, sellerAccount = "setup@demo.test", id()
				botURL = "http://127.0.0.1:9081"
				telegramID := d.partnerTelegramID("invitee@demo.test")
				d.put(fmt.Sprintf("partner-seller-%d/activated-account", telegramID), sellerAccount)
			}
			d.put("seller-email", setupEmail)
			check(atomic(filepath.Join(d.root, "env/backend.env"), []byte("AIPAY_TELEGRAM_API_BASE_URL="+botURL)))
			for _, admin := range []string{"admin1", "admin2"} {
				d.put("user/"+admin, admin)
				d.password(admin)
				d.credential(admin)
				d.put("session-until/"+admin, time.Now().Add(time.Hour))
				d.browser(admin).cookies["__Host-kaivo_platform_session"] = admin
			}
			kind := "seller"
			if name == "platform" {
				kind = "platform"
			}
			req := invitationRequest{Kind: kind, Email: "Invitee@demo.test"}
			const email = "invitee@demo.test"
			invID, mailID := id(), id()
			token := b64.EncodeToString(random(32))
			body := object{"email": req.Email}
			create := "/invitations/sellers"
			want := object{"kind": kind, "email": req.Email, "invitation_id": invID, "token": token}
			if kind == "platform" {
				req.Roles = []string{"risk", "finance"}
				body["platform_roles"] = req.Roles
				want["roles"], want["origin"] = req.Roles, d.origins.platform
				create = "/invitations/platform-staff"
			} else {
				body["seller_account_id"] = sellerAccount
				if name == "partner seller" {
					body["email"] = email
				}
				want["seller_account_id"], want["origin"] = sellerAccount, d.origins.seller
			}
			approval := "/invitations/" + invID + "/approvals"
			var calls []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/api/v1/platform")
				reply := object{"token": "csrf"}
				if path != "/auth/csrf" {
					calls = append(calls, path)
					var submitted object
					check(json.NewDecoder(r.Body).Decode(&submitted))
					c, err := r.Cookie("__Host-kaivo_platform_session")
					if err != nil || r.Host != "admin.demo.test" || r.Header.Get("Origin") != d.origins.platform {
						t.Error("unexpected admin portal context")
						return
					}
					switch path {
					case create:
						if c.Value != "admin1" || !reflect.DeepEqual(submitted, normalized(body)) {
							t.Error("incorrect invitation creation")
						}
						reply = object{"id": invID, "email": email, "invited_by": "admin1", "status": "pending",
							"seller_account_id": sellerAccount}
						if kind == "platform" {
							reply["status"], reply["version"] = "pending_approval", 1
						}
					case approval:
						if c.Value != "admin2" || !reflect.DeepEqual(submitted, object{"expected_version": float64(1)}) {
							t.Error("incorrect independent approval")
						}
						reply = object{"id": invID, "status": "pending", "approved_by": "admin2"}
					default:
						t.Error("unexpected partner invitation operation", path)
					}
					reply["extra"] = token // A backend extension must not be checkpointed.
				}
				w.Write(encoded(object{"code": 200, "data": reply}))
			}))
			defer srv.Close()
			for _, admin := range []string{"admin1", "admin2"} {
				d.browser(admin).addr = strings.TrimPrefix(srv.URL, "http://")
			}
			mail := filepath.Join(d.root, "data/iam/mail")
			writeMail := func(delivery, value string) {
				check(atomic(filepath.Join(mail, delivery+".json"), encoded(iamMail{email, invitationSubject, "Token\uff1a" + value})))
			}
			writeMail(mailID, token)
			writeMail(id(), b64.EncodeToString(random(32))) // Another invitation for the same recipient.
			d.active = &result{Name: "invite", Evidence: object{}}
			d.history.Steps = []*result{d.active}
			state := filepath.Join(d.dir, "state.json")
			var pending []byte
			path := d.exportInvitation(req, func(recipient, invitation string) string {
				if recipient != email || invitation != invID {
					t.Fatal("mail lookup used the wrong recipient or invitation")
				}
				pending = file(state)
				return mailID
			})
			wantCalls := []string{create}
			if kind == "platform" {
				wantCalls = append(wantCalls, approval)
			}
			if !slices.Equal(calls, wantCalls) || path != filepath.Join(d.dir, "invitations", invID+".json") {
				t.Fatal("unexpected invitation operations or output path")
			}
			var handoff object
			decode(file(path), &handoff)
			created, err := time.Parse(time.RFC3339Nano, str(handoff, "created_at"))
			delete(handoff, "created_at")
			if err != nil || time.Since(created).Abs() > time.Minute || !reflect.DeepEqual(handoff, normalized(want)) {
				t.Fatal("incorrect invitation handoff fields")
			}
			for name, mode := range map[string]fs.FileMode{path: 0600, filepath.Dir(path): 0700} {
				st, err := os.Stat(name)
				if err != nil || st.Mode().Perm() != mode {
					t.Fatal("incorrect invitation permissions")
				}
			}
			refused := func() {
				t.Helper()
				restarted := newDriver(d.root, "", "invite")
				if msg := failureText(func() { restarted.exportInvitation(req, nil) }); !strings.Contains(msg, "invitation already published") {
					t.Fatalf("expected existing handoff refusal, got %q", msg)
				}
				if !slices.Equal(calls, wantCalls) || len(restarted.browsers) != 0 {
					t.Fatal("repeated a request for a published invitation")
				}
			}
			check(os.Rename(path, path+".moved"))
			refused()
			check(os.Rename(path+".moved", path))
			check(atomic(state, pending)) // Crash after linking the handoff, before saving its ID.
			refused()
			d.report()
			check(filepath.WalkDir(d.dir, func(p string, entry fs.DirEntry, err error) error {
				if err == nil && !entry.IsDir() && p != path && bytes.Contains(file(p), []byte(token)) {
					t.Error("invitation token escaped the handoff file")
				}
				return err
			}))
		})
	}
}
