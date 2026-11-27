package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	syncatomic "sync/atomic"
	"testing"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"google.golang.org/protobuf/proto"
)

func TestA144RetryEvidence(t *testing.T) {
	audits := []object{
		{"action": "order.dispatch_control", "id": "initial"}, {"action": "order.dispatch_not_sent"},
		{"action": "order.retry_claimed", "id": "again"}, {"action": "order.dispatch_not_sent"},
		{"action": "order.retry_claimed", "id": "last"}, {"action": "order.dispatched"},
	}
	creates := []object{
		normalized(object{"execution_key": "create_payment:initial", "category": "not_sent", "error_code": "transport_connect", "requests": 0}),
		normalized(object{"execution_key": "create_payment:again", "category": "not_sent", "error_code": "transport_connect", "requests": 0}),
		normalized(object{"execution_key": "create_payment:last", "category": "succeeded", "responses": 1}),
	}
	if !validA144Retries(audits, creates) || validA144Retries(audits[4:], creates[2:]) || validA144Retries(audits[:5], creates) {
		t.Fatal("expected two failed grants and a successful retry")
	}
	for _, tc := range []struct {
		row   object
		key   string
		value any
	}{
		{audits[2], "action", "order.dispatch_control"}, {audits[1], "action", "order.dispatched"},
		{creates[2], "execution_key", "create_payment:again"}, {creates[2], "category", "unknown"},
		{creates[0], "error_code", "transport_tls"}, {creates[1], "requests", creates[2]["responses"]},
	} {
		old := tc.row[tc.key]
		tc.row[tc.key] = tc.value
		if validA144Retries(audits, creates) {
			t.Errorf("accepted invalid %s = %v", tc.key, tc.value)
		}
		tc.row[tc.key] = old
	}
}

func TestA144CancellationPayload(t *testing.T) {
	const order = "original"
	event := &pay.OrderCancellationVerificationRequested{OrderId: order, EscrowReservationId: "hold", ControlVersion: 7,
		Basis: pay.OrderCancellationBasis_ORDER_CANCELLATION_BASIS_CREATE_NOT_FOUND_INFERRED}
	wire := func() string {
		b, err := proto.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b)
	}
	if got := a144Cancellation(wire(), order); !proto.Equal(event, got) {
		t.Fatal("inferred cancellation payload changed")
	}
	expectFailure(t, func() { a144Cancellation(wire(), "different") })
	expectFailure(t, func() { a144Cancellation("ff", order) })
	for _, basis := range []pay.OrderCancellationBasis{0, 2} {
		event.Basis = basis
		event.EscrowReservationId = "contains\x20\x01inside"
		expectFailure(t, func() { a144Cancellation(wire(), order) })
	}
}

func TestNativeGatewayScenarioPrerequisites(t *testing.T) {
	for _, scenario := range []string{a144NotFound, a144NotSent, a145NeverSent, a145StaleBinding, a145UnpaidBeforeT, a145LatePayment, a145Refusals, kQueryTransient, kLedgerCancelEvent, disputeReturn} {
		root := t.TempDir()
		amount, channel := scenarioOrder(scenario, true)
		if scenarios[scenario] == nil || channel != epayChannel || amount != "2.00" {
			t.Fatal("missing EPay scenario", scenario)
		}
		args := []string{root, root, "run", scenario}
		refuses := func(want string) {
			t.Helper()
			if err := execute(args); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("expected %q, got %v", want, err)
			}
		}
		t.Setenv("AIPAY_DEMO_TARGET", "k8s")
		refuses("仅本机栈")
		t.Setenv("AIPAY_DEMO_TARGET", "native")
		marker := filepath.Join(root, "stack.env")
		check(atomic(marker, nil))
		refuses("Compose")
		check(os.Remove(marker))
		payment := filepath.Join(root, "env/payment.env")
		check(atomic(payment, nil))
		refuses("需要交易与核验网关")
		check(atomic(filepath.Join(root, "env/reconciliation.env"), []byte("AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS=verify\n")))
		check(atomic(filepath.Join(root, "inputs/upstream-sim/config.json"), []byte(`{"environment":"test"}`)))
		for _, mode := range []string{"staging", "production"} {
			check(atomic(payment, []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=trade\nAIPAY_ENVIRONMENT="+mode+"\n")))
			if scenario != a144NotSent && scenario != a145NeverSent && scenario != kQueryTransient {
				refuses("AIPAY_ENVIRONMENT=development")
			} else {
				refuses("control token")
			}
		}
		check(atomic(payment, []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=trade\nAIPAY_ENVIRONMENT=development\n")))
		refuses("control token")
	}
}

func TestPaymentDevOwnerEnvironment(t *testing.T) {
	root := t.TempDir()
	e := nativeEnvironment{root: root, dir: root}
	check(atomic(filepath.Join(root, "env/payment-migrate.env"), []byte("AIPAY_DATABASE_URL=owner-db\n")))
	bin := filepath.Join(root, "bin/payment")
	check(atomic(bin, []byte("#!/bin/sh\nprintf '%s/%s' \"$AIPAY_ENVIRONMENT\" \"$AIPAY_DATABASE_URL\"\n")))
	check(os.Chmod(bin, 0700))
	t.Setenv("AIPAY_ENVIRONMENT", "parent")
	for _, args := range [][]string{
		{"dev", "backdate-create", "--order", "order", "--seconds", "4320"},
		{"dev", "archive-work", "--order", "order"},
	} {
		check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_ENVIRONMENT=development\n")))
		if !isPaymentDevCommand("payment", args) || isPaymentDevCommand("ledger", args) {
			t.Fatalf("incorrect owner gate for %s", args[1])
		}
		if got := string(e.owner("payment", "AIPAY_DATABASE_URL", args...)); got != "development/owner-db" {
			t.Fatalf("wrong payment owner environment for %s", args[1])
		}
		check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_ENVIRONMENT=staging\n")))
		expectFailure(t, func() { e.owner("payment", "AIPAY_DATABASE_URL", args...) })
		expectFailure(t, func() { new(kubeEnvironment).owner("payment", "AIPAY_DATABASE_URL", args...) })
	}
	for _, args := range [][]string{nil, {"dev"}, {"dev", "other"}, {"archive-work"}, {"other", "backdate-create"}} {
		if isPaymentDevCommand("payment", args) {
			t.Fatalf("unexpected payment dev command: %v", args)
		}
	}
	if got := string(e.owner("payment", "AIPAY_DATABASE_URL", "another")); got != "/owner-db" {
		t.Fatal("unrelated owner command inherited the environment")
	}
}

func TestA144ReadsEnabledPackages(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", a144NotFound)
	d.put("uuid/channel/epay_v1", "channel")
	d.put("uuid/verify-account/epay_v1", "verification")
	d.put("unpaid-timeout/epay_v1", "4320")
	hash := bytes.Repeat([]byte{7}, 32)
	config := b64.EncodeToString(encoded(object{"gateway": d.addresses().gateway, "pid": "1001", "unpaid_timeout_seconds": "4320"}))
	op := d.browser("operations")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("attempted upgrade of already compatible packages")
		}
		var data object
		switch path := strings.TrimPrefix(r.URL.Path, op.prefix); path {
		case "/channel-accounts/channel", "/verification/accounts/verification":
			c := object{"channel_account_id": "channel", "config_json": config, "channel_code": epayChannel, "enabled": true}
			id := "bound-trade"
			if strings.HasPrefix(path, "/verification/") {
				id = "bound-verify"
				c["verification_account_id"] = "verification"
			}
			data = object{"configuration": c, "enabled": true, "control_version": 3, "plugin_version_id": id}
		case "/plugins", "/verification/plugins":
			p := object{"code": epayChannel, "version": "0.4.0", "publication_status": "executed", "plugin_version_id": "bound-trade",
				"emergency_disabled": false, "package_sha256": b64.EncodeToString(hash), "publication_approval_request_id": "approval"}
			if path == "/verification/plugins" {
				p["code"], p["semver"], p["status"], p["plugin_version_id"] = epayChannel+"_verify", "0.3.0", "executed", "bound-verify"
				delete(p, "version")
				delete(p, "publication_status")
			}
			data = object{"items": []object{p}}
			if r.URL.Query().Get("cursor") == "" {
				p["plugin_version_id"] = "unbound"
				data["next_cursor"] = "more"
			}
		default:
			t.Error("unexpected API read", path)
		}
		w.Write(encoded(object{"code": 200, "data": data}))
	}))
	defer server.Close()
	op.addr = strings.TrimPrefix(server.URL, "http://")
	pins := d.a144Plugins()
	if pins[epayChannel] != "bound-trade" || pins[epayChannel+"_verify"] != "bound-verify" {
		t.Fatal("did not resolve the actual bound packages")
	}
	for _, code := range []string{epayChannel, epayChannel + "_verify"} {
		if obj(d.active.Evidence[code])["package_sha256"] != hex.EncodeToString(hash) {
			t.Fatal("missing published digest", code)
		}
	}
}

func TestA144SwitchUsesCurrentOwnerVersions(t *testing.T) {
	d := newDriver(t.TempDir(), "", a144NotFound)
	d.put("uuid/channel/epay_v1", "channel")
	d.put("uuid/verify-account/epay_v1", "verify")
	d.put("unpaid-timeout/epay_v1", "4320")
	d.put("user/operations", "operator")
	d.put("session-until/operations", time.Now().Add(time.Hour))
	op := d.browser("operations")
	op.cookies["__Host-kaivo_platform_session"] = "session"
	digest := bytes.Repeat([]byte{8}, 32)
	for _, p := range d.a144PluginAccounts() {
		t.Run(p.code, func(t *testing.T) {
			d.put("hash/"+p.code, hex.EncodeToString(digest))
			var proposals syncatomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var data object
				switch r.Method + " " + strings.TrimPrefix(r.URL.Path, op.prefix) {
				case "GET " + p.plugins:
					data = object{"items": []object{{"code": p.code, p.versionField: p.minimum, p.statusField: "executed",
						"plugin_version_id": "new", "publication_approval_request_id": "approved", "package_sha256": b64.EncodeToString(digest),
						"control_version": 4, "emergency_disabled": false}}}
				case "GET " + p.accountPath + "/" + p.accountID:
					cfg := object{"gateway": d.addresses().gateway, "pid": "1001", "unpaid_timeout_seconds": "4320"}
					c := object{"channel_account_id": "channel", "channel_code": epayChannel, "enabled": true, "config_json": b64.EncodeToString(encoded(cfg))}
					c[p.accountField] = p.accountID
					data = object{"plugin_version_id": "old", "enabled": true, "control_version": 17, "configuration": c}
				case "GET /auth/csrf":
					data = object{"token": "csrf"}
				case "POST " + p.enables + "/requests":
					var body object
					b, err := io.ReadAll(r.Body)
					if err != nil || decodeJSON(b, &body) != nil || body[p.accountField] != p.accountID || body["plugin_version_id"] != "new" ||
						num(body, "expected_control_version") != 17 || num(body, "expected_plugin_control_version") != 4 {
						t.Error("incorrect rebinding proposal")
					}
					proposals.Add(1)
					w.Write(encoded(object{"code": 409, "msg": "test approval boundary"}))
					return
				default:
					t.Error("unexpected administration call", r.Method, r.URL.Path)
				}
				w.Write(encoded(object{"code": 200, "data": data}))
			}))
			defer server.Close()
			op.addr = strings.TrimPrefix(server.URL, "http://")
			switchVersion := func() { p.upgrade(d, p.minimum, "") }
			if why := failureText(switchVersion); !strings.Contains(why, "test approval boundary") || proposals.Load() != 1 {
				t.Fatal("failed to propose a switch from the enabled account", why)
			}
			d.put("hash/"+p.code, strings.Repeat("99", 32))
			if why := failureText(switchVersion); !strings.Contains(why, "另一份包摘要") || proposals.Load() != 1 {
				t.Fatal("version collision did not stop before rebinding", why)
			}
		})
	}
}
