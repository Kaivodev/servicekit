package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/protobuf/testvectors"
)

// Project the published payment vector the same way the browser receives it.
// In particular, HTTP Money uses amount_minor and digests use raw base64url.
func TestSellerRefundApprovalVector(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name     string
			Material object
			Bytes    string `json:"request_bytes"`
			Digest   string `json:"request_digest"`
		} `json:"approval_vectors"`
	}
	decode(testvectors.PaymentSellerRefundV1(), &fixture)
	if len(fixture.Vectors) != 4 {
		t.Fatal("expected review and failure vectors with and without optional fields")
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			m := v.Material
			op := obj(m[str(m, "kind")])
			if branch, ok := op["branch"].(string); ok {
				op["branch"] = strings.ToLower(strings.TrimPrefix(branch, "REFUND_RESERVATION_BRANCH_"))
			}
			if op["refunded_amount"] != nil {
				amount := obj(op["refunded_amount"])
				op["refunded_amount"] = object{"currency": amount["currency"], "amount_minor": amount["units"]}
			}
			if digest, ok := op["evidence_sha256"].(string); ok {
				hash, err := base64.StdEncoding.DecodeString(digest)
				if err != nil {
					t.Fatal(err)
				}
				op["evidence_sha256"] = b64.EncodeToString(hash)
			}
			quote := obj(obj(op["trade"])["quote"])
			for _, k := range []string{"fiat_amount", "escrow_usdt", "recipient_usdt", "platform_fee_usdt", "channel_fee_usdt", "merchant_fee_usdt", "spread_usdt"} {
				currency := "USDT"
				if k == "fiat_amount" {
					currency = "CNY"
				}
				quote[k] = object{"currency": currency, "amount_minor": quote[k]}
			}
			delete(quote, "fiat_currency")
			request, _ := hex.DecodeString(v.Bytes)
			digest, _ := hex.DecodeString(v.Digest)
			header := normalized(object{"id": m["approval_request_id"], "requested_by": m["requested_by"], "kind": m["kind"], "requested_at": m["requested_at"], "expires_at": m["expires_at"],
				"required_approvals": 2, "request_bytes": b64.EncodeToString(request), "request_digest": b64.EncodeToString(digest)})
			header["status"] = "executed"
			d := newDriver(t.TempDir(), "", "settle-refunds")
			d.active = &result{Evidence: object{}}
			// An already confirmed refund has both signatures. Reading it must issue no POST.
			records := []any{}
			for _, person := range approvers {
				records = append(records, object{"request_id": header["id"], "approver_id": d.key("person/" + person), "assertion": object{"credential_id": b64.EncodeToString(d.credential(person).ID)}})
			}
			d.approveExisting("existing", "payment", str(m, "requested_by"), "/seller-refund-reviews", object{"approval_request": header, "material": m, "approvals": records})
			if d.active.Evidence["request_digest"] != header["request_digest"] {
				t.Fatal("missing signed digest")
			}
		})
	}
}

func TestManualRefundEvidenceAndBalance(t *testing.T) {
	const refund = "01a2179d-e80d-748c-bbdf-1669ed512593"
	data := refundPNG(refund)
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil || img.Bounds().Dx() != 32 || img.Bounds().Dy() != 32 || !bytes.Equal(data, refundPNG(refund)) {
		t.Fatal("invalid or unstable demo PNG")
	}
	before := object{"available_usdt_micro": "10"}
	after := object{"available_usdt_micro": "17", "refund_reserved_usdt_micro": "0"}
	checkSettledBalance(before, after, 7)
	expectFailure(t, func() { checkSettledBalance(before, after, 8) })
	after["refund_reserved_usdt_micro"] = "1"
	expectFailure(t, func() { checkSettledBalance(before, after, 7) })
}

func TestLegacyRefundSellerEvidenceReplay(t *testing.T) {
	const refund = "01a2179d-e80d-748c-bbdf-1669ed512593"
	const order = "01a2179d-dbee-71c5-973b-46ef672e8658"
	const path = "/accounts/account/refunds/" + refund
	root := t.TempDir()
	d := newDriver(root, "", "settle-refunds")
	d.put("user/seller", "user")
	d.put("seller-account", "account")
	d.put("session-until/seller", time.Now().Add(time.Minute))
	d.put("totp/seller", "JBSWY3DPEHPK3PXP")
	b := d.browser("seller")
	b.cookies["__Host-kaivo_seller_session"] = "session"
	digest := b64.EncodeToString(bytes.Repeat([]byte{7}, 32))
	detail := object{"fiat_amount": object{"currency": "CNY", "amount_minor": "100"}}
	var first []byte
	var key string
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result object
		switch strings.TrimPrefix(r.URL.Path, b.prefix) {
		case "/auth/csrf":
			result = object{"token": "csrf"}
		case "/auth/reauth":
			var body object
			raw, _ := io.ReadAll(r.Body)
			decode(raw, &body)
			binding := obj(obj(body["target"])["binding"])
			if binding["body_sha256"] != digest || binding["permission"] != "payment.refund.process" || binding["http_path"] != b.prefix+"/accounts/:seller_account_id/refunds/:id/process" {
				t.Error("incorrect evidence grant binding")
			}
			result = object{"challenge_purpose": "reauthentication", "challenge_id": "challenge"}
		case "/auth/challenges/challenge":
			result = object{"method": "totp"}
		case "/auth/challenges/challenge/verify":
			raw, _ := io.ReadAll(r.Body)
			var body object
			decode(raw, &body)
			if body["method"] != "totp" {
				t.Error("missing seller TOTP")
			}
			result = object{"state": "authenticated", "session": object{"user_id": "user"}, "reauthentication": object{"reauthentication_id": "grant"}}
		case path + "/process":
			posts++
			data, _ := io.ReadAll(r.Body)
			if posts == 1 {
				first, key = data, r.Header.Get("Idempotency-Key")
				var body object
				decode(data, &body)
				if key == "" || body["money"] != "1.00" || body["upstream_refund_no"] != "demo:"+order || num(body, "expected_evidence_version") != 0 || !strings.HasSuffix(str(body, "refunded_at"), "+08:00") {
					t.Error("invalid evidence for old order")
				}
				w.Header().Set("X-Command-SHA256", digest)
				w.Write(encoded(object{"code": 428}))
				return
			}
			if !bytes.Equal(data, first) || r.Header.Get("Idempotency-Key") != key || posts == 2 && r.Header.Get("X-Reauthentication-ID") != "grant" {
				t.Error("changed evidence, idempotency key or grant")
			}
			result = object{"subject": object{"refund_id": refund}, "version": 1, "evidence_id": "evidence"}
		default:
			t.Error("unexpected request", r.URL.Path)
		}
		w.Write(encoded(object{"code": 200, "data": result}))
	}))
	defer srv.Close()
	for range 2 {
		// Restart with only the persisted state. The server's second success
		// simulates replay after losing the response to the authorized write.
		browser := d.browser("seller")
		browser.addr = strings.TrimPrefix(srv.URL, "http://")
		(tradeRun{d: d, order: order}).submitRefundEvidence(refundSubject(refund), detail)
		d = newDriver(root, "", "settle-refunds")
	}
	if posts != 3 {
		t.Fatalf("got %d process calls", posts)
	}
}

func TestPlatformRefundCommandVector(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name, SHA256 string
			Request      object
		}
	}
	decode(testvectors.PaymentWebCommandV1(), &fixture)
	for _, v := range fixture.Vectors {
		if v.Name != "create-platform-refund" {
			continue
		}
		r := v.Request
		version, err := strconv.ParseInt(str(r, "expected_control_version"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		c := platformRefundCommand(str(r, "order_id"), str(r, "escrow_reservation_id"), str(r, "idempotency_key"), str(r, "reason"), version)
		if hex.EncodeToString(c.digest[:]) != v.SHA256 || c.template != "/orders/:order_id/refunds" || c.permission != "payment.refund.initiate" ||
			c.path != "/orders/"+str(r, "order_id")+"/refunds" || c.body["expected_control_version"] != version {
			t.Fatal("platform initiation differs from the grant or command contract")
		}
		return
	}
	t.Fatal("missing create-platform-refund vector")
}

func TestManualEvidenceResubmissionAndLateSubject(t *testing.T) {
	for _, tc := range []struct {
		subject reviewSubject
		version int64
	}{
		{refundSubject("refund"), 2},
		{latePaymentSubject("late"), 1},
	} {
		t.Run(tc.subject.kind, func(t *testing.T) {
			d := newDriver(t.TempDir(), "", "manual-refund")
			d.put("seller-account", "account")
			d.put("session-until/seller", time.Now().Add(time.Minute))
			b := d.browser("seller")
			b.cookies["__Host-kaivo_seller_session"] = "session"
			trade := tradeRun{d: d, order: "order"}
			field := tc.subject.kind + "_id"
			path := b.prefix + "/accounts/account" + tc.subject.path()
			row := object{field: tc.subject.id, "order_id": "order", "status": "awaiting_seller",
				"fiat_amount": object{"amount_minor": "100", "currency": "CNY"}}
			if tc.version == 2 {
				row["evidence"] = object{"version": 1, "evidence_id": "first", "status": "rejected"}
			}
			accepted := object{"subject": object{field: tc.subject.id}, "version": tc.version, "evidence_id": "new"}
			var submissions int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var result object
				switch r.URL.Path {
				case path:
					result = row
				case b.prefix + "/auth/csrf":
					result = object{"token": "csrf"}
				case path + "/process":
					var body object
					data, _ := io.ReadAll(r.Body)
					decode(data, &body)
					if r.Method != "POST" || r.Header.Get("Idempotency-Key") == "" || num(body, "expected_evidence_version") != tc.version-1 || body["money"] != "1.00" {
						t.Error("wrong processing request")
					}
					files := body["files"].([]any)
					png := standard(str(obj(files[0]), "data"))
					if tc.version == 2 && bytes.Equal(png, refundPNG(tc.subject.id)) {
						t.Error("resubmitted rejected screenshot")
					}
					submissions++
					row["status"], row["evidence"] = "awaiting_review", accepted
					result = accepted
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
				}
				w.Write(encoded(object{"code": 200, "data": result}))
			}))
			defer srv.Close()
			b.addr = strings.TrimPrefix(srv.URL, "http://")
			for range 2 {
				e := trade.evidenceVersion(tc.subject, tc.version)
				if e["evidence_id"] != "new" {
					t.Fatal("lost evidence on resume")
				}
			}
			expectFailure(t, func() { trade.evidenceVersion(tc.subject, tc.version+1) })
			if submissions != 1 {
				t.Fatal("resumption repeated the upload")
			}
		})
	}
}

func TestManualScenarioStartsAfterLegacyCompletion(t *testing.T) {
	const scenario = "refund-before-release"
	root := t.TempDir()
	d := newDriver(root, "", scenario)
	d.put("finished/"+scenario, true)
	d.put("seller-account", "existing-seller")
	d.history.RefundFlow = ""
	d.history.Steps = []*result{{Name: "automatic refund", Status: "ok"}}
	d.report()
	d = newDriver(root, "", scenario)
	if d.scope == scenario || len(d.history.Steps) != 0 || d.required("seller-account") != "existing-seller" {
		t.Fatal("manual scenario reused automatic checkpoints or lost setup")
	}
	d.step("manual step", func() {})
	d = newDriver(root, "", scenario)
	d.step("manual step", func() { t.Fatal("manual step executed twice") })
}
