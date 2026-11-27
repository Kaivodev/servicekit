package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"github.com/Kaivodev/protobuf/testvectors"
	"google.golang.org/protobuf/proto"
)

func TestA145ScenarioRouting(t *testing.T) {
	for _, name := range []string{a145NeverSent, a145StaleBinding, a145UnpaidBeforeT, a145LatePayment, a145Refusals} {
		amount, channel := scenarioOrder(name, true)
		if !isA145Scenario(name) || scenarios[name] == nil || amount != "2.00" || channel != epayChannel {
			t.Errorf("incorrect native EPay route for %s", name)
		}
	}
	if isA145Scenario(a144NotFound) || packageKey(epayChannel, "") != epayChannel || packageKey(epayChannel, oldGatewayTag) != "v0.5.0/epay_v1" {
		t.Fatal("A145 scenarios or packages overlap existing state")
	}
}

func TestA145CancellationEvent(t *testing.T) {
	for _, basis := range []pay.OrderCancellationBasis{unboundClose, boundClose} {
		e := &pay.OrderCancellationVerificationRequested{OrderId: "order", EscrowReservationId: "hold", ControlVersion: 7, Basis: basis}
		b, err := proto.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		wire := hex.EncodeToString(b)
		checkCloseEvent(wire, "order", "hold", 7, basis)
		expectFailure(t, func() { checkCloseEvent(wire, "other", "hold", 7, basis) })
		expectFailure(t, func() { checkCloseEvent(wire, "order", "different", 7, basis) })
		expectFailure(t, func() { checkCloseEvent(wire, "order", "hold", 8, basis) })
		expectFailure(t, func() { checkCloseEvent(wire, "order", "hold", 7, 0) })
	}
}

func TestA145RecoverApprovalID(t *testing.T) {
	for _, state := range []string{"none", "pending_approval", "verifying", "cancelled", "paid", "fenced"} {
		view := object{"state": state}
		want := ""
		if state != "none" {
			expectFailure(t, func() { approvalInView(view) })
			want = "existing"
			if state == "pending_approval" {
				view["pending_approval_request_id"] = want
			} else {
				view["approved_approval_request_id"] = want
			}
		}
		if approvalInView(view) != want {
			t.Errorf("lost approval ID in %s", state)
		}
	}
	expectFailure(t, func() { approvalInView(object{"state": "unknown"}) })
}

func TestA145RefusalMatchesOnlyTheExpectedWrite(t *testing.T) {
	path := assertionPath("request")
	for _, tc := range []struct {
		method, path string
		status, code int
		match        bool
	}{
		{"POST", path, 200, 409, true}, {"POST", path, 409, 409, true},
		{"GET", path, 409, 409, false}, {"POST", "/auth/login", 200, 409, false},
		{"POST", path, 500, 409, false}, {"POST", path, 200, 403, false},
	} {
		call := func() {
			if !refusedWrite(path, 409, func() { panic(failure{method: tc.method, path: tc.path, httpStatus: tc.status, businessCode: tc.code}) }) {
				t.Error("missed refusal")
			}
		}
		if tc.match {
			call()
		} else {
			expectFailure(t, call)
		}
	}
	if refusedWrite(path, 409, func() {}) {
		t.Error("counted success as a refusal")
	}
}

// Compare the portal projection against the two independent payment vectors.
func TestA145ApprovalVectorsAndResume(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name     string
			Material object
			Bytes    string `json:"request_bytes"`
			Digest   string `json:"request_digest"`
		} `json:"approval_vectors"`
	}
	decode(testvectors.PaymentForcedCloseV1(), &fixture)
	if len(fixture.Vectors) != 2 {
		t.Fatal("expected both binding classes")
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			m := v.Material
			op := obj(m["forced_close"])
			op["status"] = strings.ToLower(strings.TrimPrefix(str(op, "status"), "ORDER_STATUS_"))
			quote := obj(obj(op["trade"])["quote"])
			for _, field := range []string{"fiat_amount", "escrow_usdt", "recipient_usdt", "platform_fee_usdt", "channel_fee_usdt", "merchant_fee_usdt", "spread_usdt"} {
				currency := "USDT"
				if field == "fiat_amount" {
					currency = str(quote, "fiat_currency")
				}
				quote[field] = object{"currency": currency, "amount_minor": quote[field]}
			}
			delete(quote, "fiat_currency")
			aid, requester := str(m, "approval_request_id"), str(m, "requested_by")
			request, err := hex.DecodeString(v.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := hex.DecodeString(v.Digest)
			if err != nil {
				t.Fatal(err)
			}
			header := normalized(object{"id": aid, "kind": "forced_close", "status": "pending", "required_approvals": 2, "requested_by": requester, "requested_at": m["requested_at"], "expires_at": m["expires_at"], "request_bytes": b64.EncodeToString(request), "request_digest": b64.EncodeToString(digest)})
			approval := object{"approval_request": header, "material": m}
			if !bytes.Equal(challenge("payment", requester, approval), digest) {
				t.Fatal("forced-close digest differs from the published vector")
			}

			d := newDriver(t.TempDir(), "", a145NeverSent)
			d.active = &result{Evidence: object{}}
			d.put("user/risk", requester)
			trade := tradeRun{d: d, order: str(obj(op["trade"]), "order_id")}
			// Simulate a lost first signature response. The view points back to
			// the same request; only the missing second signature may be posted.
			first := approvers[0]
			approval["approvals"] = []any{object{"request_id": aid, "approver_id": d.key("person/" + first), "assertion": object{"credential_id": b64.EncodeToString(d.credential(first).ID)}}}
			secondPerson := d.key("person/" + approvers[1])
			secondCredential := b64.EncodeToString(d.credential(approvers[1]).ID)
			var posts []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/api/v1/platform")
				var data object
				switch {
				case r.Method == "GET" && path == "/approvals/payment/"+aid:
					data = approval
				case r.Method == "GET" && path == "/auth/csrf":
					data = object{"token": "csrf"}
				case r.Method == "POST" && path == assertionPath(aid):
					cookie, err := r.Cookie("__Host-kaivo_platform_session")
					if err != nil || cookie.Value != approvers[1] || r.Header.Get("Idempotency-Key") == "" || r.Header.Get("X-CSRF-Token") != "csrf" {
						t.Error("unexpected signer or signature headers")
						return
					}
					var body struct{ Assertion object }
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Assertion["credential_id"] != secondCredential {
						t.Error("missing second approver assertion")
						return
					}
					var client struct{ Challenge string }
					decode(raw(str(body.Assertion, "client_data_json")), &client)
					if client.Challenge != b64.EncodeToString(digest) {
						t.Error("assertion uses the wrong request digest")
					}
					posts = append(posts, cookie.Value)
					approval["approvals"] = append(approvalRecords(approval), object{"request_id": aid, "approver_id": secondPerson, "assertion": body.Assertion})
					header["status"] = "approved"
					data = approval
				default:
					t.Errorf("unexpected write or read on recovery: %s %s", r.Method, path)
					return
				}
				w.Write(encoded(object{"code": 200, "data": data}))
			}))
			defer server.Close()
			for _, person := range approvers {
				b := d.browser(person)
				b.addr = strings.TrimPrefix(server.URL, "http://")
				b.cookies["__Host-kaivo_platform_session"] = person
				d.put("session-until/"+person, time.Now().Add(time.Minute))
			}
			for _, state := range []string{"pending_approval", "verifying"} {
				view := normalized(object{"state": state, "control_version": 7, "pending_approval_request_id": aid, "approved_approval_request_id": aid})
				current := trade.submitClose(view, str(op, "reason"), 0)
				d.approveExisting("forced-close/"+aid, "payment", requester, "/forced-closes", current)
			}
			if !slices.Equal(posts, approvers[1:]) || d.active.Evidence["approval_status"] != "approved" {
				t.Fatal("recovery did not preserve the two approved signatures")
			}
		})
	}
}
