package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"github.com/Kaivodev/protobuf/testvectors"
)

func TestRecoveryScenarioRegistrationAndRestart(t *testing.T) {
	for _, name := range []string{"risk-extension-platform", "risk-extension-seller-rejected", "risk-extension-superseded", "mismatch-reverify", "mismatch-refund", "mismatch-refund-failed"} {
		if scenarios[name] == nil {
			t.Fatalf("missing scenario %s", name)
		}
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "env"), 0700); err != nil {
		t.Fatal(err)
	}
	for service, setting := range map[string]string{"payment": "AIPAY_UPSTREAM_GATEWAY_ADDRESS=trade", "reconciliation": "AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS=query"} {
		if err := os.WriteFile(filepath.Join(root, "env", service+".env"), []byte(setting), 0600); err != nil {
			t.Fatal(err)
		}
	}
	d := newDriver(root, "", mismatchReverify)
	var orders []string
	run := recoveryScenario(func(d *driver) { orders = append(orders, d.key(d.scope+"/EPay")) })
	run(d)
	run(d)
	delete(d.data, "step/"+mismatchReverify+"/Identify the recovery run")
	run(d)
	if d.scope != mismatchReverify || orders[0] != orders[1] || orders[1] == orders[2] {
		t.Fatal("restart reused a prior run or resume lost its order")
	}
}

func TestSellerExtensionReauthenticationDigest(t *testing.T) {
	c := sellerExtensionCommand("seller", "order", "escrow", "command", 3)
	if c.path != "/accounts/seller/orders/order/risk-extension-requests" || c.template != "/accounts/:seller_account_id/orders/:order_id/risk-extension-requests" ||
		c.permission != "payment.risk_extension.request" || c.body["reason_code"] != "seller_funds_frozen" || c.body["extension_seconds"] != int64(600) {
		t.Fatal("seller command binding differs from the route")
	}
	// Use the published input descriptor to independently serialize the fields
	// included in the backend's command digest.
	request := normalized(c.body)
	request["order_id"] = "order"
	request["idempotency_key"] = "command"
	m := (&pay.SubmitSellerRiskExtensionRequest{}).ProtoReflect().Descriptor()
	b := materialBytes(appendField(appendField(nil, "aipay.web.command.v1"), pay.SellerPortalService_SubmitSellerRiskExtension_FullMethodName), m, request)
	if c.digest != sha256.Sum256(b) {
		t.Fatal("seller grant does not bind the posted command")
	}
}

func TestRecoveryApprovalVectors(t *testing.T) {
	for _, data := range [][]byte{testvectors.PaymentRiskExtensionV1(), testvectors.PaymentAmountMismatchV1()} {
		var doc struct {
			Vectors []struct {
				Name     string
				Material object
				Bytes    string `json:"request_bytes"`
				Digest   string `json:"request_digest"`
			} `json:"approval_vectors"`
		}
		decode(data, &doc)
		if len(doc.Vectors) != 2 {
			t.Fatal("expected two published vectors")
		}
		for _, v := range doc.Vectors {
			t.Run(v.Name, func(t *testing.T) {
				m := v.Material
				kind, requester := str(m, "kind"), str(m, "requested_by")
				op := obj(m[kind])
				for k, prefix := range map[string]string{"origin": "RISK_EXTENSION_ORIGIN_", "reason_code": "RISK_EXTENSION_REASON_", "source": "AMOUNT_MISMATCH_SOURCE_", "kind": "AMOUNT_MISMATCH_KIND_", "outcome": "AMOUNT_MISMATCH_OUTCOME_"} {
					if enum, ok := op[k].(string); ok {
						op[k] = strings.ToLower(strings.TrimPrefix(enum, prefix))
					}
				}
				trade := obj(op["trade"])
				q := obj(trade["quote"])
				for _, k := range []string{"fiat_amount", "escrow_usdt", "recipient_usdt", "platform_fee_usdt", "channel_fee_usdt", "merchant_fee_usdt", "spread_usdt"} {
					currency := "USDT"
					if k == "fiat_amount" {
						currency = str(q, "fiat_currency")
					}
					q[k] = object{"currency": currency, "amount_minor": q[k]}
				}
				delete(q, "fiat_currency")
				wire, err := hex.DecodeString(v.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				digest, err := hex.DecodeString(v.Digest)
				if err != nil {
					t.Fatal(err)
				}
				id := str(m, "approval_request_id")
				h := normalized(object{"id": id, "kind": kind, "requested_by": requester, "requested_at": m["requested_at"], "expires_at": m["expires_at"], "status": "pending", "required_approvals": 2,
					"request_bytes": b64.EncodeToString(wire), "request_digest": b64.EncodeToString(digest)})
				a := object{"approval_request": h, "material": m}
				reply := object{"approval": a}
				if !bytes.Equal(challenge("payment", requester, requireRecoveryApproval(reply, kind, str(trade, "order_id"), requester)), digest) {
					t.Fatal("challenge differs from the owner vector")
				}
				expectFailure(t, func() { requireRecoveryApproval(reply, kind, "different-order", requester) })
				if v.Name == "refund_observed" {
					d := newDriver(t.TempDir(), "", mismatchRefund)
					d.active = &result{Evidence: object{}}
					// The owner already has one signature. Only the second signer
					// should post, and its response nests the approval in a decision.
					first, second := approvers[0], approvers[1]
					record := func(person string) object {
						return object{"request_id": id, "approver_id": d.key("person/" + person), "assertion": object{"credential_id": b64.EncodeToString(d.credential(person).ID)}}
					}
					a["approvals"] = []any{record(first)}
					posts := 0
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method == "GET" && r.URL.Path == "/api/v1/platform/auth/csrf" {
							w.Write(encoded(object{"code": 200, "data": object{"token": "csrf"}}))
							return
						}
						if r.URL.Path != "/api/v1/platform/amount-mismatch-recoveries/approvals/"+id+"/assertions" || r.Method != "POST" {
							t.Errorf("unexpected approval request %s", r.URL.Path)
							return
						}
						posts++
						body := obj(normalized(a)["approval_request"])
						body["status"] = "approved"
						w.Write(encoded(object{"code": 200, "data": object{"approval": object{"material": m, "approval_request": body, "approvals": []object{record(first), record(second)}}}}))
					}))
					defer srv.Close()
					b := d.browser(second)
					b.addr = strings.TrimPrefix(srv.URL, "http://")
					b.cookies["__Host-kaivo_platform_session"] = second
					d.put("session-until/"+second, time.Now().Add(time.Minute))
					d.approveExisting("recover", "payment", requester, "/amount-mismatch-recoveries", a)
					d.approveExisting("recover", "payment", requester, "/amount-mismatch-recoveries", a)
					if posts != 1 {
						t.Fatalf("sent %d new signatures on replay", posts)
					}
				}
				op["reason"] = "different reason"
				expectFailure(t, func() { challenge("payment", requester, a) })
			})
		}
	}
}

func TestMismatchNoticeFollowsLedgerOccupation(t *testing.T) {
	m := &pay.SellerRefundNotice{OrderId: "order", SellerAccountId: "seller", Subject: &pay.SellerRefundSubject{Subject: &pay.SellerRefundSubject_RefundId{RefundId: "refund"}},
		FiatAmount: observedMinor, FiatCurrency: "CNY", Kind: pay.SellerRefundNoticeKind_SELLER_REFUND_NOTICE_KIND_PENDING, Origin: pay.RefundOrigin_REFUND_ORIGIN_AMOUNT_MISMATCH}
	at := time.Unix(100, 0)
	verify := func(recorded time.Time) { checkMismatchNotice(m, "order", "refund", "seller", recorded, at) }
	verify(at.Add(time.Microsecond))
	expectFailure(t, func() { verify(at.Add(-time.Microsecond)) })
	expectFailure(t, func() { verify(at) })
	m.FiatAmount = p34OrderMinor
	expectFailure(t, func() { verify(at.Add(time.Microsecond)) })
}
