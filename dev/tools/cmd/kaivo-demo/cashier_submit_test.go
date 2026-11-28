package main

import (
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	syncatomic "sync/atomic"
	"testing"
	"time"
)

func TestCashierSubmitRouting(t *testing.T) {
	amount, channel := scenarioOrder(cashierSubmit, true)
	if scenarios[cashierSubmit] == nil || amount != "2.00" || channel != epayChannel {
		t.Fatal("cashier-submit must use the EPay gateway scenario")
	}
}

func TestCashierSubmitAndReturn(t *testing.T) {
	const merchantKey = "fixture-key"
	platform, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)
	pub, err := x509.MarshalPKIXPublicKey(&platform.PublicKey)
	check(err)

	for _, proto := range []string{"v1", "v2"} {
		t.Run(proto, func(t *testing.T) {
			token := b64.EncodeToString(random(32))
			link := testCashierOrigin + "/c#" + token
			const signedText = "money=2.00&out_trade_no=merchant-order&pid=1001&trade_no=platform-order&trade_status=TRADE_SUCCESS"
			fields, err := url.ParseQuery(signedText)
			check(err)
			if proto == "v1" {
				fields.Set("sign_type", "MD5")
				h := md5.Sum([]byte(signedText + merchantKey))
				fields.Set("sign", hex.EncodeToString(h[:]))
			} else {
				fields.Set("sign_type", "RSA")
				h := sha256.Sum256([]byte(signedText))
				sig, err := rsa.SignPKCS1v15(rand.Reader, platform, crypto.SHA256, h[:])
				check(err)
				fields.Set("sign", base64.StdEncoding.EncodeToString(sig))
			}
			location := merchantReturnURL + "?" + fields.Encode()
			var merchantPublic *rsa.PublicKey
			var statusViews syncatomic.Int32
			d := cashierDriver(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/submit.php", "/api/pay/submit":
					if proto == "v1" && (r.URL.Path != "/submit.php" || r.Method != http.MethodGet) ||
						proto == "v2" && (r.URL.Path != "/api/pay/submit" || r.Method != http.MethodPost || r.URL.RawQuery != "") {
						t.Error("wrong submit entry or method")
					}
					if r.ParseForm() != nil || r.Form.Has("clientip") || r.Form.Has("method") || r.Form.Get("return_url") != merchantReturnURL ||
						r.Form.Get("pid") != "1001" || r.Form.Get("money") != "2.00" || r.Form.Get("out_trade_no") != "merchant-order" {
						t.Error("unexpected submit parameters")
					}
					if proto == "v1" {
						if r.Form.Get("sign_type") != "MD5" || r.Form.Get("sign") != v1Sign(r.Form, merchantKey) {
							t.Error("invalid V1 submit signature")
						}
					} else {
						plain, ok := canonical(r.Form)
						h := sha256.Sum256([]byte(plain))
						sig, err := base64.StdEncoding.DecodeString(r.Form.Get("sign"))
						if !ok || err != nil || r.Form.Get("sign_type") != "RSA" || r.Form.Get("timestamp") == "" || rsa.VerifyPKCS1v15(merchantPublic, crypto.SHA256, h[:], sig) != nil {
							t.Error("invalid V2 submit signature")
						}
					}
					http.Redirect(w, r, link, http.StatusSeeOther)
				case cashierPath:
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer invalid" {
						t.Error("expected invalid token check")
					}
					fmt.Fprint(w, `{"code":400,"msg":"invalid token"}`)
				case cashierPath + "/go":
					if !cashierFormMatches(r, token) || r.Header.Get("Origin") != "https://admin.aipay.test" {
						t.Error("expected cross-origin cashier form")
					}
					http.Redirect(w, r, testCashierOrigin+"/c", http.StatusSeeOther)
				case cashierPath + "/status":
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+token {
						t.Error("invalid status request")
					}
					if statusViews.Add(1) == 1 {
						fmt.Fprint(w, `{"code":200,"data":{"state":"paid","return_ready":false,"poll_after_ms":1}}`)
						return
					}
					fmt.Fprint(w, `{"code":200,"data":{"state":"paid","return_ready":true}}`)
				case cashierPath + "/return":
					if !cashierFormMatches(r, token) {
						t.Error("invalid return request")
					}
					http.Redirect(w, r, location, http.StatusSeeOther)
				default:
					t.Error("unexpected request")
					http.NotFound(w, r)
				}
			})
			d.put("pid/"+proto, "1001")
			check(atomic(filepath.Join(d.dir, "merchant-key.json"), encoded(object{"Key": merchantKey})))
			check(atomic(filepath.Join(d.root, "handoff/platform-public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})))
			if proto == "v2" {
				merchantPublic = &d.merchantRSA().PublicKey
			}
			trade := tradeRun{d: d, proto: proto, number: "merchant-order", amount: "2.00"}
			if got := d.submitEPay(proto, d.createParams(trade.number, trade.amount)); got != link {
				t.Fatal("missing submitted cashier link")
			}
			d.checkCashierRefusals(token)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			d.awaitCashier(ctx, token, true)
			if statusViews.Load() != 2 {
				t.Fatal("return requested before it was ready")
			}
			trade.verifyCashierReturn(d.cashierAction(ctx, cashierPath+"/return", token, ""), "platform-order")
			for _, bad := range []string{
				strings.Replace(location, "money=2.00", "money=2.01", 1),
				location + "&trade_no=platform-order", location + "#fragment",
				strings.Replace(location, merchantReturnURL, "https://another.example.test/return", 1),
			} {
				expectFailure(t, func() { trade.verifyCashierReturn(bad, "platform-order") })
			}
			expectFailure(t, func() { trade.verifyCashierReturn(location, "another-order") })
		})
	}
}

func TestCashierEvidenceOnLiveResume(t *testing.T) {
	token := b64.EncodeToString(random(32))
	link := testCashierOrigin + "/c#" + token
	want := testCashierOrigin + "/c#<redacted>"
	d := newDriver(t.TempDir(), "", livePhase)
	d.liveEPay = true
	d.step("测试上游 商户下单", func() {
		for _, key := range []string{"payurl", "pay_info", "qrcode"} {
			d.evidence(key, link)
		}
	})
	d.output = filepath.Join(t.TempDir(), "report.json")
	for range 2 {
		d.trimSavedLiveLinks()
	}
	d.report()
	for _, name := range []string{d.output, filepath.Join(d.dir, "state.json")} {
		if strings.Contains(string(file(name)), token) {
			t.Fatal("live report or checkpoint leaked the cashier token")
		}
	}
	for _, key := range []string{"payurl", "pay_info", "qrcode"} {
		if d.active.Evidence[key] != want {
			t.Fatal("missing live cashier redaction")
		}
	}
	if safe := paymentLinkEvidence("https://upstream.example.test/pay?secret=private/c#" + token); safe != "https://upstream.example.test/pay" {
		t.Fatal("cashier-shaped query bypassed live payment link redaction")
	}
}
