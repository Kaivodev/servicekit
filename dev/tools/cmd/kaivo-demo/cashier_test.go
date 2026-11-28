package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	syncatomic "sync/atomic"
	"testing"
	"time"
)

const testCashierOrigin = "https://buyer.example.test"

type cashierTestEnvironment struct {
	demoEnvironment
	addr endpoints
}

func (e cashierTestEnvironment) addresses() endpoints { return e.addr }

func cashierDriver(t *testing.T, handler http.HandlerFunc) *driver {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	d := newDriver(t.TempDir(), "", cashierSubmit)
	d.origins = readPortalOrigins(map[string]string{"AIPAY_CASHIER_ORIGIN": testCashierOrigin})
	addr := d.addresses()
	addr.public = strings.TrimPrefix(srv.URL, "http://")
	d.demoEnvironment = cashierTestEnvironment{d.demoEnvironment, addr}
	return d
}

func cashierFormMatches(r *http.Request, token string) bool {
	return r.Method == http.MethodPost && r.URL.RawQuery == "" && r.Header.Get("Authorization") == "" &&
		r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" && r.ParseForm() == nil &&
		r.PostForm.Encode() == (url.Values{"token": {token}}).Encode()
}

func TestCashierInstruction(t *testing.T) {
	token := b64.EncodeToString(random(32))
	link := testCashierOrigin + "/c#" + token
	for _, kind := range []string{"url", "qrcode"} {
		t.Run(kind, func(t *testing.T) {
			methods := make(chan string, 2)
			sim := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RequestURI() != "/cashier/order" || r.Header.Get("Authorization") != "" {
					t.Error("unexpected simulator request")
				}
				select {
				case methods <- r.Method:
				default:
					t.Error("unexpected extra simulator request")
				}
			}))
			defer sim.Close()
			upstream := sim.URL + "/cashier/order"
			var views, actions syncatomic.Int32
			firstView := make(chan time.Time, 1)
			d := cashierDriver(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "buyer.example.test" || !strings.Contains(r.UserAgent(), "X11") || r.URL.RawQuery != "" {
					t.Error("cashier request used the wrong host, user agent or query")
				}
				switch r.URL.Path {
				case cashierPath:
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+token {
						t.Error("invalid cashier authorization")
					}
					if views.Add(1) == 1 {
						firstView <- time.Now()
						fmt.Fprint(w, `{"code":200,"data":{"state":"preparing","poll_after_ms":20}}`)
						return
					}
					if views.Load() != 2 || time.Since(<-firstView) < 20*time.Millisecond {
						t.Error("cashier did not honor the polling interval")
					}
					instruction := object{"kind": kind, "display": []string{"open"}}
					if kind == "qrcode" {
						instruction["display"], instruction["qrcode"] = []string{"qr"}, upstream
					}
					w.Write(encoded(object{"code": 200, "data": object{"state": "ready", "instruction": instruction}}))
				case cashierPath + "/go":
					actions.Add(1)
					if !cashierFormMatches(r, token) || r.Header.Get("Origin") != "" {
						t.Error("invalid cashier navigation form")
					}
					http.Redirect(w, r, upstream, http.StatusSeeOther)
				default:
					t.Error("unexpected cashier path")
					http.NotFound(w, r)
				}
			})
			// Use the native simulator client and trust only this server's certificate.
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sim.Certificate().Raw})
			check(atomic(filepath.Join(d.root, "certs/ca.crt"), ca))
			addr := d.addresses()
			addr.cashier = sim.URL
			d.demoEnvironment = cashierTestEnvironment{d.demoEnvironment, addr}
			d.output = filepath.Join(t.TempDir(), "export.json")
			d.step("resolve and pay", func() {
				if d.cashier(link, true) != upstream {
					t.Fatal("wrong resolved cashier")
				}
			})
			wantActions := int32(0)
			if kind == "url" {
				wantActions = 1
			}
			if views.Load() != 2 || actions.Load() != wantActions {
				t.Fatal("unexpected polling or action count")
			}
			if len(methods) != 2 || <-methods != "GET" || <-methods != "POST" {
				t.Fatal("simulator was not visited and paid")
			}
			if d.active.Evidence["cashier_state"] != "ready" || d.active.Evidence["cashier_link"] != testCashierOrigin+"/c#<redacted>" {
				t.Fatal("missing redacted cashier evidence")
			}
			for _, path := range []string{d.output, filepath.Join(d.dir, "state.json"), filepath.Join(d.dir, "reports", cashierSubmit+".md")} {
				report := string(file(path))
				if strings.Contains(report, token) || strings.Contains(report, upstream) || !strings.Contains(report, "HTTP 200") || kind == "url" && !strings.Contains(report, "HTTP 303") {
					t.Fatal("unsafe or incomplete cashier report")
				}
			}
		})
	}
}

func TestCashierLinkValidation(t *testing.T) {
	d := cashierDriver(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected backend request") })
	sim := d.addresses().cashier + "/cashier/old_1"
	if d.resolveCashier(sim) != sim {
		t.Fatal("simulator link changed")
	}
	token := b64.EncodeToString(random(32))
	for _, page := range []string{"https://wrong.example.test/c", testCashierOrigin + "/c?", testCashierOrigin + "/c?a=b", testCashierOrigin + "/%63", testCashierOrigin + "/c/", "https://user@buyer.example.test/c"} {
		expectFailure(t, func() { d.resolveCashier(page + "#" + token) })
	}
	for _, bad := range []string{"", token[:42], token + "=", token[:42] + "+", "%41" + token[1:]} {
		expectFailure(t, func() { d.resolveCashier(testCashierOrigin + "/c#" + bad) })
	}
}

func TestCashierRefusesInvalidInstructions(t *testing.T) {
	link := testCashierOrigin + "/c#" + b64.EncodeToString(random(32))
	for _, tc := range []struct {
		name, view string
		goStatus   int
		location   string
	}{
		{"untrusted redirect", `{"state":"ready","instruction":{"kind":"url"}}`, 303, "https://other.example.test/cashier/id"},
		{"wrong redirect status", `{"state":"ready","instruction":{"kind":"url"}}`, 302, "https://127.0.0.1:9443/cashier/id"},
		{"redirect back", `{"state":"ready","instruction":{"kind":"url"}}`, 303, link},
		{"missing QR", `{"state":"ready","instruction":{"kind":"qrcode"}}`, 0, ""},
		{"external QR", `{"state":"ready","instruction":{"kind":"qrcode","qrcode":"https://other.example.test/cashier/id"}}`, 0, ""},
		{"premature return", `{"state":"ready","return_ready":true,"instruction":{"kind":"url"}}`, 0, ""},
		{"expired", `{"state":"expired"}`, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := cashierDriver(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == cashierPath {
					fmt.Fprintf(w, `{"code":200,"data":%s}`, tc.view)
					return
				}
				if tc.goStatus == 0 || r.URL.Path != cashierPath+"/go" {
					t.Error("unexpected cashier action")
					return
				}
				http.Redirect(w, r, tc.location, tc.goStatus)
			})
			if msg := failureText(func() { d.resolveCashier(link) }); msg == "" || strings.Contains(msg, link) {
				t.Fatal("unsafe cashier instruction accepted or exposed")
			}
		})
	}
}

func TestCashierDeadline(t *testing.T) {
	d := cashierDriver(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":200,"data":{"state":"preparing","poll_after_ms":60000}}`)
	})
	var cancel context.CancelFunc
	d.ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if msg := failureText(func() { d.resolveCashier(testCashierOrigin + "/c#" + b64.EncodeToString(random(32))) }); !strings.Contains(msg, "deadline exceeded") || time.Since(start) > time.Second {
		t.Fatalf("cashier did not stop at the polling deadline: %q", msg)
	}
}

func TestRepeatedCashierLinks(t *testing.T) {
	tokens := []string{b64.EncodeToString(random(32)), b64.EncodeToString(random(32)), b64.EncodeToString(random(32))}
	const sim = "https://127.0.0.1:9443/cashier/"
	d := cashierDriver(t, func(w http.ResponseWriter, r *http.Request) {
		index := slices.Index(tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if index < 0 {
			t.Error("unexpected cashier token")
			return
		}
		id := "first"
		if index == 2 {
			id = "second"
		}
		fmt.Fprintf(w, `{"code":200,"data":{"state":"ready","instruction":{"kind":"qrcode","qrcode":%q}}}`, sim+id)
	})
	link := func(i int) string { return testCashierOrigin + "/c#" + tokens[i] }
	d.requireSameCashier(link(0), link(1))
	d.requireSameCashier(sim+"first", link(0))
	d.requireSameCashier(sim+"first", sim+"first")
	expectFailure(t, func() { d.requireSameCashier(link(0), link(2)) })
	expectFailure(t, func() { d.requireSameCashier(sim+"first", sim+"second") })
}

func TestCashierStopsWhenServerStopsPolling(t *testing.T) {
	requests := 0
	d := cashierDriver(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `{"code":200,"data":{"state":"paid","poll_after_ms":0,"return_ready":false}}`)
	})
	token := b64.EncodeToString(random(32))
	if msg := failureText(func() { d.awaitCashier(t.Context(), token, true) }); !strings.Contains(msg, "stopped polling") || requests != 1 {
		t.Fatalf("driver kept polling after poll_after_ms 0: %q after %d requests", msg, requests)
	}
}
