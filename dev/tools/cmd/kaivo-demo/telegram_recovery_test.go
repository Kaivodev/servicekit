package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const (
	testBusiness   = "00000000-0000-7000-8000-000000000011"
	testApp        = "00000000-0000-7000-8000-000000000022"
	testAccount    = "00000000-0000-7000-8000-000000000033"
	testCreate     = "/app_create " + testBusiness + " v1 127.0.0.1/32 Demo Store"
	testLookup     = "/apps " + testBusiness
	testStateKey   = "telegram/setup/test-label"
	testTOTPSecret = "JBSWY3DPEHPK3PXP"
)

func appReply(name string, version int, enabled, v1 bool) string {
	return fmt.Sprintf("%s \u00b7 %s \u00b7 PID 1234 \u00b7 \u4e1a\u52a1 %s \u00b7 \u542f\u7528 %t \u00b7 \u7248\u672c %d \u00b7 V1 %t \u00b7 V2 %t", testApp, name, testBusiness, enabled, version, v1, !v1)
}

type webhookResult struct {
	beforeWrite bool
	err         error
	status      int
	replies     []string
}

type webhookUpdate struct {
	ID      int64 `json:"update_id"`
	Message struct {
		Text string
		Chat struct{ ID int64 }
		Date int64
	}
}

type replayBot struct {
	t       *testing.T
	root    string
	d       *driver
	results []webhookResult
	updates []webhookUpdate
}

func newReplayBot(t *testing.T) *replayBot {
	f := &replayBot{t: t, root: t.TempDir()}
	f.resume()
	check(atomic(filepath.Join(f.root, "env/backend.env"), nil))
	f.d.put("totp/merchant", testTOTPSecret)
	client := localHTTP
	t.Cleanup(func() { localHTTP = client })
	localHTTP = &http.Client{Transport: startWebhook(f.roundTrip)}
	return f
}

func (f *replayBot) resume() { f.d = newDriver(f.root, "", "setup") }

func (f *replayBot) roundTrip(req *http.Request) (*http.Response, error) {
	f.t.Helper()
	defer req.Body.Close()
	var update webhookUpdate
	if err := json.NewDecoder(req.Body).Decode(&update); err != nil {
		f.t.Fatal(err)
	}
	f.updates = append(f.updates, update)
	if len(f.results) == 0 {
		f.t.Fatal("unexpected webhook request")
	}
	r := f.results[0]
	f.results = f.results[1:]
	if len(f.updates) == 1 {
		// Inspect the durable state from a second driver before the first write.
		var saved delivery
		resumed := newDriver(f.root, "", "setup")
		if !resumed.read(testStateKey, &saved) || saved.Sent || saved.ID != update.ID || saved.Command != update.Message.Text {
			f.t.Fatal("missing pending delivery before transport write")
		}
	}
	if !r.beforeWrite {
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
	}
	if len(r.replies) > 0 {
		replies := f.d.messages()
		for _, text := range r.replies {
			replies = append(replies, message{ID: int64(len(replies) + 1), Chat: update.Message.Chat.ID, Text: text})
		}
		check(atomic(filepath.Join(f.d.dir, "messages.json"), encoded(replies)))
	}
	if r.err != nil {
		return nil, r.err
	}
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Body: http.NoBody}, nil
}

func (f *replayBot) send(cmd string) message {
	return f.d.telegram("test-label", merchantUser, func() string { return cmd + " " + f.d.freshTOTP("merchant") })
}

func (f *replayBot) budget(want int) {
	f.t.Helper()
	var w mfaWindow
	if !f.d.read("totp-window/merchant", &w) || w.Count != want {
		f.t.Fatalf("MFA charges = %d, want %d", w.Count, want)
	}
}

func (f *replayBot) lost(cmd string, result webhookResult) delivery {
	f.t.Helper()
	f.results = []webhookResult{result}
	if reason := failureText(func() { f.send(cmd) }); reason == "" {
		f.t.Fatal("expected delivery failure")
	}
	f.resume()
	var pending delivery
	if !f.d.read(testStateKey, &pending) || !pending.Sent || pending.TOTPStep != totpStep(time.Now()) {
		f.t.Fatal("written delivery and TOTP step were not checkpointed")
	}
	if pending.Command != cmd+" "+totp(testTOTPSecret, time.Unix(30*pending.TOTPStep, 0)) {
		f.t.Fatal("stored TOTP step does not match the command")
	}
	f.budget(1)
	return pending
}

func TestTelegramUnsentRebuild(t *testing.T) {
	for _, construction := range []bool{false, true} {
		t.Run(fmt.Sprintf("construction=%t", construction), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newReplayBot(t)
				env := filepath.Join(f.root, "env/backend.env")
				if construction {
					check(atomic(env, []byte("AIPAY_TELEGRAM_WEBHOOK_PATH=/%zz\n")))
				} else {
					f.results = []webhookResult{{beforeWrite: true, err: errors.New("connection refused")}}
				}
				if failureText(func() { f.send(testCreate) }) == "" {
					t.Fatal("expected pre-write failure")
				}
				f.resume()
				if f.d.data[testStateKey] != nil {
					t.Fatal("unsent delivery persisted")
				}
				var oldID, oldStep int64
				if !f.d.read("update_id", &oldID) || !f.d.read("totp-step/merchant", &oldStep) {
					t.Fatal("missing original serial or step")
				}
				check(atomic(env, nil))
				f.results = []webhookResult{{replies: []string{"ok"}}}
				f.send(testCreate)
				var next delivery
				if !f.d.read(testStateKey, &next) || next.ID <= oldID || next.TOTPStep <= oldStep || next.Command == testCreate+" "+totp(testTOTPSecret, time.Unix(30*oldStep, 0)) {
					t.Fatal("retry reused its update ID or TOTP")
				}
				f.budget(2)
			})
		})
	}
}

func TestTelegramReplayWithinSkew(t *testing.T) {
	for _, tc := range []struct {
		name string
		loss webhookResult
	}{
		{"EOF", webhookResult{err: io.EOF}},
		{"timeout", webhookResult{err: context.DeadlineExceeded}},
		{"HTTP error", webhookResult{status: 503}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newReplayBot(t)
				pending := f.lost(testCreate, tc.loss)
				time.Sleep(30 * time.Second)
				// A subsequent dial failure must retain the earlier uncertain write.
				f.results = []webhookResult{{beforeWrite: true, err: io.ErrClosedPipe}, {replies: []string{"ok"}}}
				expectFailure(t, func() { f.send(testCreate) })
				f.resume()
				f.send(testCreate)
				if len(f.updates) != 3 || f.updates[0] != f.updates[1] || f.updates[1] != f.updates[2] || f.updates[2].ID != pending.ID {
					t.Fatal("replay changed the update")
				}
				f.budget(1)
			})
		})
	}
}

func TestTelegramExpiredRecovery(t *testing.T) {
	row := appReply("Demo Store", 2, true, true)
	business := testBusiness + " \u00b7 Demo \u00b7 \u5f52\u5c5e\u7248\u672c 1"
	v1Key := strings.Repeat("K", 32)
	for _, tc := range []struct {
		name, cmd, lookup, original, want, reason string
		pages                                     []string
		regenerate                                bool
	}{
		{name: "adopt application", cmd: testCreate, lookup: testLookup, pages: []string{appReply("Demo Storefront", 1, true, true) + "\n" + nextPagePrefix + "next", row}, want: row},
		{name: "adopt from a split page", cmd: testCreate, lookup: testLookup, pages: []string{strings.Repeat(appReply("Another store", 1, true, true)+"\n", 16) + row}, want: row},
		{name: "absent application", cmd: testCreate, lookup: testLookup, pages: []string{noBotRecords}, regenerate: true},
		{name: "ambiguous application", cmd: testCreate, lookup: testLookup, pages: []string{row + "\n" + row}, reason: "multiple matching rows"},
		{name: "unexpected business", cmd: testCreate, lookup: testLookup, pages: []string{strings.Replace(row, testBusiness, testAccount, 1)}, reason: "unexpected business"},
		{name: "malformed list", cmd: testCreate, lookup: testLookup, pages: []string{"unrecognized"}, reason: "invalid application row"},
		{name: "adopt business", cmd: "/business_create " + testAccount + " Demo", lookup: "/businesses", pages: []string{accountPrefix + testAccount + "\n" + business}, want: business},
		{name: "absent business", cmd: "/business_create " + testAccount + " Demo", lookup: "/businesses", pages: []string{accountPrefix + testAccount}, regenerate: true},
		{name: "adopt enabled", cmd: "/app_enabled " + testApp + " 1 on", lookup: "/app " + testApp, pages: []string{row}, want: row},
		{name: "unchanged enabled", cmd: "/app_enabled " + testApp + " 1 on", lookup: "/app " + testApp, pages: []string{appReply("Demo Store", 1, false, true)}, regenerate: true},
		{name: "adopt V1 key", cmd: "/key_generate " + testApp + " 1", lookup: "/app " + testApp, pages: []string{row}, original: v1Key, want: v1Key},
		{name: "lost V1 key", cmd: "/key_generate " + testApp + " 1", lookup: "/app " + testApp, pages: []string{row}, reason: "original key reply unavailable"},
		{name: "unchanged key", cmd: "/key_generate " + testApp + " 2", lookup: "/app " + testApp, pages: []string{row}, regenerate: true},
		{name: "adopt V2 upload", cmd: "/key_upload " + testApp + " 1 public-key", lookup: "/app " + testApp, pages: []string{appReply("Demo", 2, true, false)}, original: v2UploadReply, want: v2UploadReply},
		{name: "unconfirmed upload", cmd: "/key_upload " + testApp + " 1 public-key", lookup: "/app " + testApp, pages: []string{appReply("Demo", 2, true, false)}, reason: "original key reply unavailable"},
		{name: "unmapped", cmd: "/me", reason: "no read-only check"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newReplayBot(t)
				loss := webhookResult{err: io.EOF}
				if tc.original != "" {
					loss.replies = []string{tc.original}
				}
				old := f.lost(tc.cmd, loss)
				time.Sleep(4 * time.Minute)
				for _, page := range tc.pages {
					var chunks []string
					for chunk := range slices.Chunk([]rune(page), 2000) {
						chunks = append(chunks, string(chunk))
					}
					f.results = append(f.results, webhookResult{replies: chunks})
				}
				if tc.regenerate {
					f.results = append(f.results, webhookResult{replies: []string{"new result"}})
				}
				var reply message
				reason := failureText(func() { reply = f.send(tc.cmd) })
				if len(f.results) != 0 {
					t.Fatal("expected more webhook requests")
				}
				for i := range tc.pages {
					want := tc.lookup
					if i > 0 {
						want += " next"
					}
					if f.updates[i+1].Message.Text != want {
						t.Fatal("unexpected read-only command")
					}
				}
				f.resume()
				if tc.reason != "" {
					if !strings.Contains(reason, tc.reason) || !strings.Contains(reason, strings.Fields(tc.cmd)[0]) || !strings.Contains(reason, "test-label") {
						t.Fatalf("unexpected stop %q", reason)
					}
					if f.d.data[testStateKey] == nil || f.d.data[testStateKey+"/reply"] != nil {
						t.Fatal("ambiguous outcome changed the checkpoint")
					}
					f.budget(1)
					return
				}
				if reason != "" {
					t.Fatal(reason)
				}
				if tc.regenerate {
					last := f.updates[len(f.updates)-1]
					if last.ID <= old.ID || last.Message.Text != tc.cmd+" "+totp(testTOTPSecret, time.Now()) || last.Message.Text == old.Command || reply.Text != "new result" {
						t.Fatal("expected fresh command")
					}
					f.budget(2)
				} else {
					if reply.Text != tc.want || (tc.original != "" && reply.ID != 1) {
						t.Fatal("did not adopt the caller's reply")
					}
					f.budget(1)
				}
				cached := f.d.telegram("test-label", merchantUser, func() string { panic("rebuilt a confirmed delivery") })
				if cached != reply {
					t.Fatal("reply did not survive resume")
				}
			})
		})
	}
}

func TestTelegramLegacyDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newReplayBot(t)
		f.d.put(testStateKey, object{"ID": 52, "After": 0, "Chat": merchantUser, "User": merchantUser, "Command": testCreate + " 000000", "Date": time.Now().Unix()})
		time.Sleep(10 * time.Minute)
		f.resume()
		f.results = []webhookResult{{replies: []string{"ok"}}}
		f.d.telegram("test-label", merchantUser, func() string { panic("rebuilt legacy delivery") })
		if len(f.updates) != 1 || f.updates[0].ID != 52 || f.updates[0].Message.Text != testCreate+" 000000" || f.d.data["totp-window/merchant"] != nil {
			t.Fatal("legacy delivery was changed")
		}
	})
}

func TestTelegramSocketWriteCheckpoint(t *testing.T) {
	// net.Pipe exercises the production HTTP/1 buffering path without a listener.
	for _, written := range []bool{false, true} {
		t.Run(fmt.Sprintf("written=%t", written), func(t *testing.T) {
			f := newReplayBot(t)
			inspected := make(chan bool, 1)
			localHTTP = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				if !written {
					server.Close()
					return client, nil
				}
				go func() {
					defer server.Close()
					req, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						inspected <- false
						return
					}
					io.Copy(io.Discard, req.Body)
					req.Body.Close()
					// Keep the response pending until the write checkpoint is on disk.
					inspected <- pollUntil(time.Sleep, 5*time.Second, func() bool {
						resumed := newDriver(f.root, "", "setup")
						var saved delivery
						return resumed.read(testStateKey, &saved) && saved.Sent
					})
				}()
				return client, nil
			}}}
			expectFailure(t, func() { f.d.bot("test-label", "/balance") })
			if written && !<-inspected {
				t.Fatal("write was not checkpointed before response")
			}
			f.resume()
			var pending delivery
			if f.d.read(testStateKey, &pending) != written || pending.TOTPStep != 0 {
				t.Fatal("incorrect socket write classification")
			}
		})
	}
}

func TestTelegramReplayRefusal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newReplayBot(t)
		f.lost(testCreate, webhookResult{err: io.EOF})
		f.results = []webhookResult{{replies: []string{"\u8bf7\u6c42\u65e0\u6cd5\u5904\u7406"}}}
		reason := failureText(func() { f.send(testCreate) })
		f.resume()
		if !strings.Contains(reason, "backend bot rejected /app_create") || f.d.data[testStateKey] != nil || f.d.data[testStateKey+"/reply"] != nil {
			t.Fatal("refusal was not cleared")
		}
	})
}
