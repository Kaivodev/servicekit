package main

import (
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestStartWait(t *testing.T) {
	now := time.Unix(1000, 0)
	window := 5 * time.Minute
	cutoff := now.Add(-window - 5*time.Second)
	a, b, c := now.Add(-2*time.Minute), now.Add(-time.Minute), now
	for _, tc := range []struct {
		name    string
		history []time.Time
		wait    time.Duration
		recent  []time.Time
	}{
		{"empty", nil, 0, nil},
		{"below limit", []time.Time{b, c}, 0, []time.Time{b, c}},
		{"just full", []time.Time{a, b, c}, 185 * time.Second, []time.Time{a, b, c}},
		{"inside margin", []time.Time{cutoff.Add(time.Second), b, c}, time.Second, []time.Time{cutoff.Add(time.Second), b, c}},
		{"at expiry", []time.Time{cutoff, b, c}, 0, []time.Time{b, c}},
		{"just expired", []time.Time{cutoff.Add(-time.Nanosecond), b, c}, 0, []time.Time{b, c}},
		{"lowered limit", []time.Time{c, cutoff.Add(time.Second), a, b}, 185 * time.Second, []time.Time{a, b, c}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.history)
			wait, recent := startWait(tc.history, now, 3, window)
			if wait != tc.wait || !slices.Equal(recent, tc.recent) {
				t.Fatalf("got (%v, %v), want (%v, %v)", wait, recent, tc.wait, tc.recent)
			}
			if !slices.Equal(tc.history, before) {
				t.Fatal("input history changed")
			}
		})
	}
}

func TestStartPolicy(t *testing.T) {
	const limitKey = "AIPAY_IAM_REGISTRATION_PER_USER"
	const windowKey = "AIPAY_IAM_ATTEMPT_WINDOW"
	for _, tc := range []struct {
		env    map[string]string
		limit  int
		window time.Duration
	}{
		{nil, 3, 5 * time.Minute},
		{map[string]string{limitKey: "1"}, 1, 5 * time.Minute},
		{map[string]string{windowKey: "30s"}, 3, 30 * time.Second},
		{map[string]string{limitKey: "7", windowKey: "1h"}, 7, time.Hour},
	} {
		limit, window := startPolicy(tc.env)
		if limit != tc.limit || window != tc.window {
			t.Errorf("policy(%v) = (%d, %s), want (%d, %s)", tc.env, limit, window, tc.limit, tc.window)
		}
	}
	for key, invalid := range map[string][]string{
		limitKey:  {"", "three", "0", "-1"},
		windowKey: {"", "forever", "0s", "-1m", "29s", "61m"},
	} {
		for _, value := range invalid {
			t.Run(key+"="+value, func(t *testing.T) {
				expectFailure(t, func() { startPolicy(map[string]string{key: value}) })
			})
		}
	}
}

type startWebhook func(*http.Request) (*http.Response, error)

func (send startWebhook) RoundTrip(req *http.Request) (*http.Response, error) { return send(req) }

func TestStartDeliveryQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		root := t.TempDir()
		check(atomic(filepath.Join(root, "env/iam.env"), []byte("AIPAY_IAM_REGISTRATION_PER_USER=1\nAIPAY_IAM_ATTEMPT_WINDOW=30s\n")))
		backendEnv := filepath.Join(root, "env/backend.env")
		d := newDriver(root, "", "setup")
		began := time.Now()
		var posts []time.Duration
		var replies []message
		reply := "ok"
		saved := localHTTP
		defer func() { localHTTP = saved }()
		localHTTP = &http.Client{Transport: startWebhook(func(req *http.Request) (*http.Response, error) {
			req.Body.Close()
			posts = append(posts, time.Since(began))
			replies = append(replies, message{ID: int64(len(posts)), Chat: demoGroup, Text: reply})
			check(atomic(filepath.Join(d.dir, "messages.json"), encoded(replies)))
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})}
		start := func() string { return "/start" }
		check(atomic(backendEnv, []byte("AIPAY_TELEGRAM_WEBHOOK_PATH=/%zz\n")))
		expectFailure(t, func() { d.deliver("first", merchantUser, demoGroup, start) })
		check(atomic(backendEnv, nil))
		d.deliver("first", merchantUser, demoGroup, start)
		d = newDriver(root, "", "setup")
		d.deliver("first", merchantUser, demoGroup, func() string { panic("cached reply replayed") })
		d.deliver("other-user", merchantUser+1, demoGroup, start)
		d = newDriver(root, "", "statement")
		d.active = &result{}
		d.deliver("balance", merchantUser, demoGroup, func() string { return "/balance" })
		reply = "请求无法处理"
		expectFailure(t, func() { d.deliver("next", merchantUser, demoGroup, start) })
		reply = "ok"
		d.deliver("next", merchantUser, demoGroup, start)
		if want := []time.Duration{0, 0, 0, 35 * time.Second, 70 * time.Second}; !slices.Equal(posts, want) {
			t.Fatalf("webhook POST times %v, want %v", posts, want)
		}
		if !strings.Contains(strings.Join(d.active.Requests, "\n"), "预计等待 35s") {
			t.Fatalf("missing wait in trace %v", d.active.Requests)
		}
	})
}
