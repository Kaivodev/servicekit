package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeKubeFixtures(t *testing.T) {
	// Unix socket paths on Darwin are limited to 103 bytes.
	dir, e := os.MkdirTemp("/tmp", "demo-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	t.Setenv("AIPAY_DEMO_FIXTURE_DIR", dir)
	tokenPath := filepath.Join(t.TempDir(), "token")
	check(atomic(tokenPath, []byte("test-only-bot")))
	t.Setenv("AIPAY_TELEGRAM_BOT_TOKEN_FILE", tokenPath)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- executeContext(ctx, []string{"serve-k8s"}) }()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	control := "http://127.0.0.1:8088"
	if !pollUntil(3*time.Second, func() bool {
		res, e := localHTTP.Get(control + "/messages.json")
		if e != nil {
			return false
		}
		res.Body.Close()
		return res.StatusCode == 200
	}) {
		t.Fatal("fixture listeners unavailable")
	}
	key := "fixture-only-v1-key"
	cfg := fixtureConfig{Token: "test-only-bot", Webhook: "https://merchant.aipay.test/telegram/webhook", V1: encoded(object{"PID": "10001", "Key": key})}
	installFixtureConfig(dir, bytes.NewReader(encoded(cfg)))
	handoff := cfg
	handoff.Token = ""
	for _, tc := range []struct {
		auth   string
		status int
	}{{"", 403}, {"Bearer wrong", 403}, {"Bearer " + cfg.Token, 204}} {
		req, e := http.NewRequest("POST", control+"/config", bytes.NewReader(encoded(handoff)))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", tc.auth)
		res, e := localHTTP.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatal("fixture handoff", res.StatusCode)
		}
	}
	send := func(path string, body object) int {
		r, e := localHTTP.Post("http://127.0.0.1:8081/bot"+cfg.Token+"/"+path, "application/json", bytes.NewReader(encoded(body)))
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		return r.StatusCode
	}
	if send("sendMessage", object{"chat_id": merchantUser, "text": "test delivery"}) != 200 {
		t.Fatal("Bot API")
	}
	read := func(path string) string { return string(getLocal("127.0.0.1:8088", path, 4096)) }
	if !strings.Contains(read("/messages.json"), "test delivery") {
		t.Fatal("missing bot control record")
	}
	if send("deleteMessage", object{"chat_id": merchantUser, "message_id": 1}) != 200 || strings.Contains(read("/messages.json"), "test delivery") {
		t.Fatal("message deletion")
	}
	connect := func(target string) (net.Conn, *bufio.Reader, int) {
		c, e := net.DialTimeout("tcp", "127.0.0.1:3128", time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		r := bufio.NewReader(c)
		res, e := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
		if e != nil {
			c.Close()
			t.Fatal(e)
		}
		return c, r, res.StatusCode
	}
	bad, _, code := connect("127.0.0.1:5432")
	bad.Close()
	if code != 403 {
		t.Fatal("proxy destination policy")
	}
	host := "demo-fixtures.kaivo-sim.svc.cluster.local:8082"
	c, reader, code := connect(host)
	defer c.Close()
	if code != 200 {
		t.Fatal("CONNECT failed", code)
	}
	v := url.Values{"pid": {"10001"}, "trade_no": {"txn"}, "out_trade_no": {"ord"}, "money": {"1.00"}, "trade_status": {"TRADE_SUCCESS"}, "sign_type": {"MD5"}}
	v.Set("sign", v1Sign(v, key))
	req, e := http.NewRequest("POST", "http://"+host+"/notify", strings.NewReader(v.Encode()))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Close = true
	if e = req.Write(c); e != nil {
		t.Fatal(e)
	}
	res, e := http.ReadResponse(reader, req)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil || res.StatusCode != 200 || string(body) != "success" {
		t.Fatal("signed notification through tunnel", res.StatusCode)
	}
	if !strings.Contains(read("/connections.json"), host) || !strings.Contains(read("/notifications.json"), "txn") {
		t.Fatal("missing proxy or merchant evidence")
	}
	for _, path := range []string{"/merchant-key.json", "/config.sock", "/../driver.lock"} {
		r, e := localHTTP.Get(control + path)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatal(path, r.StatusCode)
		}
	}
	r, e := localHTTP.Post(control+"/messages.json", "text/plain", strings.NewReader("change"))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode == 200 {
		t.Fatal("writable control")
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			b := file(filepath.Join(dir, entry.Name()))
			if bytes.Contains(b, []byte(key)) || bytes.Contains(b, []byte(cfg.Token)) {
				t.Fatal("fixture configuration written to state")
			}
		}
	}
}
