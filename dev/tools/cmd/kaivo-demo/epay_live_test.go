package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testBase = "https://upstream.example.test:8443/"
	testPID  = "928734651"
	testKey  = "synthetic&merchant=sentinel"
	testEnv  = "EPAY_TEST_BASE_URL=" + testBase + "\nEPAY_TEST_PID=" + testPID + "\nEPAY_TEST_KEY=" + testKey + "\n"
)

func liveFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator.env")
	check(os.WriteFile(path, []byte(content), 0600))
	t.Setenv(liveFileEnv, path)
	return path
}

func TestLiveCredentials(t *testing.T) {
	quoted := "# operator file\r\n\r\nEPAY_TEST_BASE_URL='" + testBase + "'\r\nEPAY_TEST_PID=\"" + testPID + "\"\r\nEPAY_TEST_KEY='" + testKey + "'"
	liveFile(t, quoted)
	c := readLiveCredentials()
	if c.pid != testPID || c.key != testKey || c.gateway.String() != testBase {
		t.Fatal("quoted values did not round-trip")
	}
	for _, tc := range []struct{ name, content, diagnostic string }{
		{"missing URL", strings.ReplaceAll(testEnv, "EPAY_TEST_BASE_URL="+testBase+"\n", ""), "EPAY_TEST_BASE_URL"},
		{"missing PID", strings.ReplaceAll(testEnv, "EPAY_TEST_PID="+testPID+"\n", ""), "EPAY_TEST_PID"},
		{"missing key", strings.ReplaceAll(testEnv, "EPAY_TEST_KEY="+testKey+"\n", ""), "EPAY_TEST_KEY"},
		{"duplicate", testEnv + "EPAY_TEST_KEY=" + testKey, "EPAY_TEST_KEY"},
		{"unknown", testEnv + testKey + "=unknown", "unknown variable"},
		{"assignment", testEnv + testPID, "assignment"},
		{"http", strings.ReplaceAll(testEnv, "https:", "http:"), "EPAY_TEST_BASE_URL"},
		{"no host", strings.ReplaceAll(testEnv, testBase, "https:///"), "EPAY_TEST_BASE_URL"},
		{"userinfo", strings.ReplaceAll(testEnv, "upstream.", testKey+"@upstream."), "EPAY_TEST_BASE_URL"},
		{"query", strings.ReplaceAll(testEnv, testBase, testBase+"?key="+testKey), "EPAY_TEST_BASE_URL"},
		{"empty query", strings.ReplaceAll(testEnv, testBase, testBase+"?"), "EPAY_TEST_BASE_URL"},
		{"empty fragment", strings.ReplaceAll(testEnv, testBase, testBase+"#"), "EPAY_TEST_BASE_URL"},
		{"path", strings.ReplaceAll(testEnv, testBase, testBase+testPID), "EPAY_TEST_BASE_URL"},
		{"escaped path", strings.ReplaceAll(testEnv, testBase, testBase+"%2F"), "EPAY_TEST_BASE_URL"},
		{"zero", strings.ReplaceAll(testEnv, testPID, "0"), "EPAY_TEST_PID"},
		{"leading zero", strings.ReplaceAll(testEnv, testPID, "0"+testPID), "EPAY_TEST_PID"},
		{"signed PID", strings.ReplaceAll(testEnv, testPID, "+"+testPID), "EPAY_TEST_PID"},
		{"blank key", strings.ReplaceAll(testEnv, testKey, ""), "EPAY_TEST_KEY"},
		{"key space", strings.ReplaceAll(testEnv, testKey, testKey+" "), "EPAY_TEST_KEY"},
		{"key tab", strings.ReplaceAll(testEnv, testKey, "'"+testKey+"\t'"), "EPAY_TEST_KEY"},
		{"key control", strings.ReplaceAll(testEnv, testKey, testKey+"\x00"), "EPAY_TEST_KEY"},
		{"unmatched quote", strings.ReplaceAll(testEnv, testKey, "'"+testKey+"\""), "EPAY_TEST_KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			liveFile(t, tc.content)
			msg := failureText(func() { readLiveCredentials() })
			if !strings.Contains(msg, tc.diagnostic) || strings.Contains(msg, testKey) || strings.Contains(msg, testPID) || strings.Contains(msg, "example.test") {
				t.Fatal("expected a value-free diagnostic identifying the invalid input")
			}
		})
	}
	for _, mode := range []os.FileMode{0640, 0604, 0610} {
		path := liveFile(t, testEnv)
		check(os.Chmod(path, mode))
		expectFailure(t, func() { readLiveCredentials() })
	}
	t.Setenv(liveFileEnv, t.TempDir())
	expectFailure(t, func() { readLiveCredentials() })
}

func TestLiveEntryPoints(t *testing.T) {
	t.Setenv(liveFileEnv, "")
	t.Setenv("AIPAY_DEMO_TARGET", "native")
	root := t.TempDir()
	check(atomic(filepath.Join(root, "env/backend.env"), nil))
	d := newDriver(root, "", "setup")
	for _, action := range []string{"setup", "run"} {
		err := execute([]string{root, root, action, livePhase})
		if err == nil || !strings.Contains(err.Error(), liveFileEnv) {
			t.Fatal("missing operator file must stop the command before stack access")
		}
	}
	check(atomic(filepath.Join(root, "env/payment.env"), nil))
	if err := execute([]string{root, root, "setup", "packages"}); err == nil || !strings.Contains(err.Error(), "Prepare a fresh stack") {
		t.Fatal("package setup requires the native gateway")
	}
	path := liveFile(t, testEnv)
	for _, action := range []string{"setup", "run"} {
		err := execute([]string{root, root, action, livePhase})
		if err == nil || !strings.Contains(err.Error(), "Prepare a fresh stack") {
			t.Fatal("expected gateway prerequisite")
		}
	}
	check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=test\n")))
	for _, action := range []string{"setup", "run"} {
		if msg := failureText(func() { d.checkLivePrerequisites(action) }); !strings.Contains(msg, "complete demo setup") {
			t.Fatal("expected completed setup prerequisite")
		}
	}
	d.put("step/setup/"+channelStepName(epayChannel, "核验账户与启用"), result{Status: "ok"})
	publish := func(code, domain string) {
		m := object{"code": code, "domains": []string{domain}}
		d.put("plugin/"+code, code+"-version")
		d.put("write/setup/"+code+"/approver2/result", object{"material": object{"plugin_version": object{
			"plugin_version_id": code + "-version", "manifest_json": b64.EncodeToString(encoded(m)),
		}}})
	}
	host := "upstream.example.test"
	for _, denied := range []string{epayChannel, epayChannel + "_verify"} {
		publish(epayChannel, host)
		publish(epayChannel+"_verify", host)
		publish(denied, "different."+host)
		msg := failureText(func() { d.checkLivePrerequisites("setup") })
		if !strings.Contains(msg, denied+" manifest domains") || strings.Contains(msg, host) || d.data[channelKey(liveVariant, "operator-file-sha")] != nil {
			t.Fatal("both approved manifests must allow the exact host before binding the file")
		}
	}
	publish(epayChannel+"_verify", strings.ToUpper(host))
	d.checkLivePrerequisites("setup")
	d.put("step/setup/"+channelStepName(liveVariant, "核验账户与启用"), result{Status: "ok"})
	d.checkLivePrerequisites("run")
	check(os.WriteFile(path, []byte(strings.ReplaceAll(testEnv, testPID, testPID+"9")), 0600))
	expectFailure(t, func() { d.liveCredentials() })
	expectFailure(t, func() { d.checkLivePrerequisites("run") })
}

func TestLiveChannelAndOrder(t *testing.T) {
	liveFile(t, testEnv)
	c := readLiveCredentials()
	s := liveChannelSpec(c, "4200")
	query := object{"gateway": testBase, "pid": testPID, "unpaid_timeout_seconds": "4200"}
	trade := object{"gateway": testBase, "pid": testPID, "unpaid_timeout_seconds": "4200", "product_name": "Kaivo test"}
	if !reflect.DeepEqual(query, s.queryConfig) || !reflect.DeepEqual(trade, s.tradeConfig) || s.priority != 0 || s.minAmount != "111" || s.maxAmount != "111" || s.name != "EPay 测试上游" {
		t.Fatal("invalid live channel specification")
	}
	for _, code := range []string{md5Channel, epayChannel} {
		if channelKey(code, "channel") == channelKey(liveVariant, "channel") || channelSetup(code, "", "4200").priority != 1 {
			t.Fatal("simulator account or priority collision")
		}
	}
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_CLIENT_IP", "")
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_WAIT", "")
	if ip, wait := liveOrderSettings(); ip != "127.0.0.1" || wait != 30*time.Minute {
		t.Fatal("invalid live defaults")
	}
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_CLIENT_IP", "::1")
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_WAIT", "0s")
	if ip, wait := liveOrderSettings(); ip != "::1" || wait != 0 {
		t.Fatal("overrides not applied")
	}
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_WAIT", "-1s")
	expectFailure(t, func() { liveOrderSettings() })
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_CLIENT_IP", "invalid")
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_WAIT", "20m")
	expectFailure(t, func() { liveOrderSettings() })
	payerLink := "https://pay.test:8443/checkout/a%2Fb?pid=" + testPID + "&sign=signature#client"
	if c.paymentLink(payerLink) != payerLink || paymentLinkEvidence(payerLink) != "https://pay.test:8443/checkout/a%2Fb" {
		t.Fatal("payer link or evidence lost its original host or escaped path")
	}
	for _, link := range []string{"file:///bad", "https://user@pay.test", "https://pay.test/?x=" + testKey,
		"https://pay.test/#synthetic%26merchant%3Dsentinel", "https://pay.test/?x=synthetic%2526merchant%253Dsentinel",
		"https://pay.test/?bad=%&x=synthetic%2526merchant%253Dsentinel", "https://pay.test/?x=%250A"} {
		msg := failureText(func() { c.paymentLink(link) })
		if msg == "" || strings.Contains(msg, testPID) || strings.Contains(msg, testKey) {
			t.Fatal("unsafe instruction printed a credential or passed validation")
		}
	}
}

func TestLivePrivateWritesAndReport(t *testing.T) {
	liveFile(t, testEnv)
	c := readLiveCredentials()
	d := newDriver(t.TempDir(), "", "setup")
	d.liveEPay = true
	op := d.browser("operations")
	canonical := credentialBytes(map[string]string{"merchant_key": c.key})
	sum := sha256.Sum256(canonical)
	digest := b64.EncodeToString(sum[:])
	spec := liveChannelSpec(c, "4200")
	config := b64.EncodeToString(encoded(spec.tradeConfig))
	approvalBytes := b64.EncodeToString([]byte("approval:" + config))
	var keys = map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, op.prefix)
		if path == "/auth/csrf" {
			fmt.Fprint(w, `{"code":200,"data":{"token":"csrf"}}`)
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" || (keys[path] != "" && keys[path] != key) {
			t.Error("retry changed the idempotency key")
		}
		keys[path] = key
		var body object
		check(json.NewDecoder(r.Body).Decode(&body))
		switch path {
		case "/channel-accounts/credentials", "/verification/credentials":
			if body["credentials_json"] != b64.EncodeToString(canonical) {
				t.Error("seal received the wrong canonical bytes")
			}
			fmt.Fprintf(w, `{"code":200,"data":{"credentials_ref":"sealed","credentials_sha256":%q,"ignored":%q}}`, digest, testKey)
		case "/channel-accounts/requests", "/channel-accounts/approvals/test/assertions":
			fmt.Fprintf(w, `{"code":200,"data":{"request_bytes":%q,"config_json":%q}}`, approvalBytes, config)
		case "/verification/accounts/requests":
			fmt.Fprintf(w, `{"code":400,"msg":%q}`, testKey+testPID)
		default:
			t.Error("unexpected portal endpoint")
		}
	}))
	defer srv.Close()
	op.addr = strings.TrimPrefix(srv.URL, "http://")
	d.liveStep("测试上游", func() {
		d.evidence("配置", c.reportConfig())
		d.evidence("pay_info", paymentLinkEvidence(c.paymentLink("https://pay.example.test/order/opaque?pid="+testPID+"&sign=query-sentinel#fragment-sentinel")))
		for range 2 {
			for _, path := range []string{"/channel-accounts/credentials", "/verification/credentials"} {
				r := op.write(path, path, func() object { return object{"credentials_json": b64.EncodeToString(canonical)} })
				verifiedCredentialDigest(r, canonical)
			}
			op.write("channel", "/channel-accounts/requests", func() object { return object{"config_json": config} })
			op.write("assert", "/channel-accounts/approvals/test/assertions", func() object { return object{"assertion": "signature"} })
		}
	})
	reason := failureText(func() {
		d.liveStep("refusal", func() {
			op.write("verify", "/verification/accounts/requests", func() object { return object{"config_json": config} })
		})
	})
	if reason == "" || strings.Contains(reason, testKey) || strings.Contains(reason, testPID) {
		t.Fatal("backend error was not sanitized")
	}
	if !reflect.DeepEqual(c.reportConfig(), object{"gateway": "upstream.example.test", "pid": "<configured>"}) {
		t.Fatal("report config must show just the hostname and PID marker")
	}
	for _, name := range []string{"state.json", "reports/setup.md", "reports/setup.json"} {
		b := file(filepath.Join(d.dir, name))
		if strings.HasPrefix(name, "reports/") && !bytes.Contains(b, []byte("<configured>")) {
			t.Fatal("missing literal PID marker in report")
		}
		if strings.HasPrefix(name, "reports/") && !bytes.Contains(b, []byte(`"pay_info": "https://pay.example.test/order/opaque"`)) {
			t.Fatalf("%s missing sanitized payment link", name)
		}
		for _, sensitive := range []string{testKey, testPID, testBase, b64.EncodeToString(canonical), config, approvalBytes, digest, "query-sentinel", "fragment-sentinel"} {
			if bytes.Contains(b, []byte(sensitive)) {
				t.Fatalf("%s retained private data", name)
			}
		}
	}
}

func TestLiveReportWithMerchantID(t *testing.T) {
	liveFile(t, strings.Replace(testEnv, "upstream.", testPID+".", 1))
	c := readLiveCredentials()
	cfg := c.reportConfig()
	if cfg["gateway"] != testPID+".example.test" || cfg["pid"] != "<configured>" ||
		c.containsKey("upstream-"+testPID) || !c.containsKey("ok%: synthetic%2526merchant%253Dsentinel") {
		t.Fatal("PID or encoded KEY incorrectly handled in report fields")
	}
}

func TestLiveResumeTrimsPreviousEvidence(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", livePhase)
	const path = "https://cashier.test:8443/p/a%2Fb"
	d.step("测试上游 商户下单", func() { d.evidence("pay_info", path+"?sign=old-sign#old-fragment") })
	t.Setenv(liveFileEnv, "")
	t.Setenv("AIPAY_DEMO_TARGET", "native")
	output := filepath.Join(root, "resumed.json")
	err := execute([]string{root, root, "run", livePhase, "-o", output})
	if err == nil || !strings.Contains(err.Error(), liveFileEnv) {
		t.Fatal("expected preflight failure on resume")
	}
	for _, name := range []string{output, filepath.Join(d.dir, "reports/epay-live.md"), filepath.Join(d.dir, "state.json")} {
		b := string(file(name))
		if !strings.Contains(b, path) || strings.Contains(b, "old-sign") || strings.Contains(b, "old-fragment") {
			t.Fatal("previous link parameters survived resume")
		}
	}
}

func TestLiveRouteAndPaidWait(t *testing.T) {
	d := newDriver(t.TempDir(), "", livePhase)
	d.put("uuid/"+channelKey(liveVariant, "channel"), "live-account")
	check(atomic(filepath.Join(d.root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=test")))
	trade := tradeRun{d: d, name: "测试上游"}
	row := normalized(object{"order_id": "order", "channel_code": epayChannel, "channel_account_id": "sim-account", "amount_minor": 111})
	if msg := failureText(func() { trade.step("route", func() { trade.checkOrderRoute(row) }) }); !strings.Contains(msg, "epay_v1 channel account sim-account") {
		t.Fatal("fallback to simulator with the same plugin must stop before payment")
	}
	row["channel_account_id"] = "live-account"
	trade.step("route", func() { trade.checkOrderRoute(row) })
	key := d.key(livePhase + "/order-number")
	prompts := 0
	prompt := func(context.Context) { prompts++ }
	wait := func(at any) {
		trade.step("wait", func() {
			paid := waitLivePayment(t.Context(), 0, func(context.Context) (any, error) { return at, nil }, prompt)
			trade.d.evidence("paid_verified_at", paid)
		})
	}
	if msg := failureText(func() { wait(nil) }); msg != "未付款" || prompts != 1 {
		t.Fatal("unpaid order should prompt once and time out")
	}
	trade.d = newDriver(d.root, "", livePhase)
	wait("paid timestamp")
	if prompts != 1 || trade.d.key(livePhase+"/order-number") != key || trade.d.active.Evidence["paid_verified_at"] != "paid timestamp" {
		t.Fatal("restart must accept the original paid order without prompting again")
	}
	if msg := failureText(func() {
		waitLivePayment(t.Context(), time.Millisecond, func(ctx context.Context) (any, error) { <-ctx.Done(); return nil, ctx.Err() }, prompt)
	}); msg != "未付款" {
		t.Fatal("ledger lookup must respect payment deadline")
	}
}

func TestLiveMerchantCreate(t *testing.T) {
	liveFile(t, testEnv)
	d := newDriver(t.TempDir(), "", livePhase)
	d.liveEPay = true
	creds := readLiveCredentials()
	const merchantKey = "test-merchant-key"
	d.put("pid/v1", "123")
	check(atomic(filepath.Join(d.dir, "merchant-key.json"), encoded(object{"Key": merchantKey})))
	const payURL = "https://pay.example.test/checkout?pid=" + testPID + "&sign=signature"
	const qrURL = "https://pay.example.test/qr?pid=" + testPID + "&sign=qr-signature"
	const failed = "epay-live merchant create failed"
	for _, tc := range []struct {
		name               string
		status             int
		body               string
		wantLink, wantFail string
	}{
		{"prefer payurl", 200, fmt.Sprintf(`{"code":1,"payurl":%q,"qrcode":%q}`, payURL, qrURL), payURL, ""},
		{"qrcode only", 200, fmt.Sprintf(`{"code":1,"qrcode":%q}`, qrURL), qrURL, ""},
		{"empty payurl", 200, fmt.Sprintf(`{"code":1,"payurl":"","qrcode":%q}`, qrURL), qrURL, ""},
		{"refusal", 200, fmt.Sprintf(`{"code":-1,"msg":"invalid clientip for %s"}`, testPID), "", failed + " (code=-1 msg=\"invalid clientip for " + testPID + "\")"},
		{"V2 success code", 200, `{"code":0,"msg":"refused"}`, "", failed + ` (code=0 msg="refused")`},
		{"HTTP failure", 503, fmt.Sprintf(`{"code":1,"payurl":%q,"msg":"unavailable"}`, payURL), "", failed + ` (code=1 msg="unavailable")`},
		{"raw key", 200, fmt.Sprintf(`{"code":-1,"msg":%q}`, testKey), "", failed},
		{"encoded key", 200, `{"code":-1,"msg":"100%: synthetic%2526merchant%253Dsentinel"}`, "", failed},
		{"key elsewhere", 200, fmt.Sprintf(`{"code":-1,"msg":"invalid clientip","extra":%q}`, testKey), "", failed},
		{"malformed response", 502, testKey, "", failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/mapi.php" || r.ParseForm() != nil ||
					r.PostForm.Get("pid") != "123" || r.PostForm.Get("sign_type") != "MD5" ||
					r.PostForm.Get("sign") == "" || r.PostForm.Get("sign") != v1Sign(r.PostForm, merchantKey) ||
					r.PostForm.Get("money") != "1.11" || r.PostForm.Get("clientip") != "::1" || r.PostForm.Get("out_trade_no") != "same-order" {
					t.Error("unexpected V1 merchant request")
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			d.browser("merchant").addr = strings.TrimPrefix(srv.URL, "http://")
			var link string
			msg := failureText(func() { link = d.createLiveEPayOrder("same-order", "::1", creds) })
			if msg != tc.wantFail || link != tc.wantLink {
				t.Fatal("unexpected V1 payment link or failure diagnostic")
			}
		})
	}
}

func TestLiveDisable(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AIPAY_DEMO_TARGET", "native")
	check(atomic(filepath.Join(root, "env/backend.env"), nil))
	t.Setenv(liveFileEnv, "")
	check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=test\n")))
	if err := execute([]string{root, root, "setup", liveOffPhase}); err == nil || !strings.Contains(err.Error(), "missing setup result uuid/channel/") {
		t.Fatal("standalone cleanup must resolve the existing live channel without an operator file")
	}
	d := newDriver(root, "", liveOffPhase)
	d.liveEPay = true
	d.put("uuid/"+channelKey(liveVariant, "channel"), "live-account")
	d.put("session-until/risk", time.Now().Add(time.Hour))
	d.put("cookies/risk", map[string]string{"__Host-kaivo_platform_session": "session"})
	const path = "/api/v1/platform/channel-accounts/live-account"
	enabled, version := false, 6
	reads := 0
	var writes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == path:
			reads++
			fmt.Fprintf(w, `{"code":200,"data":{"configuration":{"channel_account_id":"live-account","channel_code":"epay_v1","enabled":%t,"config_json":%q},"control_version":%d}}`, enabled, testPID, version)
		case r.Method == "GET" && r.URL.Path == "/api/v1/platform/auth/csrf":
			fmt.Fprint(w, `{"code":200,"data":{"token":"csrf"}}`)
		case r.Method == "POST" && r.URL.Path == path+"/emergency-disable":
			var body object
			check(json.NewDecoder(r.Body).Decode(&body))
			key := r.Header.Get("Idempotency-Key")
			if !enabled || key == "" || r.Header.Get("X-CSRF-Token") != "csrf" ||
				len(body) != 2 || body["expected_control_version"] != float64(version) || body["reason"] == "" {
				t.Error("invalid disable command")
			}
			writes = append(writes, key)
			if len(writes) == 1 {
				fmt.Fprint(w, `{"code":503}`)
				return
			}
			enabled = false
			version++
			fmt.Fprintf(w, `{"code":200,"data":{"channel_account_id":"live-account","control_version":%d}}`, version)
		default:
			t.Errorf("unexpected disable request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	d.browser("risk").addr = strings.TrimPrefix(srv.URL, "http://")
	d.disableLiveEPay()
	if reads != 1 || len(writes) != 0 || d.active.Evidence["结果"] != "已停用，跳过" {
		t.Fatal("disabled channel must only be read")
	}
	enabled = true
	if failureText(d.disableLiveEPay) == "" {
		t.Fatal("owner refusal must fail the step")
	}
	// Switch entry points after an ambiguous write. Both must recover the
	// same idempotency key and also recheck a previously finished run.
	d = newDriver(root, "", livePhase)
	d.liveEPay = true
	d.put("finished/"+livePhase, true)
	d.browser("risk").addr = strings.TrimPrefix(srv.URL, "http://")
	d.run(livePhase)
	d.run(livePhase)
	enabled = true
	version++
	d.run(livePhase)
	if reads != 5 || len(writes) != 3 || writes[0] != writes[1] || writes[1] == writes[2] || enabled {
		t.Fatal("disable must re-read the channel and reuse a key only for the same version")
	}
	for _, name := range []string{"state.json", "reports/epay-live-off.md", "reports/epay-live.json"} {
		if bytes.Contains(file(filepath.Join(d.dir, name)), []byte(testPID)) {
			t.Fatal("disable cached private channel configuration")
		}
	}
}
