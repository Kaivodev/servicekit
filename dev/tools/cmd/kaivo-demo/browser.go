package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"

	"slices"
	"strings"
	"sync"
	"time"
)

type browser struct {
	d                          *driver
	name, origin, addr, prefix string
	cookies                    map[string]string
}

func (d *driver) browser(name string) *browser {
	if b := d.browsers[name]; b != nil {
		return b
	}
	b := &browser{d: d, name: name, origin: d.origins.platform, addr: d.addresses().admin, prefix: "/api/v1/platform", cookies: map[string]string{}}
	if name == "seller" {
		b.origin = d.origins.seller
		b.addr = d.addresses().seller
		b.prefix = "/api/v1/seller"
	}
	if name == "merchant" {
		b.origin = "https://merchant.aipay.test"
		b.addr = d.addresses().public
		b.prefix = ""
	}
	d.read("cookies/"+name, &b.cookies)
	d.browsers[name] = b
	return b
}

var localHTTP = &http.Client{Timeout: 35 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (b *browser) http(method, path, label, ctype string, body []byte, headers map[string]string) (int, []byte) {
	return b.send(b.request(method, path, ctype, body, headers), label)
}

func (b *browser) request(method, path, ctype string, body []byte, headers map[string]string) *http.Request {
	req, e := http.NewRequestWithContext(b.d.ctx, method, "http://"+b.addr+path, bytes.NewReader(body))
	check(e)
	req.Host = strings.TrimPrefix(b.origin, "https://")
	req.Header.Set("User-Agent", "Kaivo demo browser")
	isBrowser := b.name != "merchant" || strings.HasPrefix(path, "/totp/enroll/")
	if isBrowser && method != "GET" {
		req.Header.Set("Origin", b.origin)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for k, v := range b.cookies {
		if !isBrowser {
			break
		}
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	return req
}

func (b *browser) send(req *http.Request, label string) (int, []byte) {
	// The client has one fixed listener and cookie scope per browser. It never follows redirects.
	code, out, _ := b.sendWithHeaders(req, label)
	return code, out
}

func (b *browser) sendWithHeaders(req *http.Request, label string) (int, []byte, http.Header) {
	res, e := b.d.doHTTP(localHTTP, req)
	return b.response(req, label, res, e)
}

type deliveryConn struct {
	net.Conn
	written func()
}

func (c deliveryConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.written()
	}
	return n, err
}

// Observe the connection for this webhook alone. For a small HTTP/1 POST,
// WroteRequest can fire while the entire request is still buffered in net/http.
func (b *browser) sendTracked(req *http.Request, label string, markSent func() error) int {
	var once sync.Once
	var saveErr error
	written := func() { once.Do(func() { saveErr = markSent() }) }
	client := *localHTTP
	if transport, ok := client.Transport.(*http.Transport); ok {
		tr := transport.Clone()
		dial := tr.DialContext
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return deliveryConn{conn, written}, nil
		}
		client.Transport = tr
		defer tr.CloseIdleConnections()
	} else {
		trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				written()
			}
		}}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}
	res, err := b.d.doHTTP(&client, req)
	if res != nil {
		written()
	}
	once.Do(func() {}) // Join an in-flight callback and disarm any later one.
	if saveErr != nil && res != nil {
		res.Body.Close()
	}
	check(saveErr)
	code, _, _ := b.response(req, label, res, err)
	return code
}

func (b *browser) response(req *http.Request, label string, res *http.Response, e error) (int, []byte, http.Header) {
	if e != nil {
		stop("%s %s transport failed", req.Method, label)
	}
	defer res.Body.Close()
	out, e := io.ReadAll(io.LimitReader(res.Body, 20<<20))
	check(e)
	for _, c := range res.Cookies() {
		require(strings.HasPrefix(c.Name, "__Host-") && c.Secure && c.Path == "/" && c.Domain == "", "unexpected browser cookie scope")
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	if len(res.Cookies()) > 0 {
		b.d.put("cookies/"+b.name, b.cookies)
	}
	b.d.trace(fmt.Sprintf("%s %s → HTTP %d · request %s", req.Method, label, res.StatusCode, res.Header.Get("X-Request-ID")))
	return res.StatusCode, out, res.Header
}
func (b *browser) api(method, path, key string, body object) object {
	return b.apiGrant(method, path, key, body, "")
}
func (b *browser) apiGrant(method, path, key string, body object, grant string) object {
	return b.portalAPI(method, path, key, body, grant, nil)
}

// An image upload needs the server's canonical JPEG command digest before MFA.
func (b *browser) submitRecent(c portalCommand) object {
	return b.portalAPI("POST", c.path, c.key, c.body, "", func(digest []byte) string {
		copy(c.digest[:], digest)
		return b.grant(c)
	})
}

func (b *browser) portalAPI(method, path, key string, body object, grant string, reauthenticate func([]byte) string) object {
	var data []byte
	h := map[string]string{}
	if grant != "" {
		h["X-Reauthentication-ID"] = grant
	}
	if method != "GET" {
		csrf := b.api("GET", "/auth/csrf", "", nil)
		h["X-CSRF-Token"] = str(csrf, "token")
		if key == "" {
			key = id()
		}
		h["Idempotency-Key"] = key
		data = encoded(body)
	}
	displayPath, _, _ := strings.Cut(path, "?")
	label := b.prefix + displayPath
	if strings.HasPrefix(displayPath, "/auth/challenges/") {
		label = b.prefix + "/auth/challenges/{id}"
		if strings.HasSuffix(displayPath, "/verify") {
			label += "/verify"
		}
	}
	if method != "GET" {
		keys := slices.Sorted(maps.Keys(body))
		b.d.trace(fmt.Sprintf("%s %s · fields %s · idempotency %s", method, label, strings.Join(keys, ","), h["Idempotency-Key"]))
	}
	code, out, headers := b.sendWithHeaders(b.request(method, b.prefix+path, "application/json", data, h), label)
	var env struct {
		Code    int
		Data    object
		Message string `json:"msg"`
	}
	postReleaseEntry := b.d.history.Scenario == "dispute-refund-after-release" && method == "POST" && path == "/disputes"
	if postReleaseEntry && (code == 404 || code == 405 || code == 501) {
		stop("已放币争议登记缺入口：POST %s 返回 HTTP %d", label, code)
	}
	if b.d.liveEPay || b.d.scope == "invite" {
		// A malformed envelope or backend diagnostic may echo a submitted value.
		require(decodeJSON(out, &env) == nil, "invalid portal response")
	} else {
		decode(out, &env)
	}
	if reauthenticate != nil && env.Code == 428 && (code == 200 || code == 428) {
		digest := raw(headers.Get("X-Command-SHA256"))
		require(len(digest) == sha256.Size, "missing canonical reauthentication digest")
		return b.apiGrant(method, path, key, body, reauthenticate(digest))
	}
	if code != 200 || env.Code != 200 {
		if postReleaseEntry {
			switch env.Code {
			case 404, 405, 501:
				stop("已放币争议登记缺入口：POST %s 返回 HTTP %d，业务码 %d", label, code, env.Code)
			case 409:
				stop("已放币争议登记被拒绝（缺入口或订单控制状态冲突）：POST %s 返回 HTTP %d，业务码 %d", label, code, env.Code)
			}
		}
		if env.Code == 401 || env.Code == 428 {
			delete(b.d.data, "session-until/"+b.name)
			b.d.save()
		}
		if b.d.liveEPay || b.d.scope == "invite" {
			stop("%s %s → HTTP %d, backend code %d", method, label, code, env.Code)
		}
		panic(failure{reason: fmt.Sprintf("%s %s → HTTP %d, backend code %d (%s)", method, label, code, env.Code, env.Message), method: method, path: path, httpStatus: code, businessCode: env.Code, message: env.Message})
	}
	if strings.HasSuffix(path, "/assertions") {
		checkRenderedApprovals(env.Data)
		if approval, ok := env.Data["approval"].(object); ok {
			checkRenderedApprovals(approval)
		}
	}
	return env.Data
}
func (b *browser) post(path string, body object) object { return b.api("POST", path, "", body) }

// Config proposals and both assertion responses carry the PID in signed material.
func (d *driver) privateChannelApproval(path string) bool {
	return d.liveEPay && ((strings.HasPrefix(path, "/channel-accounts/") && path != "/channel-accounts/credentials") ||
		strings.HasPrefix(path, "/verification/accounts/"))
}

// Rebuild private bodies in memory. Recover their results from the owner
// with the same key and the original assertion after an ambiguous write.
func (b *browser) write(label, path string, makeBody func() object) object {
	d := b.d
	privateApproval := d.privateChannelApproval(path)
	seal := path == "/channel-accounts/credentials" || path == "/verification/credentials"
	privateResult := privateApproval || d.liveEPay && seal
	k := "write/" + d.scope + "/" + label
	var response object
	if !privateResult && d.read(k+"/result", &response) {
		return response
	}
	var body object
	privateBody := privateApproval && !strings.HasSuffix(path, "/assertions")
	upload := path == "/plugins" || path == "/verification/plugins" || seal
	if privateBody || upload {
		body = makeBody()
		digest := fmt.Sprintf("%x", sha256.Sum256(encoded(body)))
		require(d.value(k+"/body-sha", func() string { return digest }) == digest, "changed upload on retry")
	} else if !d.read(k+"/body", &body) {
		body = makeBody()
		d.put(k+"/body", body)
	}
	response = b.api("POST", path, d.key(k), body)
	if !privateResult {
		d.put(k+"/result", response)
	}
	return response
}
func (d *driver) password(name string) string {
	return d.value("password/"+name, func() string { return "D1!" + b64.EncodeToString(random(21)) })
}
func (d *driver) email(name string) string {
	if name == "seller" && d.data["seller-email"] != nil {
		return d.required("seller-email")
	}
	return name + "@demo.aipay.test"
}

// IAM charges every MFA verification (TOTP and WebAuthn, successful or not)
// to one fixed per-account window (default 5 attempts per 5 minutes). Stay one
// below the limit and wait for the window to expire instead of tripping the
// lockout. The state key keeps its historical totp-window name.
const (
	totpWindow       = 5*time.Minute + 2*time.Second
	totpBudget       = 4
	iamTOTPSkewSteps = 1
)

type mfaWindow struct {
	Start time.Time
	Count int
}

// awaitMFA waits until name has MFA budget left in the IAM attempt window.
// Call it before starting a login or reauthentication: an IAM challenge
// expires after five minutes, as long as the window itself.
func (d *driver) awaitMFA(name string) {
	var window mfaWindow
	d.read("totp-window/"+name, &window)
	if window.Count >= totpBudget {
		if wait := time.Until(window.Start.Add(totpWindow)); wait > 0 {
			d.trace(fmt.Sprintf("waiting %s for the IAM MFA attempt window of %s", wait.Round(time.Second), name))
			d.sleep(wait)
		}
	}
}

// chargeMFA records one MFA verification for name after ready returns.
func (d *driver) chargeMFA(name string, ready func()) time.Time {
	d.awaitMFA(name)
	if ready != nil {
		ready()
	}
	var window mfaWindow
	d.read("totp-window/"+name, &window)
	now := time.Now()
	if !now.Before(window.Start.Add(totpWindow)) {
		window.Start, window.Count = now, 0
	}
	window.Count++
	d.put("totp-window/"+name, window)
	return now
}

func (d *driver) freshTOTP(name string) string {
	now := d.chargeMFA(name, func() {
		var last int64
		d.read("totp-step/"+name, &last)
		for totpStep(time.Now()) <= last || time.Now().Unix()%30 >= 28 {
			d.sleep(250 * time.Millisecond)
		}
	})
	step := totpStep(now)
	d.put("totp-step/"+name, step)
	if d.commandTOTPStep != nil {
		*d.commandTOTPStep = step
	}
	return totp(d.required("totp/"+name), now)
}
func (d *driver) login(name string) {
	b := d.browser(name)
	// Reuse only the full session delivered by IAM. Each portal call still
	// presents that session and is authorized for its own method.
	var validUntil time.Time
	sessionCookie := "__Host-kaivo_platform_session"
	if name == "seller" {
		sessionCookie = "__Host-kaivo_seller_session"
	}
	if d.read("session-until/"+name, &validUntil) && time.Now().Before(validUntil) && b.cookies[sessionCookie] != "" {
		return
	}
	login := func() object {
		return b.post("/auth/login", object{"email": d.email(name), "password": d.password(name)})
	}
	d.awaitMFA(name)
	r := login()
	if str(r, "state") == "setup_required" {
		if name == "seller" {
			o := b.post("/me/mfa/totp/enrollments", object{})
			d.put("totp/"+name, qrSecret(raw(str(o, "qr_code_png"))))
			b.post("/me/mfa/totp/confirm", object{"enrollment_id": str(o, "enrollment_id"), "code": d.freshTOTP(name)})
		} else {
			o := b.post("/me/webauthn/enrollments", object{"name": "demo-" + name})
			att := d.credential(name).register(d.origins, options(str(o, "options_json")))
			b.post("/me/webauthn/enrollments/"+str(o, "registration_id")+"/confirm", att)
		}
		r = login()
	}
	require(str(r, "state") == "mfa_required", "expected IAM MFA challenge")
	r = b.verifyMFA(r)
	require(str(r, "state") == "authenticated", "IAM did not grant full session")
	s := obj(r["session"])
	require(s["restricted"] == false, "restricted session")
	user := str(s, "user_id")
	var saved string
	if d.read("user/"+name, &saved) {
		require(saved == user, "unexpected IAM user")
	}
	d.put("user/"+name, user)
	auth, e := time.Parse(time.RFC3339Nano, str(s, "auth_time"))
	check(e)
	until := auth.Add(8 * time.Minute)
	for _, field := range []string{"idle_expires_at", "absolute_expires_at"} {
		t, e := time.Parse(time.RFC3339Nano, str(s, field))
		check(e)
		if t.Before(until) {
			until = t
		}
	}
	d.put("session-until/"+name, until)
	if name == "seller" {
		require(str(s, "seller_account_id") == d.required("seller-account"), "seller scope mismatch")
	}
}
func (b *browser) verifyMFA(r object) object {
	d, name := b.d, b.name
	p := "/auth/challenges/" + str(r, "challenge_id")
	o := b.api("GET", p, "", nil)
	var answer object
	if name == "seller" {
		answer = object{"method": "totp", "code": d.freshTOTP(name)}
	} else {
		opt := options(str(o, "options_json"))
		require(str(opt, "rpId") == d.origins.rpID(), "login RP mismatch")
		if allowed, ok := opt["allowCredentials"].([]any); ok && len(allowed) > 0 {
			offered := false
			for _, entry := range allowed {
				if obj(entry)["id"] == b64.EncodeToString(d.credential(name).ID) {
					offered = true
				}
			}
			require(offered, "credential not offered by IAM")
		}
		d.chargeMFA(name, nil)
		answer = object{"assertion": d.assert(name, raw(str(opt, "challenge")))}
	}
	return b.post(p+"/verify", answer)
}

type iamMail struct{ To, Subject, Body string }

func matchesMail(b []byte, recipient, subject string) bool {
	var m iamMail
	require(decodeJSON(b, &m) == nil, "invalid IAM security mail")
	return m.To == recipient && m.Subject == subject
}
func (d *driver) mail(recipient, subject string) string {
	return d.waitForMail(recipient, func() []byte { return d.mailBody(recipient, subject) })
}

func (d *driver) waitForMail(recipient string, read func() []byte) string {
	var body []byte
	d.waitFor("IAM mail for "+recipient, 90*time.Second, func() bool {
		body = read()
		return body != nil
	})
	return mailToken(body)
}

func mailToken(body []byte) string {
	var m iamMail
	require(decodeJSON(body, &m) == nil, "invalid IAM security mail")
	_, s, ok := strings.Cut(m.Body, "：")
	require(ok && len(raw(s)) == 32, "unexpected IAM security mail")
	return s
}
func form(v url.Values) []byte { return []byte(v.Encode()) }
func standard(s string) []byte { b, e := base64.StdEncoding.DecodeString(s); check(e); return b }
