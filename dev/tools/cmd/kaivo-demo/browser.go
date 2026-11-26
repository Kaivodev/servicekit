package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"

	"slices"
	"strings"
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
	b := &browser{d: d, name: name, origin: adminOrigin, addr: d.addresses().admin, prefix: "/api/v1/platform", cookies: map[string]string{}}
	if name == "seller" {
		b.origin = "https://seller.aipay.test"
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
	res, e := localHTTP.Do(req)
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
	return b.portalAPI("POST", c.path, c.key, c.body, "", &c)
}

func (b *browser) portalAPI(method, path, key string, body object, grant string, recent *portalCommand) object {
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
	postReleaseEntry := b.d.scope == "dispute-refund-after-release" && method == "POST" && path == "/disputes"
	if postReleaseEntry && (code == 404 || code == 405 || code == 501) {
		stop("已放币争议登记缺入口：POST %s 返回 HTTP %d", label, code)
	}
	if b.d.liveEPay {
		// A malformed envelope or backend diagnostic may echo a submitted value.
		require(decodeJSON(out, &env) == nil, "invalid portal response")
	} else {
		decode(out, &env)
	}
	if recent != nil && env.Code == 428 && (code == 200 || code == 428) {
		digest := raw(headers.Get("X-Command-SHA256"))
		require(len(digest) == len(recent.digest), "missing canonical reauthentication digest")
		copy(recent.digest[:], digest)
		return b.apiGrant(method, path, key, body, b.grant(*recent))
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
		if b.d.liveEPay {
			stop("%s %s → HTTP %d, backend code %d", method, label, code, env.Code)
		}
		stop("%s %s → HTTP %d, backend code %d (%s)", method, label, code, env.Code, env.Message)
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
	upload := path == "/plugins" || path == "/verification/plugins" || path == "/channel-accounts/credentials" ||
		path == "/verification/credentials" && (d.liveEPay || !d.native() || d.gatewayMode())
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

// IAM charges every TOTP verification, successful or not, to a fixed
// per-account window (default 5 attempts per 5 minutes). Stay one below the
// limit and wait for the window to expire instead of tripping the lockout.
const (
	totpWindow = 5*time.Minute + 2*time.Second
	totpBudget = 4
)

func (d *driver) freshTOTP(name string) string {
	var window struct {
		Start time.Time
		Count int
	}
	d.read("totp-window/"+name, &window)
	if window.Count >= totpBudget {
		if wait := time.Until(window.Start.Add(totpWindow)); wait > 0 {
			d.trace(fmt.Sprintf("waiting %s for the IAM TOTP attempt window of %s", wait.Round(time.Second), name))
			d.sleep(wait)
		}
	}
	var last int64
	d.read("totp-step/"+name, &last)
	for time.Now().Unix()/30 <= last || time.Now().Unix()%30 >= 28 {
		d.sleep(250 * time.Millisecond)
	}
	now := time.Now()
	if !now.Before(window.Start.Add(totpWindow)) {
		window.Start, window.Count = now, 0
	}
	window.Count++
	d.put("totp-window/"+name, window)
	d.put("totp-step/"+name, now.Unix()/30)
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
	r := login()
	if str(r, "state") == "setup_required" {
		if name == "seller" {
			o := b.post("/me/mfa/totp/enrollments", object{})
			d.put("totp/"+name, qrSecret(raw(str(o, "qr_code_png"))))
			b.post("/me/mfa/totp/confirm", object{"enrollment_id": str(o, "enrollment_id"), "code": d.freshTOTP(name)})
		} else {
			o := b.post("/me/webauthn/enrollments", object{"name": "demo-" + name})
			att := d.credential(name).register(options(str(o, "options_json")))
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
		require(str(opt, "rpId") == rp, "login RP mismatch")
		if allowed, ok := opt["allowCredentials"].([]any); ok && len(allowed) > 0 {
			offered := false
			for _, entry := range allowed {
				if obj(entry)["id"] == b64.EncodeToString(d.credential(name).ID) {
					offered = true
				}
			}
			require(offered, "credential not offered by IAM")
		}
		answer = object{"assertion": d.assert(name, raw(str(opt, "challenge")))}
	}
	return b.post(p+"/verify", answer)
}

type iamMail struct{ To, Subject, Body string }

func matchesMail(b []byte, recipient, subject string) bool {
	var m iamMail
	decode(b, &m)
	return m.To == recipient && m.Subject == subject
}
func (d *driver) mail(name, subject string) string {
	var body []byte
	waitFor("IAM mail for "+name, 90*time.Second, func() bool {
		body = d.mailBody(d.email(name), subject)
		return body != nil
	})
	var m iamMail
	decode(body, &m)
	_, s, ok := strings.Cut(m.Body, "：")
	require(ok && len(raw(s)) == 32, "unexpected IAM security mail")
	return s
}
func form(v url.Values) []byte { return []byte(v.Encode()) }
func standard(s string) []byte { b, e := base64.StdEncoding.DecodeString(s); check(e); return b }
