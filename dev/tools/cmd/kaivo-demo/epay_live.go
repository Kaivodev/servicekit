package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	livePhase        = "epay-live"
	liveOffPhase     = "epay-live-off"
	liveVariant      = "epay_v1_live"
	liveFileEnv      = "KAIVO_DEMO_EPAY_LIVE_FILE"
	liveCreateFailed = "epay-live merchant create failed"
)

type liveCredentials struct {
	gateway  *url.URL
	pid, key string
}

var positivePID = regexp.MustCompile(`^[1-9][0-9]*$`)

func readLiveCredentials() liveCredentials {
	path := os.Getenv(liveFileEnv)
	require(path != "", liveFileEnv+" is required for epay-live")
	// Check the open descriptor before reading. A FIFO must never block setup.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	require(err == nil, "cannot open "+liveFileEnv)
	defer f.Close()
	info, err := f.Stat()
	require(err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0,
		liveFileEnv+" requires a private regular file")
	b, err := io.ReadAll(f)
	require(err == nil, "cannot read "+liveFileEnv)
	values := map[string]string{}
	for line := range strings.SplitSeq(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if s := strings.TrimSpace(line); s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		require(ok, "invalid assignment in "+liveFileEnv)
		switch name {
		case "EPAY_TEST_BASE_URL", "EPAY_TEST_PID", "EPAY_TEST_KEY":
		default:
			stop("unknown variable in " + liveFileEnv)
		}
		_, seen := values[name]
		require(!seen, "duplicate "+name)
		if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
			require(len(value) >= 2 && value[len(value)-1] == value[0], "invalid "+name)
			value = value[1 : len(value)-1]
		} else {
			require(!strings.HasSuffix(value, "'") && !strings.HasSuffix(value, "\""), "invalid "+name)
		}
		values[name] = value
	}
	address := values["EPAY_TEST_BASE_URL"]
	u, err := url.Parse(address)
	require(err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		!strings.ContainsAny(address, "?#") && (u.EscapedPath() == "" || u.EscapedPath() == "/"), "invalid EPAY_TEST_BASE_URL")
	pid, key := values["EPAY_TEST_PID"], values["EPAY_TEST_KEY"]
	require(positivePID.MatchString(pid), "invalid EPAY_TEST_PID")
	require(key != "" && utf8.ValidString(key) && strings.IndexFunc(key, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) == -1, "invalid EPAY_TEST_KEY")
	return liveCredentials{u, pid, key}
}

func (c liveCredentials) fingerprint() string {
	return fmt.Sprintf("%x", sha256.Sum256(encoded([]string{c.gateway.String(), c.pid, c.key})))
}

func (d *driver) liveCredentials() liveCredentials {
	c := readLiveCredentials()
	require(c.fingerprint() == d.required(channelKey(liveVariant, "operator-file-sha")), "epay-live operator file changed since setup")
	return c
}

var percentEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// Decode valid escapes even beside a literal percent (common in error messages).
func anyURLDecoded(s string, match func(string) bool) bool {
	for {
		if match(s) {
			return true
		}
		if !strings.Contains(s, "%") {
			return false
		}
		next, err := url.PathUnescape(s)
		if err != nil {
			next = percentEscape.ReplaceAllStringFunc(s, func(escape string) string {
				b, _ := url.PathUnescape(escape)
				return b
			})
		}
		if next == s {
			return false
		}
		s = next
	}
}

func (c liveCredentials) containsKey(s string) bool {
	return anyURLDecoded(s, func(text string) bool { return strings.Contains(text, c.key) })
}

func (c liveCredentials) createFailure(reply object) string {
	if c.containsKey(fmt.Sprint(reply)) {
		return liveCreateFailed
	}
	var code string
	switch value := reply["code"].(type) {
	case json.Number:
		code = value.String()
	case string:
		code = fmt.Sprintf("%q", value)
	default:
		return liveCreateFailed
	}
	detail := "code=" + code
	if msg, ok := reply["msg"].(string); ok {
		detail += fmt.Sprintf(" msg=%q", msg)
	}
	if c.containsKey(detail) {
		return liveCreateFailed
	}
	return liveCreateFailed + " (" + detail + ")"
}

func (c liveCredentials) reportConfig() object {
	host := c.gateway.Hostname()
	if c.containsKey(host) {
		host = "<configured>"
	}
	return object{"gateway": host, "pid": "<configured>"}
}

func (d *driver) checkLivePrerequisites(action string) {
	c := readLiveCredentials()
	require(d.gatewayMode(), "epay-live requires gateway mode")
	if action == "run" {
		require(d.data["step/setup/"+channelStepName(liveVariant, "核验账户与启用")] != nil, "complete demo setup epay-live first")
	} else {
		require(d.data["step/setup/"+channelStepName(epayChannel, "核验账户与启用")] != nil, "complete demo setup channels first")
		// The final approved owner material is the manifest of the bound version,
		// even if a later packages run has replaced the local build directory.
		for _, code := range []string{epayChannel, epayChannel + "_verify"} {
			var r object
			require(d.read("write/setup/"+code+"/"+approvers[len(approvers)-1]+"/result", &r), "missing published "+code+" approval")
			p := obj(obj(r["material"])["plugin_version"])
			require(str(p, "plugin_version_id") == d.required("plugin/"+code), "published plugin version mismatch")
			requireLiveDomain(code, c.gateway.Hostname(), raw(str(p, "manifest_json")))
		}
	}
	k := channelKey(liveVariant, "operator-file-sha")
	fingerprint := c.fingerprint()
	if action == "setup" {
		d.value(k, func() string { return fingerprint })
	}
	require(d.required(k) == fingerprint, "epay-live operator file changed since setup")
}

func requireLiveDomain(code, host string, manifest []byte) {
	var m struct {
		Code    string
		Domains []string
	}
	decode(manifest, &m)
	require(m.Code == code, "published manifest code mismatch")
	for _, domain := range m.Domains {
		if strings.EqualFold(domain, host) {
			return
		}
	}
	stop("EPAY_TEST_BASE_URL host is absent from the published %s manifest domains", code)
}

func liveChannelSpec(c liveCredentials, timeout string) channelSpec {
	s := channelSetup(epayChannel, true, c.gateway.String(), timeout)
	s.name, s.minAmount, s.maxAmount, s.priority = "EPay 测试上游", "111", "111", 0
	s.tradeFile, s.queryFile = "", ""
	s.tradeConfig["pid"], s.queryConfig["pid"] = c.pid, c.pid
	s.tradeConfig["product_name"] = "Kaivo test"
	return s
}

func (d *driver) setupLiveEPay() {
	d.liveStep("测试上游通道配置", func() {
		d.evidence("配置", d.liveCredentials().reportConfig())
		d.login("operations")
	})
	d.setupChannel(liveVariant, true)
}

func liveOrderSettings() (string, time.Duration) {
	ip := setting("AIPAY_DEMO_EPAY_LIVE_CLIENT_IP", "127.0.0.1")
	require(net.ParseIP(ip) != nil, "invalid AIPAY_DEMO_EPAY_LIVE_CLIENT_IP")
	wait, err := time.ParseDuration(setting("AIPAY_DEMO_EPAY_LIVE_WAIT", "30m"))
	require(err == nil && wait >= 0, "invalid AIPAY_DEMO_EPAY_LIVE_WAIT")
	return ip, wait
}

// A payment instruction can contain an opaque token. Reject credentials even
// in escaped URL components before exposing the link to a terminal or report.
func (c liveCredentials) paymentLink(link string) string {
	u, err := url.Parse(link)
	require(err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil,
		"invalid epay-live payment link")
	unsafe := anyURLDecoded(link, func(text string) bool {
		return strings.Contains(text, c.key) || strings.ContainsFunc(text, unicode.IsControl)
	})
	require(!unsafe, "unsafe epay-live payment link")
	return link
}

// The terminal gets the original validated bytes. Checkpoints and reports keep
// only the origin and escaped path, even for an empty query or fragment.
func paymentLinkEvidence(link string) string {
	if i := strings.IndexAny(link, "?#"); i >= 0 {
		return link[:i]
	}
	return link
}

// Older drivers checkpointed the full payment link. Trim it before a resume
// can copy a previous step into state or publish it in another report.
func (d *driver) trimSavedLiveLinks() {
	trim := func(r *result) bool {
		link, _ := r.Evidence["pay_info"].(string)
		safe := paymentLinkEvidence(link)
		if safe == link {
			return false
		}
		r.Evidence["pay_info"] = safe
		return true
	}
	key := "step/" + livePhase + "/测试上游 商户下单"
	var r result
	if d.read(key, &r) && trim(&r) {
		d.put(key, r)
	}
	if d.scope == livePhase {
		for _, step := range d.history.Steps {
			trim(step)
		}
	}
}

func (d *driver) createLiveEPayOrder(number, ip string, creds liveCredentials) string {
	params := d.createParams(number, "1.11")
	params.Set("clientip", ip)
	params.Set("pid", d.required("pid/v1"))
	var merchant struct{ Key string }
	decode(file(filepath.Join(d.dir, "merchant-key.json")), &merchant)
	params.Set("sign_type", "MD5")
	params.Set("sign", v1Sign(params, merchant.Key))

	const path = "/mapi.php"
	status, body := d.browser("merchant").http("POST", path, path, "application/x-www-form-urlencoded", form(params), nil)
	var reply object
	require(decodeJSON(body, &reply) == nil, liveCreateFailed)
	if status != 200 || reply["code"] != json.Number("1") {
		stop("%s", creds.createFailure(reply))
	}
	field := "payurl"
	if reply[field] == nil || reply[field] == "" {
		field = "qrcode"
	}
	return creds.paymentLink(str(reply, field))
}

func (d *driver) runLiveEPay() {
	ip, limit := liveOrderSettings()
	t := tradeRun{d: d, name: "测试上游", proto: "v1", number: d.key(livePhase + "/order-number")}
	t.baseline()
	creds := d.liveCredentials()
	var link string
	created := t.step("商户下单", func() {
		clientIP := d.value(livePhase+"/client-ip", func() string { return ip })
		link = d.createLiveEPayOrder(t.number, clientIP, creds)
		t.readOrderRoute()
		d.evidence("pay_info", paymentLinkEvidence(link))
		d.evidence("提示", livePaymentPrompt)
	})
	t.order = str(created.Evidence, "订单 ID")
	t.step("等待主动查单", func() {
		prompt := func(ctx context.Context) {
			// On resume read the original instruction only if the ledger has
			// not observed payment. Never submit a second merchant order.
			rows, err := d.queryRows(ctx, "payment", "payment_orders", `SELECT COALESCE(data#>>'{payment_instruction,url}',
				data#>>'{payment_instruction,qrcode}') AS link FROM payment_orders
				WHERE id=$1 AND channel_account_id=$2 AND out_trade_no=$3`,
				t.order, d.required("uuid/"+channelKey(liveVariant, "channel")), t.number)
			require(ctx.Err() != context.DeadlineExceeded, "未付款")
			check(err)
			require(len(rows) == 1, "original epay-live order not found")
			if value, _ := rows[0]["link"].(string); value != "" {
				fmt.Println(livePaymentPrompt, creds.paymentLink(value))
			}
		}
		if link != "" {
			fmt.Println(livePaymentPrompt, link)
			prompt = nil
		}
		paid := waitLivePayment(d.ctx, limit, func(ctx context.Context) (any, error) {
			rows, err := d.queryRows(ctx, "ledger", "ledger_trade_reservations",
				"SELECT paid_verified_at FROM ledger_trade_reservations WHERE order_id=$1", t.order)
			if len(rows) == 0 {
				return nil, err
			}
			return rows[0]["paid_verified_at"], err
		}, prompt)
		d.evidence("paid_verified_at", paid)
	})
	d.login("seller")
	d.login("operations")
	t.release()
	t.step("交易网关执行记录", func() {
		rows := d.rows("payment", "payment_gateway_executions", `SELECT operation,category,upstream_code,occurred_at
			FROM payment_gateway_executions WHERE order_id=$1 AND operation IN ('create_payment','query_payment') ORDER BY occurred_at`, t.order)
		seen := map[string]bool{}
		for _, row := range rows {
			if code, ok := row["upstream_code"].(string); ok && creds.containsKey(code) {
				row["upstream_code"] = "<redacted>"
			}
			seen[str(row, "operation")] = true
		}
		d.evidence("payment_gateway_executions", rows)
		require(seen["create_payment"] && seen["query_payment"], "missing gateway create or query evidence")
	})
	d.disableLiveEPay()
}

func (d *driver) disableLiveEPay() {
	d.liveStep("停用测试上游通道", func() {
		ch := d.required("uuid/" + channelKey(liveVariant, "channel"))
		d.login("risk")
		risk := d.browser("risk")
		path := "/channel-accounts/" + ch
		current := risk.api("GET", path, "", nil)
		cfg := obj(current["configuration"])
		require(cfg["channel_account_id"] == ch && cfg["channel_code"] == epayChannel, "unexpected epay-live channel account")
		enabled, ok := cfg["enabled"].(bool)
		require(ok, "missing channel enabled flag")
		version := num(current, "control_version")
		require(version > 0, "invalid channel control version")
		d.evidence("channel_account_id", ch)
		if !enabled {
			d.evidence("结果", "已停用，跳过")
		} else {
			key := d.key(fmt.Sprintf("%s/disable/%s/%d", livePhase, ch, version))
			r := risk.api("POST", path+"/emergency-disable", key, object{
				"expected_control_version": version, "reason": "结束 EPay 测试上游联调",
			})
			require(r["channel_account_id"] == ch && num(r, "control_version") == version+1, "unexpected channel disable result")
			version++
			d.evidence("结果", "已停用")
		}
		d.evidence("control_version", version)
	})
}

const livePaymentPrompt = "请在浏览器打开并付款 1.11 元"

func waitLivePayment(ctx context.Context, limit time.Duration, lookup func(context.Context) (any, error), prompt func(context.Context)) any {
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		paid, err := lookup(ctx)
		require(ctx.Err() != context.DeadlineExceeded, "未付款")
		check(err)
		if paid != nil {
			return paid
		}
		if prompt != nil {
			prompt(ctx)
			prompt = nil
		}
		require(limit > 0, "未付款")
		select {
		case <-ctx.Done():
			require(ctx.Err() != context.DeadlineExceeded, "未付款")
			stop("演示已中断")
		case <-tick.C:
		}
	}
}
