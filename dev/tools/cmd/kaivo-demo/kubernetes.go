package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const fixtureService = "demo-fixtures"

func setting(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

type kubeEnvironment struct {
	ctx              context.Context
	command          []string
	namespaces       map[string]string
	syncDelay        time.Duration
	base, simPort    int
	seed, dir        string
	forwards         map[string]*serviceForward
	serviceByAddress map[string]string
	launchForward    func(context.Context, string, string, []string) (*forward, error)
	trace            func(string)
	lastBackend      time.Time
	// Within one invocation all consumers use the same owner secret and forwarding endpoint.
	databases map[string]*pgx.ConnConfig
	configs   map[string]map[string]string
	materials map[string][]byte
}

var mailpitID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func newKubeEnvironment(ctx context.Context, dir string, trace func(string)) *kubeEnvironment {
	k := &kubeEnvironment{
		ctx: ctx, dir: dir, seed: os.Getenv("KAIVO_STAGING_SEED"), trace: trace,
		command:          strings.Fields(setting("KUBECTL", "kubectl")),
		namespaces:       map[string]string{},
		forwards:         map[string]*serviceForward{},
		serviceByAddress: map[string]string{},
		databases:        map[string]*pgx.ConnConfig{},
		configs:          map[string]map[string]string{},
		materials:        map[string][]byte{},
	}
	k.launchForward = k.forward
	require(len(k.command) > 0, "empty KUBECTL")
	var err error
	k.syncDelay, err = time.ParseDuration(setting("AIPAY_DEMO_CONFIGMAP_SYNC", "75s"))
	require(err == nil && k.syncDelay > 0 && k.syncDelay <= 10*time.Minute, "invalid AIPAY_DEMO_CONFIGMAP_SYNC (use a duration up to 10m)")
	k.base, err = strconv.Atoi(setting("AIPAY_DEMO_PORT_BASE", "18080"))
	require(err == nil && k.base > 0 && k.base <= 65535-7, "invalid AIPAY_DEMO_PORT_BASE")
	k.simPort, err = strconv.Atoi(setting("AIPAY_DEMO_SIM_PORT", "9080"))
	require(err == nil && k.simPort >= 1 && k.simPort <= 65535, "invalid AIPAY_DEMO_SIM_PORT (expected 1..65535)")
	require(k.simPort < k.base || k.simPort > k.base+7, "AIPAY_DEMO_SIM_PORT overlaps the eight ports starting at AIPAY_DEMO_PORT_BASE")
	for _, domain := range []string{"business", "sim", "ledger", "reconciliation"} {
		name := setting("AIPAY_DEMO_NS_"+strings.ToUpper(domain), "kaivo-"+domain)
		require(len(name) <= 63 && dnsLabel.MatchString(name), "invalid namespace for "+domain)
		k.namespaces[domain] = name
	}
	return k
}
func (*kubeEnvironment) native() bool                { return false }
func (d *driver) requireNative(capability string)    { require(d.native(), capability+"：仅本机栈") }
func (*kubeEnvironment) stack(args ...string) []byte { stop("%s：仅本机栈", args[0]); return nil }
func (*kubeEnvironment) cursorMoved(string, string) bool {
	stop("ledger-reader 日志：仅本机栈")
	return false
}
func (k *kubeEnvironment) local(offset int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(k.base+offset))
}
func (k *kubeEnvironment) addresses() endpoints {
	sim := fmt.Sprintf("http://127.0.0.1:%d", k.simPort)
	suffix := "." + k.namespaces["sim"] + ".svc.cluster.local"
	return endpoints{k.local(0), k.local(1), k.local(2), sim, "http://upstream-sim" + suffix + ":9080", "http://127.0.0.1:9080", "http://" + fixtureService + suffix + ":8082"}
}
func (k *kubeEnvironment) bin(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, k.command[0], append(slices.Clone(k.command[1:]), args...)...)
}
func (k *kubeEnvironment) invoke(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c := k.bin(ctx, args...)
	c.Stdin = bytes.NewReader(stdin)
	c.Stderr = io.Discard
	return c.Output()
}
func (k *kubeEnvironment) kubectl(stdin []byte, ns, verb string, args ...string) []byte {
	out, err := k.invoke(k.ctx, stdin, append([]string{"-n", ns, verb}, args...)...)
	// Tool output and arguments can contain credentials or complete manifests.
	require(err == nil, "kubectl "+verb+" failed in "+ns)
	return out
}
func (k *kubeEnvironment) data(ns, kind, name string) map[string]string {
	var v struct{ Data map[string]string }
	out := k.kubectl(nil, ns, "get", kind, name, "-o", "json")
	require(json.Unmarshal(out, &v) == nil && v.Data != nil, "invalid "+kind+" "+name)
	return v.Data
}
func (k *kubeEnvironment) field(ns, kind, name, key string) []byte {
	value, ok := k.data(ns, kind, name)[key]
	require(ok && value != "", "missing "+name+"/"+key)
	if kind == "secret" {
		b, e := base64.StdEncoding.Strict().DecodeString(value)
		require(e == nil, "invalid Secret field "+name+"/"+key)
		return b
	}
	return []byte(value)
}
func (k *kubeEnvironment) domain(service string) string {
	switch service {
	case "iam", "backend", "payment", "notifier":
		return "business"
	case "devcollection", "devchain":
		return "sim"
	case "ledger", "reconciliation":
		return service
	}
	stop("%s：仅本机栈", service)
	return ""
}
func (k *kubeEnvironment) env(service string) map[string]string {
	if m := k.configs[service]; m != nil {
		return m
	}
	ns := k.namespaces[k.domain(service)]
	m := k.data(ns, "configmap", service+"-config")
	if service == "backend" {
		m["AIPAY_TELEGRAM_WEBHOOK_SECRET"] = string(k.field(ns, "secret", "backend-private", "telegram-webhook-secret"))
	}
	k.configs[service] = m
	return m
}
func (k *kubeEnvironment) input(name string) []byte {
	if name == "seller-reviews.json" {
		ns := k.namespaces["business"]
		return k.field(ns, "configmap", "payment-inputs", name)
	}
	if b, ok := k.materials[name]; ok {
		return b
	}
	var b []byte
	switch name {
	case "deposits/scenario.json":
		return k.field(k.namespaces["sim"], "configmap", "deposit-dataset", "scenario.json")
	case "handoff/query.json":
		b = k.field(k.namespaces["reconciliation"], "secret", "reconciliation-handoff", "query.json")
	case "handoff/epay.json":
		b = k.field(k.namespaces["reconciliation"], "secret", "reconciliation-handoff", "epay.json")
	case "handoff/trade.json":
		// The existing simulator Secret already holds the form-md5 trade key.
		var cfg struct {
			Accounts []struct {
				ID     string
				Style  string
				Shared string `json:"shared_secret"`
			}
		}
		require(decodeJSON(k.input("inputs/upstream-sim/config.json"), &cfg) == nil, "invalid upstream-sim-private/config.json")
		for _, a := range cfg.Accounts {
			if a.ID == simulatorAccount(md5Channel) && a.Style == "form-md5" && a.Shared != "" {
				b = encoded(map[string]string{"shared": a.Shared})
				break
			}
		}
		require(b != nil, "missing md5-demo trade credential in upstream-sim-private/config.json")
	case "inputs/upstream-sim/config.json":
		b = k.field(k.namespaces["sim"], "secret", "upstream-sim-private", "config.json")
	case "handoff/platform-public.pem", "handoff/ledger-report-public.pem":
		b = k.field(k.namespaces["business"], "configmap", "kaivo-signing-public", filepath.Base(name))
	default:
		stop("%s：仅本机栈", name)
	}
	k.materials[name] = b
	return b
}
func (k *kubeEnvironment) database(owner string) *pgx.ConnConfig {
	domain := k.domain(owner)
	_, err := k.ensureForward(k.ctx, domain+"-pg-rw")
	check(err)
	if cfg := k.databases[owner]; cfg != nil {
		return cfg.Copy()
	}
	raw := k.field(k.namespaces[domain], "secret", "pg-"+owner, "uri")
	u, e := url.Parse(string(raw))
	require(e == nil && (u.Scheme == "postgresql" || u.Scheme == "postgres") && u.User != nil && u.User.Username() == owner && u.Path == "/aipay_"+owner, "invalid pg-"+owner+" owner URI")
	// Preserve the TLS server name from the Secret while dialing only the
	// loopback port. pgx may also construct fallbacks for sslmode=prefer.
	cfg, e := pgx.ParseConfig(string(raw))
	require(e == nil, "invalid "+owner+" evidence connection")
	offset := map[string]int{"business": 5, "ledger": 6, "reconciliation": 7}[domain]
	cfg.Host, cfg.Port = "127.0.0.1", uint16(k.base+offset)
	for _, f := range cfg.Fallbacks {
		f.Host, f.Port = cfg.Host, cfg.Port
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	k.databases[owner] = cfg
	return cfg.Copy()
}
func (k *kubeEnvironment) callbackCIDRs() []string {
	// The callback originates from the simulator Pod, not its ClusterIP.
	var pods struct {
		Items []struct {
			Metadata struct{ DeletionTimestamp *string }
			Status   struct{ Phase, PodIP string }
		}
	}
	decode(k.kubectl(nil, k.namespaces["sim"], "get", "pods", "-l", "app.kubernetes.io/name=upstream-sim", "-o", "json"), &pods)
	var cidrs []string
	for _, p := range pods.Items {
		if p.Metadata.DeletionTimestamp != nil || p.Status.Phase != "Running" {
			continue
		}
		ip, e := netip.ParseAddr(p.Status.PodIP)
		require(e == nil, "invalid upstream-sim Pod IP")
		cidrs = append(cidrs, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	require(len(cidrs) > 0, "missing running upstream-sim Pod")
	slices.Sort(cidrs)
	return cidrs
}
func (k *kubeEnvironment) doHTTP(client *http.Client, req *http.Request) (*http.Response, error) {
	service := k.serviceByAddress[req.URL.Host]
	restarted, err := k.ensureForward(req.Context(), service)
	if service == "backend" {
		k.lastBackend = time.Now()
	}
	if err != nil {
		return nil, err
	}
	if restarted {
		// A pooled connection can still point at the previous kubectl process.
		localHTTP.CloseIdleConnections()
	}
	return client.Do(req)
}

const backendKeepAliveInterval = 30 * time.Second

// Run probes on the polling goroutine so a restart cannot race request dispatch or teardown.
func (k *kubeEnvironment) pause(delay time.Duration) {
	end := time.Now().Add(delay)
	for !k.lastBackend.IsZero() {
		next := k.lastBackend.Add(backendKeepAliveInterval)
		if !next.Before(end) {
			break
		}
		k.sleepUntil(next)
		k.touchBackend()
	}
	k.sleepUntil(end)
}

func (k *kubeEnvironment) sleepUntil(end time.Time) {
	select {
	case <-k.ctx.Done():
		stop("interrupted during Kubernetes wait")
	case <-time.After(time.Until(end)):
	}
}

func (k *kubeEnvironment) touchBackend() {
	ctx, cancel := context.WithTimeout(k.ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+k.local(0)+"/health/live", nil)
	check(err)
	res, err := k.doHTTP(localHTTP, req)
	if err != nil {
		k.trace("Backend keep-alive failed")
		return
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(res.Body, 4096)); err != nil || res.StatusCode != http.StatusOK {
		k.trace(fmt.Sprintf("Backend keep-alive failed (HTTP %d)", res.StatusCode))
	}
}

func (k *kubeEnvironment) cashierClient() (*http.Client, string) {
	return localHTTP, net.JoinHostPort("127.0.0.1", strconv.Itoa(k.simPort))
}

func (k *kubeEnvironment) getLocal(address, path string, limit int64) []byte {
	req, e := http.NewRequestWithContext(k.ctx, http.MethodGet, "http://"+address+path, nil)
	check(e)
	res, e := k.doHTTP(localHTTP, req)
	require(e == nil, "forwarded HTTP endpoint unavailable")
	defer res.Body.Close()
	require(res.StatusCode == http.StatusOK, fmt.Sprintf("forwarded HTTP endpoint returned %d", res.StatusCode))
	b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	require(e == nil && int64(len(b)) <= limit, "invalid forwarded HTTP response")
	return b
}
func (k *kubeEnvironment) fixtureRecord(name string) []byte {
	return k.getLocal(k.local(4), "/"+name, 32<<20)
}
func (k *kubeEnvironment) mailBody(recipient, subject string) []byte {
	for start := 0; ; {
		var page struct {
			Total    int
			Messages []struct {
				ID string
				To []struct{ Address string }
			}
		}
		decode(k.getLocal(k.local(3), fmt.Sprintf("/api/v1/messages?start=%d&limit=50", start), 2<<20), &page)
		for _, m := range page.Messages {
			if !slices.ContainsFunc(m.To, func(to struct{ Address string }) bool { return to.Address == recipient }) {
				continue
			}
			require(mailpitID.MatchString(m.ID), "invalid Mailpit message id")
			var detail struct{ Text string }
			decode(k.getLocal(k.local(3), "/api/v1/message/"+m.ID, 1<<20), &detail)
			var body iamMail
			if json.Unmarshal([]byte(detail.Text), &body) == nil && body.To == recipient && body.Subject == subject {
				return []byte(detail.Text)
			}
		}
		start += len(page.Messages)
		if len(page.Messages) == 0 || start >= page.Total {
			return nil
		}
	}
}

func (k *kubeEnvironment) syncMerchantKeys() {
	token := k.field(k.namespaces["business"], "secret", "backend-private", "bot-token")
	cfg := fixtureConfig{Webhook: k.env("backend")["AIPAY_TELEGRAM_WEBHOOK_URL"]}
	for path, dest := range map[string]*json.RawMessage{"merchant-key.json": &cfg.V1, "merchant-v2.json": &cfg.V2} {
		b, e := os.ReadFile(filepath.Join(k.dir, path))
		if os.IsNotExist(e) {
			continue
		}
		check(e)
		*dest = b
	}
	req, err := http.NewRequestWithContext(k.ctx, "POST", "http://"+k.local(4)+"/config", bytes.NewReader(encoded(cfg)))
	check(err)
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", "application/json")
	res, err := k.doHTTP(localHTTP, req)
	require(err == nil, "fixture configuration endpoint unavailable")
	defer res.Body.Close()
	require(res.StatusCode == http.StatusNoContent, "fixture configuration rejected")
}
