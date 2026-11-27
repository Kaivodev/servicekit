package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type object = map[string]any

var b64 = base64.RawURLEncoding

type failure struct {
	reason                   string
	method, path, message    string
	httpStatus, businessCode int
}

func stop(format string, a ...any) { panic(failure{reason: fmt.Sprintf(format, a...)}) }
func check(e error) {
	if e != nil {
		stop("%s", e)
	}
}
func require(ok bool, s string) {
	if !ok {
		stop("%s", s)
	}
}
func encoded(v any) []byte { b, e := json.Marshal(v); check(e); return b }
func decode(b []byte, v any) {
	check(decodeJSON(b, v))
}
func decodeJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid trailing data")
	}
	return nil
}
func obj(v any) object { m, ok := v.(map[string]any); require(ok, "missing response object"); return m }
func str(m object, k string) string {
	s, ok := m[k].(string)
	require(ok && s != "", "missing "+k)
	return s
}
func num(m object, k string) int64 {
	n, ok := m[k].(json.Number)
	require(ok, "missing number "+k)
	v, e := n.Int64()
	check(e)
	return v
}
func raw(s string) []byte {
	b, e := b64.Strict().DecodeString(s)
	require(e == nil, "invalid base64url field")
	return b
}
func id() string              { return uuid.Must(uuid.NewV7()).String() }
func random(n int) []byte     { v := make([]byte, n); _, e := rand.Read(v); check(e); return v }
func file(path string) []byte { b, e := os.ReadFile(path); check(e); return b }
func atomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".writing-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}

type result struct {
	Name     string   `json:"step"`
	Status   string   `json:"status"`
	Requests []string `json:"requests,omitempty"`
	Evidence object   `json:"evidence,omitempty"`
	Error    string   `json:"error,omitempty"`
}
type report struct {
	Scenario, Started, Logs string
	RefundFlow              string   `json:"refund_flow,omitempty"`
	Checks                  []string `json:"checks,omitempty"`
	SourceNotes             []string `json:"source_notes,omitempty"`
	Steps                   []*result
}
type driver struct {
	ctx context.Context
	demoEnvironment
	root, repo, dir, scope string
	output                 string
	liveEPay               bool
	data                   map[string]json.RawMessage
	history                report
	active                 *result
	browsers               map[string]*browser
}

func (d *driver) save()               { check(atomic(filepath.Join(d.dir, "state.json"), encoded(d.data))) }
func (d *driver) put(k string, v any) { d.data[k] = encoded(v); d.save() }
func (d *driver) read(k string, v any) bool {
	b, ok := d.data[k]
	if ok {
		decode(b, v)
	}
	return ok
}
func (d *driver) value(k string, f func() string) string {
	var s string
	if !d.read(k, &s) {
		s = f()
		d.put(k, s)
	}
	return s
}
func (d *driver) key(k string) string { return d.value("uuid/"+k, id) }
func (d *driver) required(k string) string {
	var s string
	require(d.read(k, &s) && s != "", "missing setup result "+k)
	return s
}
func (d *driver) trace(s string) {
	if d.active != nil {
		d.active.Requests = append(d.active.Requests, s)
	}
}
func (d *driver) evidence(k string, v any) { d.active.Evidence[k] = v }
func (d *driver) report() {
	out := filepath.Join(d.dir, "reports", d.history.Scenario)
	reportJSON := func(v any) []byte {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(!d.liveEPay)
		check(enc.Encode(v))
		return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	b := reportJSON(d.history)
	check(atomic(out+".json", b))
	var md strings.Builder
	logLabel := "日志目录"
	if !d.native() {
		logLabel = "服务日志"
	}
	fmt.Fprintf(&md, "# %s\n\n%s\n\n%s %s\n", d.history.Scenario, d.history.Started, logLabel, d.history.Logs)
	if len(d.history.Checks) > 0 {
		fmt.Fprint(&md, "\n## 验收步骤与证据\n\n")
		for _, item := range d.history.Checks {
			fmt.Fprintln(&md, "-", item)
		}
		fmt.Fprint(&md, "\n## 服务端源码疑点（待实测）\n\n")
		for _, item := range d.history.SourceNotes {
			fmt.Fprintln(&md, "-", item)
		}
	}
	for _, s := range d.history.Steps {
		fmt.Fprintf(&md, "\n## %s · %s\n\n", s.Name, s.Status)
		for _, r := range s.Requests {
			fmt.Fprintf(&md, "- %s\n", r)
		}
		if s.Error != "" {
			fmt.Fprintln(&md, "\n"+s.Error)
		}
		if len(s.Evidence) > 0 {
			b := reportJSON(s.Evidence)
			fmt.Fprintf(&md, "\n```json\n%s\n```\n", b)
		}
	}
	check(atomic(out+".md", []byte(md.String())))
	if d.output != "" {
		data := []byte(md.String())
		if strings.EqualFold(filepath.Ext(d.output), ".json") {
			data = b
		}
		check(atomic(d.output, data))
	}
}
func (d *driver) liveStep(name string, f func()) { d.executeStep(name, "", f) }
func (d *driver) step(name string, f func())     { d.executeStep(name, d.scope, f) }
func (d *driver) executeStep(name, checkpointScope string, f func()) {
	k := "step/" + checkpointScope + "/" + name
	r := &result{Name: name, Status: "running", Evidence: object{}}
	replaced := false
	for i, previous := range d.history.Steps {
		if previous.Name == name {
			d.history.Steps[i] = r
			replaced = true
			break
		}
	}
	if !replaced {
		d.history.Steps = append(d.history.Steps, r)
	}
	d.active = r
	if checkpointScope != "" && d.read(k, r) {
		d.report()
		return
	}
	defer func() {
		if v := recover(); v != nil {
			if reason, ok := v.(failure); ok {
				r.Error = reason.reason
				r.Status = "failed"
				if strings.HasPrefix(reason.reason, "缺样本：") {
					r.Status = "缺样本"
				}
				d.report()
			}
			panic(v)
		}
	}()
	f()
	r.Status = "ok"
	if checkpointScope != "" {
		d.put(k, r)
	}
	d.report()
}
func envFile(p string) map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(string(file(p)), "\n") {
		if line != "" {
			k, v, ok := strings.Cut(line, "=")
			require(ok, "invalid stack env")
			m[k] = v
		}
	}
	return m
}
func command(dir string, env []string, bin string, args ...string) []byte {
	c := exec.Command(bin, args...)
	c.Dir = dir
	c.Env = env
	b, e := c.Output()
	if e != nil {
		stop("%s %s failed (%v)", filepath.Base(bin), strings.Join(args[:min(1, len(args))], " "), e)
	}
	return b
}
func (d *driver) refreshMarket() {
	if d.native() {
		d.trace("stack.py refresh-market")
	} else {
		d.trace("kaivo-stagingseed market · server-side apply 并等待 ConfigMap 投射")
	}
	d.demoEnvironment.refreshMarket()
	if k, ok := d.demoEnvironment.(*kubeEnvironment); ok {
		var quote struct{ Minute time.Time }
		decode(k.field(k.namespaces["business"], "configmap", "payment-inputs", "rate.json"), &quote)
		require(!quote.Minute.IsZero(), "missing refreshed market minute")
		waitFor("ledger to import the refreshed USDT/USD observation", time.Minute, func() bool {
			return len(d.rows("ledger", "ledger_usd_rates", "SELECT version FROM ledger_usd_rates WHERE asset='USDT' AND observed_at=$1 LIMIT 1", quote.Minute)) == 1
		})
	}
}
func (d *driver) stack(args ...string) []byte {
	d.trace("stack.py " + strings.Join(args, " "))
	return d.demoEnvironment.stack(args...)
}
func (d *driver) owner(service, dbvar string, args ...string) []byte {
	d.trace(service + " " + strings.Join(args[:min(2, len(args))], " "))
	return d.demoEnvironment.owner(service, dbvar, args...)
}
func (d *driver) declaration(name string, v any) string {
	p := filepath.Join(d.dir, "declarations", name+".json")
	check(atomic(p, encoded(v)))
	return p
}
func (d *driver) sleep(delay time.Duration) {
	select {
	case <-time.After(delay):
	case <-d.ctx.Done():
		stop("演示已中断")
	}
}

func waitFor(why string, limit time.Duration, f func() bool) {
	if !pollUntil(limit, f) {
		stop("timed out waiting for %s", why)
	}
}
func pollUntil(limit time.Duration, f func() bool) bool {
	end := time.Now().Add(limit)
	for {
		if f() {
			return true
		}
		if !time.Now().Before(end) {
			return false
		}
		time.Sleep(400 * time.Millisecond)
	}
}
func newDriver(root, repo, scope string) *driver {
	return driverAt(root, repo, scope, filepath.Join(root, "demo"))
}
func driverAt(root, repo, scope, dir string) *driver {
	d := &driver{ctx: context.Background(), root: root, repo: repo, dir: dir, scope: scope, data: map[string]json.RawMessage{}, browsers: map[string]*browser{}, history: report{Scenario: scope, Started: time.Now().UTC().Format(time.RFC3339), Logs: filepath.Join(root, "logs")}}
	// Automatic-refund checkpoints contain different orders, approvals and balance
	// baselines. Retain them and the shared setup while starting a manual sample.
	switch scope {
	case "refund-before-release", "refund-after-release", "dispute-refund-before-release", "dispute-refund-after-release", "refund-insufficient":
		d.scope += "/manual"
		d.history.RefundFlow = "manual"
	}
	d.demoEnvironment = nativeEnvironment{root, repo, d.dir}
	b, e := os.ReadFile(filepath.Join(d.dir, "state.json"))
	if e == nil {
		decode(b, &d.data)
	} else if !errors.Is(e, os.ErrNotExist) {
		check(e)
	}
	previous, e := os.ReadFile(filepath.Join(d.dir, "reports", scope+".json"))
	if e == nil {
		var saved report
		decode(previous, &saved)
		if saved.Scenario == scope && saved.RefundFlow == d.history.RefundFlow {
			d.history = saved
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		check(e)
	}
	return d
}
