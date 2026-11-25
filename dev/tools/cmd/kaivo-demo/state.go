package main

import (
	"bytes"
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

type failure struct{ reason string }

func stop(format string, a ...any) { panic(failure{fmt.Sprintf(format, a...)}) }
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
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	check(dec.Decode(v))
	require(dec.Decode(new(any)) == io.EOF, "invalid trailing data")
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
	Checks                  []string `json:"checks,omitempty"`
	SourceNotes             []string `json:"source_notes,omitempty"`
	Steps                   []*result
}
type driver struct {
	root, repo, dir, scope string
	output                 string
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
	out := filepath.Join(d.dir, "reports", d.scope)
	b, e := json.MarshalIndent(d.history, "", "  ")
	check(e)
	check(atomic(out+".json", b))
	var md strings.Builder
	fmt.Fprintf(&md, "# %s\n\n%s\n\n日志目录 %s\n", d.scope, d.history.Started, d.history.Logs)
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
			b, e := json.MarshalIndent(s.Evidence, "", "  ")
			check(e)
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
func (d *driver) liveStep(name string, f func()) { d.executeStep(name, false, f) }
func (d *driver) step(name string, f func())     { d.executeStep(name, true, f) }
func (d *driver) executeStep(name string, checkpoint bool, f func()) {
	k := "step/" + d.scope + "/" + name
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
	if checkpoint && d.read(k, r) {
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
	if checkpoint {
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
func (d *driver) env(s string) map[string]string {
	return envFile(filepath.Join(d.root, "env", s+".env"))
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
func (d *driver) stack(args ...string) []byte {
	d.trace("stack.py " + strings.Join(args, " "))
	return command(d.repo, os.Environ(), "python3", append([]string{"-B", filepath.Join(d.repo, "dev/native/stack.py")}, args...)...)
}
func (d *driver) owner(service, dbvar string, args ...string) []byte {
	d.trace(service + " " + strings.Join(args[:min(2, len(args))], " "))
	var dsn string
	if dbvar == sellersDatabase {
		dsn = d.env("iam-sellers")[dbvar]
	} else {
		dsn = d.env(service + "-migrate")["AIPAY_DATABASE_URL"]
	}
	require(dsn != "", "missing "+service+" ceremony connection")
	list := []string{"PATH=" + os.Getenv("PATH"), dbvar + "=" + dsn}
	if dbvar == "AIPAY_IAM_BOOTSTRAP_DATABASE_URL" {
		for k, v := range d.env("iam") {
			if k == "AIPAY_ENVIRONMENT" || strings.HasPrefix(k, "AIPAY_IAM_DATA_") || k == "AIPAY_IAM_EMAIL_TTL" {
				list = append(list, k+"="+v)
			}
		}
	}
	return command(d.dir, list, filepath.Join(d.root, "bin", service), args...)
}
func (d *driver) declaration(name string, v any) string {
	p := filepath.Join(d.dir, "declarations", name+".json")
	check(atomic(p, encoded(v)))
	return p
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
	d := &driver{root: root, repo: repo, dir: filepath.Join(root, "demo"), scope: scope, data: map[string]json.RawMessage{}, browsers: map[string]*browser{}, history: report{Scenario: scope, Started: time.Now().UTC().Format(time.RFC3339), Logs: filepath.Join(root, "logs")}}
	b, e := os.ReadFile(filepath.Join(d.dir, "state.json"))
	if e == nil {
		decode(b, &d.data)
	} else if !errors.Is(e, os.ErrNotExist) {
		check(e)
	}
	previous, e := os.ReadFile(filepath.Join(d.dir, "reports", scope+".json"))
	if e == nil {
		decode(previous, &d.history)
	} else if !errors.Is(e, os.ErrNotExist) {
		check(e)
	}
	return d
}
