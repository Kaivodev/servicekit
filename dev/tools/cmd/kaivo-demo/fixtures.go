package main

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const merchantUser int64 = 20812001
const demoGroup int64 = -10020812001
const notifyOrigin = "http://localhost:9082"

type message struct {
	ID, Chat int64
	Text     string
	Deleted  bool
}
type receipt struct{ Trade, MerchantOrder, PID, Money, Status string }
type fixtures struct {
	dir, token, webhook string
	mu                  sync.Mutex
}

func readRecords[T any](path string) ([]T, error) {
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var items []T
	e = json.Unmarshal(b, &items)
	return items, e
}
func (f *fixtures) bot(w http.ResponseWriter, r *http.Request) {
	method, ok := strings.CutPrefix(r.URL.Path, "/bot"+f.token+"/")
	if !ok || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Chat int64 `json:"chat_id"`
		User int64 `json:"user_id"`
		ID   int64 `json:"message_id"`
		Text string
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in) != nil {
		w.WriteHeader(400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var result any
	switch method {
	case "getWebhookInfo":
		result = object{"url": f.webhook}
	case "getChatMember":
		status := "left"
		if in.Chat == demoGroup && in.User == merchantUser {
			status = "member"
		}
		result = object{"user": object{"id": in.User}, "status": status}
	case "sendMessage", "deleteMessage":
		p := filepath.Join(f.dir, "messages.json")
		msgs, e := readRecords[message](p)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		if method == "sendMessage" {
			if in.Chat == 0 || in.Text == "" {
				w.WriteHeader(400)
				return
			}
			i := int64(len(msgs) + 1)
			msgs = append(msgs, message{ID: i, Chat: in.Chat, Text: in.Text})
			result = object{"message_id": i}
		} else {
			if in.ID < 1 || in.ID > int64(len(msgs)) || msgs[in.ID-1].Chat != in.Chat {
				w.WriteHeader(400)
				return
			}
			msgs[in.ID-1].Deleted = true
			msgs[in.ID-1].Text = ""
			result = true
		}
		if atomic(p, encoded(msgs)) != nil {
			w.WriteHeader(500)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(object{"ok": true, "result": result})
}
func canonical(v url.Values) (string, bool) {
	var keys []string
	for k, vs := range v {
		if len(vs) != 1 || k == "" || strings.ContainsAny(k, "&=") || strings.Contains(vs[0], "&") {
			return "", false
		}
		if k != "sign" && k != "sign_type" && vs[0] != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		keys[i] = k + "=" + v.Get(k)
	}
	return strings.Join(keys, "&"), true
}
func v1Sign(v url.Values, key string) string {
	p, ok := canonical(v)
	if !ok || key == "" {
		return ""
	}
	h := md5.Sum([]byte(p + key))
	return hex.EncodeToString(h[:])
}
func (f *fixtures) notify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/notify" || r.URL.RawQuery != "" || r.Host != "localhost:9082" {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil {
		w.WriteHeader(400)
		return
	}
	v := r.PostForm
	valid := false
	switch v.Get("sign_type") {
	case "MD5":
		var key struct{ PID, Key string }
		b, e := os.ReadFile(filepath.Join(f.dir, "merchant-key.json"))
		if e != nil || json.Unmarshal(b, &key) != nil {
			w.WriteHeader(503)
			return
		}
		sig := v1Sign(v, key.Key)
		valid = sig != "" && v.Get("pid") == key.PID && subtle.ConstantTimeCompare([]byte(sig), []byte(v.Get("sign"))) == 1
	case "RSA":
		var info struct {
			PID  string
			SPKI []byte
		}
		b, e := os.ReadFile(filepath.Join(f.dir, "merchant-v2.json"))
		if e != nil || json.Unmarshal(b, &info) != nil {
			w.WriteHeader(503)
			return
		}
		public, e := x509.ParsePKIXPublicKey(info.SPKI)
		key, ok := public.(*rsa.PublicKey)
		if e == nil && ok {
			canonical, ok := canonical(v)
			sig, e := base64.StdEncoding.DecodeString(v.Get("sign"))
			h := sha256.Sum256([]byte(canonical))
			valid = ok && e == nil && v.Get("pid") == info.PID && rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) == nil
		}
	}
	if !valid || v.Get("trade_status") != "TRADE_SUCCESS" || v.Get("trade_no") == "" || v.Get("out_trade_no") == "" {
		w.WriteHeader(403)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := filepath.Join(f.dir, "notifications.json")
	rs, e := readRecords[receipt](p)
	if e != nil || atomic(p, encoded(append(rs, receipt{v.Get("trade_no"), v.Get("out_trade_no"), v.Get("pid"), v.Get("money"), v.Get("trade_status")}))) != nil {
		w.WriteHeader(500)
		return
	}
	io.WriteString(w, "success")
}
func tunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" || (r.Host != "127.0.0.1:9082" && r.Host != "[::1]:9082") {
		w.WriteHeader(403)
		return
	}
	dst, e := net.DialTimeout("tcp4", "127.0.0.1:9082", 2*time.Second)
	if e != nil {
		w.WriteHeader(502)
		return
	}
	defer dst.Close()
	c, rw, e := http.NewResponseController(w).Hijack()
	if e != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	dst.SetDeadline(time.Now().Add(20 * time.Second))
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil || rw.Flush() != nil {
		return
	}
	go func() { io.Copy(dst, rw); dst.(*net.TCPConn).CloseWrite() }()
	io.Copy(c, dst)
}
func (d *driver) serve() {
	env := d.env("backend")
	f := fixtures{dir: d.dir, token: strings.TrimSpace(string(file(env["AIPAY_TELEGRAM_BOT_TOKEN_FILE"]))), webhook: env["AIPAY_TELEGRAM_WEBHOOK_URL"]}
	require(f.token != "" && f.webhook != "", "missing Bot API configuration")
	errs := make(chan error, 3)
	for _, s := range []struct {
		port   int
		handle http.HandlerFunc
	}{{9081, f.bot}, {9082, f.notify}, {3128, tunnel}} {
		l, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", s.port))
		check(e)
		defer l.Close()
		srv := &http.Server{Handler: s.handle, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second}
		go func() { errs <- srv.Serve(l) }()
	}
	fmt.Println("Bot API, merchant and CONNECT ready")
	check(<-errs)
}
