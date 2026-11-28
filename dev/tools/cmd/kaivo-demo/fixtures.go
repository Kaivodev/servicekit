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
	"strconv"
	"strings"
	"sync"
	syncatomic "sync/atomic"
	"time"
)

const merchantUser int64 = 20812001
const demoGroup int64 = -10020812001
const notifyOrigin = "http://localhost:9082"

type message struct {
	ID, Chat int64
	Text     string
	Deleted  bool
	Document *documentMeta `json:",omitempty"`
}
type documentMeta struct {
	Filename, Caption, SHA256 string
	Size                      int
}

// Read the multipart stream without spilling headers or form fields to temporary files.
func parseDocument(r *http.Request) (int64, *documentMeta, []byte, bool) {
	parts, err := r.MultipartReader()
	if err != nil {
		return 0, nil, nil, false
	}
	var chat int64
	doc := &documentMeta{}
	var data []byte
	seen := map[string]bool{}
	for {
		p, err := parts.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, nil, nil, false
		}
		name := p.FormName()
		if seen[name] {
			return 0, nil, nil, false
		}
		seen[name] = true
		limit := 4096
		if name == "document" {
			limit = 12 << 20
		}
		b, err := io.ReadAll(io.LimitReader(p, int64(limit+1)))
		if err != nil || len(b) > limit {
			return 0, nil, nil, false
		}
		switch name {
		case "chat_id":
			chat, err = strconv.ParseInt(string(b), 10, 64)
			if err != nil || p.FileName() != "" {
				return 0, nil, nil, false
			}
		case "caption":
			if p.FileName() != "" {
				return 0, nil, nil, false
			}
			doc.Caption = string(b)
		case "document":
			doc.Filename = p.FileName()
			if doc.Filename == "" || len(b) == 0 {
				return 0, nil, nil, false
			}
			doc.Size, doc.SHA256 = len(b), fmt.Sprintf("%x", sha256.Sum256(b))
			data = b
		default:
			return 0, nil, nil, false
		}
	}
	return chat, doc, data, chat != 0 && len(data) > 0
}

type receipt struct{ Trade, MerchantOrder, PID, Money, Status string }
type fixtures struct {
	dir, token, webhook string
	mu                  sync.Mutex
	host                string
	config              syncatomic.Pointer[fixtureConfig]
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
	token, webhook := f.token, f.webhook
	if f.host != "" {
		cfg := f.config.Load()
		if cfg == nil {
			w.WriteHeader(503)
			return
		}
		token, webhook = cfg.Token, cfg.Webhook
	}
	method, ok := strings.CutPrefix(r.URL.Path, "/bot"+token+"/")
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
	var doc *documentMeta
	var document []byte
	if method == "sendDocument" {
		r.Body = http.MaxBytesReader(w, r.Body, (12<<20)+(64<<10))
		in.Chat, doc, document, ok = parseDocument(r)
		if !ok {
			w.WriteHeader(400)
			return
		}
	} else if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in) != nil {
		w.WriteHeader(400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var result any
	switch method {
	case "getWebhookInfo":
		result = object{"url": webhook}
	case "getChatMember":
		status := "left"
		if in.Chat == demoGroup && in.User == merchantUser {
			status = "member"
		}
		result = object{"user": object{"id": in.User}, "status": status}
	case "sendMessage", "sendDocument", "deleteMessage":
		p := filepath.Join(f.dir, "messages.json")
		msgs, e := readRecords[message](p)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		if method != "deleteMessage" {
			if in.Chat == 0 || (doc == nil && in.Text == "") {
				w.WriteHeader(400)
				return
			}
			i := int64(len(msgs) + 1)
			if doc != nil && atomic(filepath.Join(f.dir, "documents", doc.SHA256), document) != nil {
				w.WriteHeader(500)
				return
			}
			msgs = append(msgs, message{ID: i, Chat: in.Chat, Text: in.Text, Document: doc})
			result = object{"message_id": i}
		} else {
			if in.ID < 1 || in.ID > int64(len(msgs)) || msgs[in.ID-1].Chat != in.Chat {
				w.WriteHeader(400)
				return
			}
			msgs[in.ID-1].Deleted = true
			msgs[in.ID-1].Text = ""
			msgs[in.ID-1].Document = nil
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
	host := f.host
	if host == "" {
		host = "localhost:9082"
	}
	if r.Method != "POST" || r.URL.Path != "/notify" || r.URL.RawQuery != "" || r.Host != host {
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
		b, e := f.verifier("merchant-key.json")
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
		b, e := f.verifier("merchant-v2.json")
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
	connectMerchant(w, r, "127.0.0.1:9082", nil)
}
func connectMerchant(w http.ResponseWriter, r *http.Request, address string, record func() error) {
	dst, e := net.DialTimeout("tcp4", address, 2*time.Second)
	if e != nil {
		w.WriteHeader(502)
		return
	}
	defer dst.Close()
	if record != nil && record() != nil {
		w.WriteHeader(500)
		return
	}
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
	readPortalOrigins(env)
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
