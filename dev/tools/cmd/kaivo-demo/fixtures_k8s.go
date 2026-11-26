package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
)

// Installed via the Pod loopback control port or the owner-only Unix socket.
// The token and notification verification keys live only in the server process.
type fixtureConfig struct {
	Token, Webhook string
	V1, V2         json.RawMessage `json:",omitempty"`
}

func fixtureDir(args []string) string {
	require(len(args) <= 1, "usage: serve-k8s [STATE_DIR]")
	if len(args) == 1 {
		require(args[0] != "", "missing fixture state directory")
		return args[0]
	}
	return setting("AIPAY_DEMO_FIXTURE_DIR", "/tmp/demo")
}
func (f *fixtures) verifier(name string) ([]byte, error) {
	if f.host == "" {
		return os.ReadFile(filepath.Join(f.dir, name))
	}
	cfg := f.config.Load()
	if cfg != nil {
		if name == "merchant-key.json" && len(cfg.V1) > 0 {
			return cfg.V1, nil
		}
		if name == "merchant-v2.json" && len(cfg.V2) > 0 {
			return cfg.V2, nil
		}
	}
	return nil, errors.New("merchant verifier unavailable")
}
func (f *fixtures) configure(l net.Listener) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		var cfg fixtureConfig
		b, e := io.ReadAll(io.LimitReader(c, 64<<10))
		if e == nil && len(b) < 64<<10 && json.Unmarshal(b, &cfg) == nil && cfg.Token != "" && cfg.Webhook != "" {
			f.install(cfg)
			io.WriteString(c, "ok")
		}
		c.Close()
	}
}
func (f *fixtures) install(cfg fixtureConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if prev := f.config.Load(); prev != nil && prev.Token == cfg.Token {
		if cfg.V1 == nil {
			cfg.V1 = prev.V1
		}
		if cfg.V2 == nil {
			cfg.V2 = prev.V2
		}
	}
	f.config.Store(&cfg)
}

func installFixtureConfig(dir string, input io.Reader) {
	c, e := net.DialTimeout("unix", filepath.Join(dir, "config.sock"), 3*time.Second)
	require(e == nil, "fixture configuration socket unavailable")
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	n, e := io.Copy(c, io.LimitReader(input, 64<<10))
	require(e == nil && n < 64<<10, "invalid fixture configuration")
	check(c.(*net.UnixConn).CloseWrite())
	reply, e := io.ReadAll(io.LimitReader(c, 3))
	require(e == nil && string(reply) == "ok", "fixture configuration rejected")
}

var storedDoc = regexp.MustCompile(`^/documents/[a-f0-9]{64}$`)

func (f *fixtures) control(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" && r.URL.RequestURI() == "/config" {
		if f.token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+f.token)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var cfg fixtureConfig
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil || json.Unmarshal(body, &cfg) != nil || cfg.Webhook == "" || cfg.Token != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cfg.Token = f.token
		f.install(cfg)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != "GET" || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case "/messages.json", "/notifications.json", "/connections.json":
		w.Header().Set("Content-Type", "application/json")
	default:
		if !storedDoc.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	b, e := os.ReadFile(filepath.Join(f.dir, r.URL.Path[1:]))
	if os.IsNotExist(e) {
		if storedDoc.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		b = []byte("[]")
	} else if e != nil {
		w.WriteHeader(500)
		return
	}
	w.Write(b)
}

type proxyConnection struct {
	Target string
	At     time.Time
}

func (f *fixtures) proxy(w http.ResponseWriter, r *http.Request, localMerchant string) {
	if r.Method != "CONNECT" {
		w.WriteHeader(403)
		return
	}
	target, port, e := net.SplitHostPort(r.Host)
	hostname, _, _ := net.SplitHostPort(f.host)
	if e != nil || port != "8082" {
		w.WriteHeader(403)
		return
	}
	if target != hostname {
		// Notifier pins DNS and sends the ClusterIP in CONNECT. Resolve only our
		// configured Service, never a caller-controlled hostname.
		ip, e := netip.ParseAddr(target)
		if e != nil {
			w.WriteHeader(403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
		if e != nil || !slices.ContainsFunc(ips, func(a netip.Addr) bool { return a.Unmap() == ip.Unmap() }) {
			w.WriteHeader(403)
			return
		}
	}
	connectMerchant(w, r, localMerchant, func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := filepath.Join(f.dir, "connections.json")
		records, e := readRecords[proxyConnection](p)
		if e != nil {
			return e
		}
		return atomic(p, encoded(append(records, proxyConnection{r.Host, time.Now().UTC()})))
	})
}
func serveKubeFixtures(ctx context.Context, dir string) {
	serveKubeFixturesWithListeners(ctx, dir, "127.0.0.1:8082", net.Listen)
}

func serveKubeFixturesWithListeners(ctx context.Context, dir, localMerchant string, listen func(string, string) (net.Listener, error)) {
	check(os.MkdirAll(dir, 0700))
	// Undeleted Bot messages can contain a newly issued merchant key.
	if runtime.GOOS == "linux" && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		require(isTmpfs(dir), "fixture state requires emptyDir.medium: Memory")
	}
	lock := roleLock(dir, "fixtures.lock")
	defer lock.Close()
	ns := setting("AIPAY_DEMO_NS_SIM", "kaivo-sim")
	require(dnsLabel.MatchString(ns), "invalid simulator namespace")
	f := &fixtures{dir: dir, host: fixtureService + "." + ns + ".svc.cluster.local:8082"}
	if path := os.Getenv("AIPAY_TELEGRAM_BOT_TOKEN_FILE"); path != "" {
		token := strings.TrimSpace(string(file(path)))
		require(token != "", "empty Bot API token")
		f.token = token
		f.config.Store(&fixtureConfig{Token: token, Webhook: setting("AIPAY_TELEGRAM_WEBHOOK_URL", "https://merchant.aipay.test/telegram/webhook")})
	}
	path := filepath.Join(dir, "config.sock")
	// flock excludes an active server before removing a stale socket after a crash.
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		check(e)
	}
	l, e := net.Listen("unix", path)
	check(e)
	defer l.Close()
	check(os.Chmod(path, 0600))
	go f.configure(l)
	errs := make(chan error, 4)
	proxy := func(w http.ResponseWriter, r *http.Request) { f.proxy(w, r, localMerchant) }
	for _, s := range []struct {
		port    int
		handler http.HandlerFunc
	}{{8081, f.bot}, {8082, f.notify}, {3128, proxy}, {8088, f.control}} {
		host := "0.0.0.0"
		if s.port == 8088 {
			host = "127.0.0.1"
		}
		l, e := listen("tcp4", fmt.Sprintf("%s:%d", host, s.port))
		check(e)
		srv := &http.Server{Handler: s.handler, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second}
		defer srv.Close()
		go func() { errs <- srv.Serve(l) }()
	}
	fmt.Println("Bot API, merchant, CONNECT and loopback control ready")
	select {
	case <-ctx.Done():
		return
	case e := <-errs:
		check(e)
	}
}
