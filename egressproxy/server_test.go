package egressproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kaivodev/servicekit/config"
)

func TestAddressPolicy(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "64:ff9b::/96"} {
		p := netip.MustParsePrefix(prefix)
		// Exercise both ends of each required prefix.
		a := p.Masked().Addr()
		b := a.AsSlice()
		for i := p.Bits(); i < len(b)*8; i++ {
			b[i/8] |= 1 << (7 - uint(i%8))
		}
		last, _ := netip.AddrFromSlice(b)
		for _, ip := range []netip.Addr{a, last} {
			if permitted(ip, nil) {
				t.Fatal("allowed denied address in", prefix)
			}
			if ip.Is4() && permitted(netip.AddrFrom16(ip.As16()), nil) {
				t.Fatal("allowed mapped address in", prefix)
			}
		}
	}
	for _, s := range []string{"1.1.1.1", "100.63.255.255", "100.128.0.0", "172.32.0.0", "198.20.0.1", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if !permitted(netip.MustParseAddr(s), nil) {
			t.Fatal("denied", s)
		}
	}
	allow := []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}
	if !permitted(netip.MustParseAddr("::ffff:198.18.2.3"), allow) || permitted(netip.MustParseAddr("10.0.0.1"), allow) {
		t.Fatal("incorrect CIDR override")
	}
}

type running struct {
	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func start(t *testing.T, s *Server) *running {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r := &running{ln: ln, cancel: cancel, done: make(chan struct{})}
	go func() { r.err = s.Serve(ctx, ln); close(r.done) }()
	t.Cleanup(func() { r.cancel(); r.wait(t) })
	return r
}

func (r *running) wait(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
		if r.err != nil {
			t.Fatal(r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not stop")
	}
}

func (r *running) client(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", r.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newTestServer(t *testing.T, cfg Config, log io.Writer) *Server {
	t.Helper()
	cfg.AllowedHosts = []string{"ExChanGe.test."}
	s, err := New(cfg, slog.New(slog.NewJSONHandler(log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	s.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("unexpected upstream dial")
		return nil, errors.New("unexpected dial")
	}
	return s
}

func request(target string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: exchange.test:443\r\n\r\n"
}

func response(t *testing.T, c net.Conn, req string) (int, *bufio.Reader) {
	t.Helper()
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	p, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	return p.StatusCode, r
}

func TestRequestRejections(t *testing.T) {
	s := newTestServer(t, Config{}, io.Discard)
	s.headerTimeout = 75 * time.Millisecond
	r := start(t, s)
	base := "CONNECT exchange.test:443 HTTP/1.1\r\nX-Header: "
	for _, tc := range []struct {
		name, req string
		status    int
	}{
		{"method", "GET / HTTP/1.1\r\nHost: exchange.test\r\n\r\n", 405},
		{"port", request("exchange.test:80"), 403},
		{"unknown host", request("other.test:443"), 403},
		{"subdomain", request("sub.exchange.test:443"), 403},
		{"ip", request("127.0.0.1:443"), 403},
		{"ipv6", request("[::1]:443"), 403},
		{"no port", request("exchange.test"), 403},
		{"absolute uri", request("https://exchange.test:443/"), 403},
		{"loopback forbidden", request("exchange.test:443"), 403},
		{"exactly 8 KiB permitted to reach policy", base + strings.Repeat("a", maxHeader-len(base)-4) + "\r\n\r\n", 403},
		{"one byte over", base + strings.Repeat("a", maxHeader-len(base)-3) + "\r\n\r\n", 431},
		{"long line", "CONNECT " + strings.Repeat("a", maxHeader), 431},
		{"slow header", "CONNECT exchange.test:443 HTTP/1.1\r\nHost:", 408},
		{"slow request line", "CONNECT ", 408},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := response(t, r.client(t), tc.req)
			if code != tc.status {
				t.Fatalf("got %d, want %d", code, tc.status)
			}
		})
	}
}

func TestLookupIPv4Only(t *testing.T) {
	s := newTestServer(t, Config{}, io.Discard)
	var queried string
	s.lookup = func(_ context.Context, network, _ string) ([]netip.Addr, error) {
		queried = network
		return nil, nil // No IPv4 answer.
	}
	_, status := s.connect(t.Context(), "exchange.test")
	if queried != "ip4" || status != http.StatusBadGateway {
		t.Fatalf("lookup network=%q status=%d", queried, status)
	}
}

func TestDNSValidation(t *testing.T) {
	for _, tc := range []struct {
		name              string
		answers           []string
		lookupErr         bool
		status, wantDials int
	}{
		{"mixed", []string{"1.1.1.1", "10.0.0.1"}, false, 403, 0},
		{"private-first", []string{"10.0.0.1", "1.1.1.1"}, false, 403, 0},
		{"no answers", nil, false, 502, 0},
		{"DNS error", nil, true, 502, 0},
		{"dial error", []string{"1.1.1.1", "8.8.8.8"}, false, 502, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, Config{}, io.Discard)
			var lookups, dials atomic.Int32
			s.lookup = func(ctx context.Context, _, host string) ([]netip.Addr, error) {
				lookups.Add(1)
				if host != "exchange.test." {
					t.Error("wrong lookup")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 10*time.Second {
					t.Error("missing dial deadline")
				}
				if tc.lookupErr {
					return nil, errors.New("DNS unavailable")
				}
				var ips []netip.Addr
				for _, a := range tc.answers {
					ips = append(ips, netip.MustParseAddr(a))
				}
				return ips, nil
			}
			s.dial = func(_ context.Context, network, addr string) (net.Conn, error) {
				idx := int(dials.Add(1)) - 1
				if network != "tcp" || idx >= len(tc.answers) || addr != net.JoinHostPort(tc.answers[idx], "443") {
					t.Error("dialed different from approved address")
				}
				return nil, errors.New("dial failed")
			}
			code, _ := response(t, start(t, s).client(t), request("EXCHANGE.TEST.:443"))
			if code != tc.status || lookups.Load() != 1 || int(dials.Load()) != tc.wantDials {
				t.Fatal(code, lookups.Load(), dials.Load())
			}
		})
	}
}

func echo(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { defer c.Close(); io.Copy(c, c) })
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("echo connections leaked")
		}
	})
	return ln.Addr().String()
}

func echoProxy(t *testing.T, log io.Writer) *Server {
	t.Helper()
	addr := echo(t)
	s := newTestServer(t, Config{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Environment: config.Development}, log)
	s.dial = func(ctx context.Context, network, target string) (net.Conn, error) {
		if network != "tcp" || target != "127.0.0.1:443" {
			t.Error("dialed unchecked address", target)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return s
}

func expectBytes(t *testing.T, r io.Reader, want string) {
	t.Helper()
	b := make([]byte, len(want))
	if _, err := io.ReadFull(r, b); err != nil || string(b) != want {
		t.Fatalf("incorrect tunnel bytes: %v", err)
	}
}

func TestTunnelAndDrain(t *testing.T) {
	var logs bytes.Buffer
	s := echoProxy(t, &logs)
	s.max = 1
	r := start(t, s)
	client := r.client(t)
	payload := "private-tunnel-content"
	code, reader := response(t, client, request("EXCHANGE.TEST.:443")+payload)
	if code != 200 {
		t.Fatal(code)
	}
	expectBytes(t, reader, payload)
	// The active connection fills capacity, including while transferring.
	other := r.client(t)
	p, err := http.ReadResponse(bufio.NewReader(other), nil)
	if err != nil || p.StatusCode != 503 {
		t.Fatal(p, err)
	}
	r.cancel()
	// Wait for the listener to close. The established tunnel remains usable.
	until := time.Now().Add(time.Second)
	for {
		c, err := net.DialTimeout("tcp", r.ln.Addr().String(), 100*time.Millisecond)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(until) {
			t.Fatal("listener remained open")
		}
	}
	if _, err := io.WriteString(client, "more"); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, reader, "more")
	client.Close()
	r.wait(t)
	if strings.Contains(logs.String(), payload) {
		t.Fatal("logged tunnel content")
	}
	var closed int
	for line := range strings.Lines(logs.String()) {
		var entry struct {
			Host     string
			Port     int
			Outcome  string
			Up       int `json:"up_bytes"`
			Down     int `json:"down_bytes"`
			Duration int64
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Outcome == "closed" {
			closed++
			if entry.Host != "exchange.test" || entry.Port != 443 || entry.Up != len(payload)+4 || entry.Down != entry.Up || entry.Duration <= 0 {
				t.Fatal(entry)
			}
		}
	}
	if closed != 1 {
		t.Fatal("missing tunnel log", logs.String())
	}
}

func TestIdleTimeout(t *testing.T) {
	var logs bytes.Buffer
	s := echoProxy(t, &logs)
	s.idle = 120 * time.Millisecond
	r := start(t, s)
	client := r.client(t)
	code, reader := response(t, client, request("exchange.test:443"))
	if code != 200 {
		t.Fatal(code)
	}
	for range 5 {
		time.Sleep(30 * time.Millisecond)
		if _, err := io.WriteString(client, "x"); err != nil {
			t.Fatal(err)
		}
		expectBytes(t, reader, "x")
	}
	start := time.Now()
	_, err := reader.ReadByte()
	if !errors.Is(err, io.EOF) || time.Since(start) > time.Second {
		t.Fatalf("idle close: %v", err)
	}
	r.cancel()
	r.wait(t)
	if !strings.Contains(logs.String(), "idle_timeout") {
		t.Fatal(logs.String())
	}
}

func TestForcedShutdown(t *testing.T) {
	s := echoProxy(t, io.Discard)
	s.grace = 50 * time.Millisecond
	r := start(t, s)
	client := r.client(t)
	code, reader := response(t, client, request("exchange.test:443"))
	if code != 200 {
		t.Fatal(code)
	}
	start := time.Now()
	r.cancel()
	r.wait(t)
	if elapsed := time.Since(start); elapsed < s.grace || elapsed > time.Second {
		t.Fatal("incorrect drain time", elapsed)
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatal("forced tunnel close", err)
	}
}

func TestEmptyProbe(t *testing.T) {
	var logs bytes.Buffer
	s := newTestServer(t, Config{}, &logs)
	r := start(t, s)
	client := r.client(t)
	client.Close()
	// A round trip synchronizes the accept loop before shutdown.
	code, _ := response(t, r.client(t), "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	if code != 405 {
		t.Fatal(code)
	}
	r.cancel()
	r.wait(t)
	if s.EmptyConnections() != 1 || strings.Count(logs.String(), "\n") != 1 {
		t.Fatal(s.EmptyConnections(), logs.String())
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []Config{
		{}, {AllowedHosts: []string{"127.0.0.1"}}, {AllowedHosts: []string{"[::1]"}}, {AllowedHosts: []string{"*.example.com"}},
		{AllowedHosts: []string{"bad..host"}}, {AllowedHosts: []string{"test"}, MaxConnections: 1025},
		{AllowedHosts: []string{"test"}, AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Environment: config.Test},
	} {
		if _, err := New(cfg, nil); err == nil {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
	s, err := New(Config{AllowedHosts: []string{"exchange.test"}}, nil)
	if err != nil || s.max != 64 || s.idle != 2*time.Minute || s.dialTimeout != 10*time.Second || s.headerTimeout != 10*time.Second || s.grace != 10*time.Second {
		t.Fatal("unexpected defaults", err)
	}
}

func TestDialTimeout(t *testing.T) {
	s := newTestServer(t, Config{}, io.Discard)
	s.dialTimeout = 20 * time.Millisecond
	s.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	code, _ := response(t, start(t, s).client(t), request("exchange.test:443"))
	if code != 502 {
		t.Fatalf("dial timeout status %d", code)
	}
}

// stalledUpstream acknowledges entry into Write before blocking on a peer that
// never reads. Grace expiry must interrupt both halves of the tunnel.
type stalledUpstream struct {
	net.Conn
	writing chan struct{}
	once    sync.Once
}

func (c *stalledUpstream) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.writing) })
	return c.Conn.Write(p)
}

func TestForceCloseBlockedUpstreamWrite(t *testing.T) {
	s := newTestServer(t, Config{Environment: config.Development, AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, io.Discard)
	s.grace = 30 * time.Millisecond
	up, peer := net.Pipe()
	defer peer.Close()
	remote := &stalledUpstream{Conn: up, writing: make(chan struct{})}
	s.dial = func(context.Context, string, string) (net.Conn, error) { return remote, nil }
	r := start(t, s)
	code, _ := response(t, r.client(t), request("exchange.test:443")+"buffered bytes")
	if code != 200 {
		t.Fatal(code)
	}
	select {
	case <-remote.writing:
	case <-time.After(time.Second):
		t.Fatal("upstream write did not start")
	}
	r.cancel()
	r.wait(t)
}
