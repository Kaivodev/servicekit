package egressproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kaivodev/servicekit/config"
)

const maxHeader = 8 << 10

// Config limits the destinations, concurrency and idle lifetime of tunnels.
type Config struct {
	AllowedHosts   []string
	MaxConnections int
	IdleTimeout    time.Duration
	Environment    config.Environment
	// AllowCIDRs permits explicit address ranges in development only.
	AllowCIDRs []netip.Prefix
}

// Server handles CONNECT connections for one namespace.
type Server struct {
	hosts                                   map[string]bool
	allow                                   []netip.Prefix
	max                                     int
	idle, headerTimeout, dialTimeout, grace time.Duration
	lookup                                  func(context.Context, string, string) ([]netip.Addr, error)
	dial                                    func(context.Context, string, string) (net.Conn, error)
	log                                     *slog.Logger
	probes                                  atomic.Uint64
}

// New validates the allowlist. A nil logger writes JSON connection logs to stdout.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if len(cfg.AllowedHosts) == 0 {
		return nil, errors.New("at least one proxy host is required")
	}
	hosts := make(map[string]bool)
	for _, entry := range cfg.AllowedHosts {
		h, ok := hostname(entry)
		if !ok {
			return nil, errors.New("invalid proxy allowlist hostname")
		}
		hosts[h] = true
	}
	if len(cfg.AllowCIDRs) > 0 && !cfg.Environment.IsDevelopment() {
		return nil, errors.New("AllowCIDRs requires development environment")
	}
	for _, p := range cfg.AllowCIDRs {
		if !p.IsValid() {
			return nil, errors.New("invalid allowed CIDR")
		}
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 64
	}
	if cfg.MaxConnections < 1 || cfg.MaxConnections > 1024 {
		return nil, errors.New("MaxConnections must be between 1 and 1024")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.IdleTimeout < 0 {
		return nil, errors.New("IdleTimeout must be positive")
	}
	if log == nil {
		log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	return &Server{
		hosts: hosts, allow: slices.Clone(cfg.AllowCIDRs), max: cfg.MaxConnections,
		idle: cfg.IdleTimeout, headerTimeout: 10 * time.Second,
		dialTimeout: 10 * time.Second, grace: 10 * time.Second,
		lookup: net.DefaultResolver.LookupNetIP, dial: (&net.Dialer{}).DialContext,
		log: log,
	}, nil
}

// EmptyConnections counts clients that closed before sending a request byte.
func (s *Server) EmptyConnections() uint64 { return s.probes.Load() }

// Serve owns ln. Cancellation closes the listener, drains up to ten seconds,
// then cancels remaining dials and closes remaining connections.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stopClose := context.AfterFunc(ctx, func() { ln.Close() })
	defer stopClose()
	defer ln.Close()
	work, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	slots := make(chan struct{}, s.max)
	var wg sync.WaitGroup
	var acceptErr error
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				acceptErr = err
			}
			break
		}
		select {
		case slots <- struct{}{}:
			wg.Go(func() {
				defer func() { <-slots }()
				defer conn.Close()
				stop := context.AfterFunc(work, func() { conn.Close() })
				defer stop()
				s.handle(work, conn)
			})
		default:
			start := time.Now()
			reply(conn, http.StatusServiceUnavailable)
			conn.Close()
			s.logConnection("", 0, "overloaded", 0, 0, start)
		}
	}
	timer := time.AfterFunc(s.grace, cancel)
	defer timer.Stop()
	wg.Wait()
	return acceptErr
}

var errLarge = errors.New("CONNECT headers exceed limit")

// Bound the complete request line and headers exactly. bufio may already hold
// initial tunnel bytes in the same TCP packet; relay consumes that reader.
func readHead(r *bufio.Reader) (*http.Request, error) {
	head := make([]byte, 0, 512)
	lineStart := 0
	for len(head) < maxHeader {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(head) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		head = append(head, b)
		if b != '\n' {
			continue
		}
		line := head[lineStart:]
		if len(line) == 1 || bytes.Equal(line, []byte("\r\n")) {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return req, err
		}
		lineStart = len(head)
	}
	return nil, errLarge
}

func reply(c net.Conn, code int) {
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code))
}

func (s *Server) logConnection(host string, port int, outcome string, up, down int64, start time.Time) {
	s.log.Info("egress connection", "host", host, "port", port, "outcome", outcome, "up_bytes", up, "down_bytes", down, "duration", time.Since(start))
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	start := time.Now()
	var host, outcome string
	var port int
	var up, down int64
	defer func() {
		if outcome != "" {
			s.logConnection(host, port, outcome, up, down, start)
		}
	}()
	_ = client.SetReadDeadline(start.Add(s.headerTimeout))
	reader := bufio.NewReaderSize(client, maxHeader)
	req, err := readHead(reader)
	if errors.Is(err, io.EOF) {
		s.probes.Add(1)
		return
	}
	if err != nil {
		code := http.StatusBadRequest
		var netErr net.Error
		switch {
		case errors.Is(err, errLarge):
			code = http.StatusRequestHeaderFieldsTooLarge
		case errors.As(err, &netErr) && netErr.Timeout():
			code = http.StatusRequestTimeout
		}
		outcome = "invalid_request"
		reply(client, code)
		return
	}
	if req.Method != http.MethodConnect {
		outcome = "method_denied"
		reply(client, http.StatusMethodNotAllowed)
		return
	}
	// Authorize the authority from the request line. Never route on headers.
	name, portText, err := net.SplitHostPort(req.RequestURI)
	port, _ = strconv.Atoi(portText)
	var valid bool
	host, valid = hostname(name)
	if err != nil || !valid || !s.hosts[host] || portText != "443" || req.RequestURI != name+":443" {
		outcome = "target_denied"
		reply(client, http.StatusForbidden)
		return
	}
	remote, status := s.connect(ctx, host)
	if status != http.StatusOK {
		outcome = "upstream_unavailable"
		if status == http.StatusForbidden {
			outcome = "address_denied"
		}
		reply(client, status)
		return
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	_ = client.SetDeadline(time.Now().Add(s.idle))
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		outcome = "client_closed"
		return
	}
	_ = client.SetDeadline(time.Time{})
	up, down, outcome = s.relay(client, reader, remote)
}

func (s *Server) connect(ctx context.Context, host string) (net.Conn, int) {
	ctx, cancel := context.WithTimeout(ctx, s.dialTimeout)
	defer cancel()
	// Query the absolute allowlisted name, independent of resolver search suffixes.
	ips, err := s.lookup(ctx, "ip4", host+".")
	if err != nil || len(ips) == 0 {
		return nil, http.StatusBadGateway
	}
	for _, ip := range ips {
		if !permitted(ip, s.allow) {
			return nil, http.StatusForbidden
		}
	}
	for _, ip := range ips {
		c, err := s.dial(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), "443"))
		if err == nil {
			return c, http.StatusOK
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, http.StatusBadGateway
}

type activityWriter struct {
	dst   net.Conn
	timer *time.Timer
	idle  time.Duration
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.timer.Reset(w.idle)
	}
	return n, err
}

func (s *Server) relay(client net.Conn, reader *bufio.Reader, remote net.Conn) (int64, int64, string) {
	var timedOut atomic.Bool
	closeBoth := func() { client.Close(); remote.Close() }
	timer := time.AfterFunc(s.idle, func() { timedOut.Store(true); closeBoth() })
	defer timer.Stop()
	sent := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(activityWriter{remote, timer, s.idle}, reader)
		closeBoth()
		sent <- n
	}()
	down, _ := io.Copy(activityWriter{client, timer, s.idle}, remote)
	closeBoth()
	up := <-sent
	if timedOut.Load() {
		return up, down, "idle_timeout"
	}
	return up, down, "closed"
}
