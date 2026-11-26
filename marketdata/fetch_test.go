package marketdata

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric"
)

var testMinute = time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)

type sinkFunc func(context.Context, Result) error

func (f sinkFunc) Record(ctx context.Context, r Result) error { return f(ctx, r) }

type records struct {
	mu      sync.Mutex
	results []Result
	err     error
}

func (s *records) Record(_ context.Context, r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, r)
	return s.err
}
func (s *records) all() []Result { s.mu.Lock(); defer s.mu.Unlock(); return slices.Clone(s.results) }

func newCollector(t *testing.T, cfg Config, s Schedule, sink Sink, provider metric.MeterProvider, log io.Writer) *Collector {
	t.Helper()
	c, err := NewCollector(cfg, s, sink, provider, slog.New(slog.NewJSONHandler(log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// withTestBaseURL exists only in the test build. Services must never set
// exchange base URLs from the environment.
func withTestBaseURL(c *Collector, base string) {
	for source, ep := range c.endpoints {
		ep.base = base
		c.endpoints[source] = ep
	}
}

func single(source Source) Schedule {
	every := time.Minute
	if source == Coinbase || source == Kraken {
		every = 5 * time.Minute
	}
	return Schedule{Sources: []Source{source}, Every: every}
}

func testHTTP(t *testing.T, source Source, h http.HandlerFunc, s *records) (*Collector, *bytes.Buffer) {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	cfg := testConfig(t)
	cfg.EgressProxy = server.URL
	var log bytes.Buffer
	c := newCollector(t, cfg, single(source), s, nil, &log)
	withTestBaseURL(c, server.URL)
	now := testMinute.Add(10*time.Second + 123456789)
	c.clock = clock{now: func() time.Time { return now }, waitUntil: func(_ context.Context, t time.Time) bool { now = t; return true }}
	return c, &log
}

func checkRaw(t *testing.T, raw *Raw, b []byte) {
	t.Helper()
	if raw == nil || raw.Size != len(b) || raw.SHA256 != sha256.Sum256(b) {
		t.Fatalf("incorrect raw response (%d bytes)", len(b))
	}
	z, err := gzip.NewReader(bytes.NewReader(raw.Gzip))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(z)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatal("gzip bytes differ", err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordedResponses(t *testing.T) {
	for _, tc := range []struct {
		source            Source
		value             string
		n                 int
		host, uri, method string
	}{
		{OKX, "6.71", 19, "www.okx.com", "/v3/c2c/tradingOrders/books?quoteCurrency=cny&baseCurrency=usdt&side=sell&paymentMethod=all&userType=all&receivingAds=false&limit=20", "GET"},
		{Binance, "6.7", 14, "p2p.binance.com", "/bapi/c2c/v2/friendly/c2c/adv/search", "POST"},
		{Coinbase, "0.99867", 1, "api.exchange.coinbase.com", "/products/USDT-USD/ticker", "GET"},
		{Kraken, "0.99866", 1, "api.kraken.com", "/0/public/Ticker?pair=USDTUSD", "GET"},
	} {
		t.Run(string(tc.source), func(t *testing.T) {
			b := fixture(t, tc.source)
			s := &records{}
			c, log := testHTTP(t, tc.source, func(w http.ResponseWriter, r *http.Request) {
				if !r.URL.IsAbs() || r.Method != tc.method || r.URL.RequestURI() != tc.uri || r.Header.Get("Accept") != "application/json" || r.UserAgent() != "kaivo-market-collector" {
					t.Errorf("wrong %s request", tc.source)
				}
				if tc.source == Binance {
					body, _ := io.ReadAll(r.Body)
					if r.Header.Get("Content-Type") != "application/json" || string(body) != `{"fiat":"CNY","page":1,"rows":20,"tradeType":"BUY","asset":"USDT","countries":[],"proMerchantAds":false,"shieldMerchantAds":false,"publisherType":null,"payTypes":[]}` {
						t.Error("wrong Binance query")
					}
				}
				w.Header().Set("Content-Encoding", "gzip")
				z := gzip.NewWriter(w)
				z.Write(b)
				z.Close()
			}, s)
			if endpoints()[tc.source].base != "https://"+tc.host {
				t.Error("incorrect production host")
			}
			c.collectMinute(t.Context(), testMinute)
			rs := s.all()
			if len(rs) != 1 {
				t.Fatal(len(rs))
			}
			r := rs[0]
			if r.Source != tc.source || r.Attempt != 1 || r.Outcome != OK || r.Minute != testMinute || r.Detail != "" {
				t.Fatal(r)
			}
			want := Observation{tc.source, testMinute, tc.value, tc.n, c.clock.now().Truncate(time.Microsecond)}
			if r.Observation == nil || *r.Observation != want {
				t.Fatalf("got %+v, want %+v", r.Observation, want)
			}
			checkRaw(t, r.Raw, b)
			if !strings.Contains(log.String(), hex.EncodeToString(r.Raw.SHA256[:])) || strings.Contains(log.String(), "http://") {
				t.Fatal("wrong log digest or URL leakage")
			}
		})
	}
}

func TestProxyPolicy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://unexpected.invalid:1234")
	t.Setenv("HTTP_PROXY", "http://unexpected.invalid:4321")
	t.Setenv("NO_PROXY", "*")
	cfg := testConfig(t)
	c := newCollector(t, cfg, single(OKX), &records{}, nil, io.Discard)
	tr := c.transport.(*http.Transport)
	for _, url := range []string{"https://www.okx.com", "http://localhost"} {
		req, _ := http.NewRequest("GET", url, nil)
		p, err := tr.Proxy(req)
		if err != nil || p.String() != cfg.EgressProxy {
			t.Fatal(p, err)
		}
	}
	if tr.TLSClientConfig.MinVersion != 0x0303 || tr.TLSClientConfig.RootCAs != nil || tr.TLSClientConfig.InsecureSkipVerify || c.settings.timeout != 10*time.Second {
		t.Fatal("TLS or timeout policy")
	}
}

func TestAttemptsAndRaw(t *testing.T) {
	ok := string(fixture(t, Coinbase))
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		source  Source
		outcome Outcome
		retry   bool
	}{
		{"429", 429, "rate limited", Coinbase, HTTPStatus, true},
		{"503", 503, "busy", Coinbase, HTTPStatus, true},
		{"400", 400, "sensitive response body", Coinbase, HTTPStatus, false},
		{"redirect", 302, "redirect", Coinbase, HTTPStatus, false},
		{"invalid redirect target", 307, "bad location", Coinbase, HTTPStatus, false},
		{"invalid", 200, "sensitive response body", Coinbase, ParseError, false},
		{"empty", 200, "", Coinbase, ParseError, false},
		{"oversize", 200, strings.Repeat("x", maxBody+10), Coinbase, ParseError, false},
		{"insufficient", 200, `{"code":"000000","success":true,"data":[]}`, Binance, InsufficientSamples, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := &records{}
			c, log := testHTTP(t, tc.source, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) > 1 {
					io.WriteString(w, ok)
					return
				}
				w.Header().Set("Location", "/redirected")
				if tc.status == 307 {
					w.Header().Set("Location", "http://[bad-location")
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}, s)
			c.collectMinute(t.Context(), testMinute)
			rs := s.all()
			want := 1
			if tc.retry {
				want = 2
			}
			if len(rs) != want || int(calls.Load()) != want || rs[0].Outcome != tc.outcome || rs[0].Observation != nil {
				t.Fatalf("calls=%d records=%+v", calls.Load(), rs)
			}
			checkRaw(t, rs[0].Raw, []byte(tc.body[:min(len(tc.body), maxBody)]))
			if len(rs[0].Detail) > 128 || strings.Contains(rs[0].Detail, "sensitive") || strings.Contains(log.String(), "sensitive") {
				t.Fatal("unsafe detail or log")
			}
			if tc.retry && (rs[1].Attempt != 2 || rs[1].Outcome != OK || rs[1].Minute != rs[0].Minute || rs[1].Observation.CollectedAt.Sub(testMinute) < 13*time.Second) {
				t.Fatal(rs[1])
			}
		})
	}
}

func TestRetryBounds(t *testing.T) {
	for _, tc := range []struct {
		name             string
		start, oversleep time.Duration
		calls            int
	}{
		{"before", 36 * time.Second, 0, 2}, {"exact cutoff", 37 * time.Second, 0, 1}, {"late", 42 * time.Second, 0, 1}, {"wakes too late", 36 * time.Second, time.Second, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &records{}
			c, _ := testHTTP(t, Coinbase, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, s)
			now := testMinute.Add(tc.start)
			c.clock.now = func() time.Time { return now }
			c.clock.waitUntil = func(_ context.Context, at time.Time) bool { now = at.Add(tc.oversleep); return true }
			c.collectMinute(t.Context(), testMinute)
			if len(s.all()) != tc.calls {
				t.Fatal(len(s.all()))
			}
		})
	}
}

func TestTransportAndIncompleteRead(t *testing.T) {
	for _, partial := range []bool{false, true} {
		s := &records{}
		var calls atomic.Int32
		c, log := testHTTP(t, Coinbase, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if partial {
				fmt.Fprint(rw, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabc")
				rw.Flush()
			}
			conn.Close()
		}, s)
		c.collectMinute(t.Context(), testMinute)
		rs := s.all()
		if partial {
			if len(rs) != 1 || rs[0].Outcome != ParseError || calls.Load() != 1 {
				t.Fatal(rs)
			}
			checkRaw(t, rs[0].Raw, []byte("abc"))
		} else if len(rs) != 0 || calls.Load() != 2 || strings.Count(log.String(), string(TransportError)) != 2 {
			t.Fatal(rs, log.String())
		}
	}
}

func TestSinkErrors(t *testing.T) {
	for _, err := range []error{fmt.Errorf("wrapped: %w", ErrDuplicate), errors.New("private DB URL")} {
		s := &records{err: err}
		c, log := testHTTP(t, Coinbase, func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{"price":"1"}`) }, s)
		outcome := "sink_error"
		writes := 3
		if errors.Is(err, ErrDuplicate) {
			outcome = "duplicate"
			writes = 1
		}
		if obs := c.collectSource(t.Context(), Coinbase, testMinute); obs != nil || len(s.all()) != writes {
			t.Fatalf("observation=%v writes=%d, want nil and %d", obs, len(s.all()), writes)
		}
		if !strings.Contains(log.String(), outcome) || strings.Contains(log.String(), "private") {
			t.Fatal(log.String())
		}
	}
}

func TestSinkRetryCutoffAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		start, oversleep time.Duration
		cancelDuringWait bool
		writes, waits    int
	}{
		{"retry-at-49s", 48 * time.Second, 0, false, 2, 1},
		{"retry-due-at-50s", 49 * time.Second, 0, false, 1, 0},
		{"already-past-50s", 51 * time.Second, 0, false, 1, 0},
		{"wake-at-50s", 48 * time.Second, time.Second, false, 1, 1},
		{"cancel-during-wait", 10 * time.Second, 0, true, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &records{err: errors.New("write failed")}
			c, _ := testHTTP(t, Coinbase, func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{"price":"1"}`) }, s)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			now := testMinute.Add(tc.start)
			waits := 0
			c.clock.now = func() time.Time { return now }
			c.clock.waitUntil = func(_ context.Context, at time.Time) bool {
				waits++
				now = at.Add(tc.oversleep)
				if tc.cancelDuringWait {
					cancel()
				}
				return true
			}
			if obs := c.collectSource(ctx, Coinbase, testMinute); obs != nil || len(s.all()) != tc.writes || waits != tc.waits {
				t.Fatalf("observation=%v writes=%d waits=%d", obs, len(s.all()), waits)
			}
		})
	}
}
