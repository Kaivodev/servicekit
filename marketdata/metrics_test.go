package marketdata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func readMetrics(t *testing.T, r *sdk.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var data metricdata.ResourceMetrics
	if err := r.Collect(t.Context(), &data); err != nil {
		t.Fatal(err)
	}
	m := map[string]metricdata.Metrics{}
	for _, scope := range data.ScopeMetrics {
		if scope.Scope.Name != "github.com/Kaivodev/servicekit/marketdata" {
			t.Fatal(scope.Scope.Name)
		}
		for _, v := range scope.Metrics {
			m[v.Name] = v
		}
	}
	return m
}

func labels(t *testing.T, s attribute.Set, expected map[string][]string) {
	t.Helper()
	if s.Len() != len(expected) {
		t.Fatalf("unexpected attributes: %v", s.ToSlice())
	}
	for key, values := range expected {
		v, ok := s.Value(attribute.Key(key))
		if !ok {
			t.Fatal("missing attribute", key)
		}
		found := false
		for _, allowed := range values {
			if v.AsString() == allowed {
				found = true
			}
		}
		if !found {
			t.Fatalf("unexpected %s=%v", key, v)
		}
	}
}

func TestPairMetrics(t *testing.T) {
	reader := sdk.NewManualReader()
	provider := sdk.NewMeterProvider(sdk.WithReader(reader))
	defer provider.Shutdown(t.Context())
	cfg := testConfig(t)
	s := Schedule{Sources: []Source{Coinbase, Kraken}, Pair: [2]Source{Coinbase, Kraken}, Every: 5 * time.Minute, MaxDeviation: "0.01"}
	sink := &records{}
	c := newCollector(t, cfg, s, sink, provider, io.Discard)
	c.clock.now = func() time.Time { return testMinute.Add(20 * time.Minute) }
	base, other := "1", "1.01"
	c.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := fmt.Sprintf(`{"price":"%s"}`, base)
		if r.URL.Host == "api.kraken.com" {
			body = fmt.Sprintf(`{"error":[],"result":{"USDTZUSD":{"c":["%s"]}}}`, other)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	c.collectMinute(t.Context(), testMinute)
	next := testMinute.Add(5 * time.Minute)
	base, other = "1.01", "0.9998999999" // just outside 1%
	c.collectMinute(t.Context(), next)
	base, other = "1", "1.001"
	c.collectMinute(t.Context(), testMinute.Add(-5*time.Minute))
	sink.err = fmt.Errorf("wrapped: %w", ErrDuplicate)
	c.collectMinute(t.Context(), next.Add(5*time.Minute))
	sink.err = errors.New("transaction failed")
	c.collectMinute(t.Context(), next.Add(10*time.Minute))

	m := readMetrics(t, reader)
	units := map[string]string{"kaivo.market.fetches": "", "kaivo.market.samples": "", "kaivo.market.fetch.duration": "s", "kaivo.market.last_success.timestamp": "s", "kaivo.market.deviation": "1", "kaivo.market.usable_minute.timestamp": "s"}
	if len(units) != len(m) {
		t.Fatal(m)
	}
	for name, want := range units {
		v, ok := m[name]
		if !ok || v.Unit != want {
			t.Fatal(name, v.Unit)
		}
	}
	sources := []string{"coinbase", "kraken"}
	source := map[string][]string{"source": sources}
	counter := m["kaivo.market.fetches"].Data.(metricdata.Sum[int64])
	if !counter.IsMonotonic || len(counter.DataPoints) != 6 {
		t.Fatal(counter)
	}
	for _, p := range counter.DataPoints {
		labels(t, p.Attributes, map[string][]string{"source": sources, "outcome": {"ok", "duplicate", "sink_error"}})
		o, _ := p.Attributes.Value("outcome")
		want := int64(1)
		if o.AsString() == "ok" {
			want = 3
		}
		if p.Value != want {
			t.Fatal(p)
		}
	}
	for _, p := range m["kaivo.market.fetch.duration"].Data.(metricdata.Histogram[float64]).DataPoints {
		labels(t, p.Attributes, source)
		if p.Count != 5 {
			t.Fatal(p)
		}
	}
	for _, p := range m["kaivo.market.samples"].Data.(metricdata.Gauge[int64]).DataPoints {
		labels(t, p.Attributes, source)
		if p.Value != 1 {
			t.Fatal(p)
		}
	}
	for _, p := range m["kaivo.market.last_success.timestamp"].Data.(metricdata.Gauge[float64]).DataPoints {
		labels(t, p.Attributes, source)
		if p.Value != float64(next.Unix()) {
			t.Fatal(p)
		}
	}
	pair := map[string][]string{"pair": {"coinbase_kraken"}}
	for name, want := range map[string]float64{"kaivo.market.deviation": (1.01 - 0.9998999999) / 1.01, "kaivo.market.usable_minute.timestamp": float64(testMinute.Unix())} {
		points := m[name].Data.(metricdata.Gauge[float64]).DataPoints
		if len(points) != 1 || math.Abs(points[0].Value-want) > 1e-12 {
			t.Fatal(name, points)
		}
		labels(t, points[0].Attributes, pair)
	}
}

func TestSinkWriteRetries(t *testing.T) {
	writeErr := errors.New("write failed")
	duplicate := fmt.Errorf("already committed: %w", ErrDuplicate)
	for _, tc := range []struct {
		name, body string
		status     int
		writes     []error
		final      string
	}{
		{"ok-third", `{"price":"1"}`, 200, []error{writeErr, writeErr, nil}, "ok"},
		{"exhausted", `{"price":"1"}`, 200, []error{writeErr, writeErr, writeErr}, "sink_error"},
		{"duplicate-on-retry", `{"price":"1"}`, 200, []error{writeErr, duplicate}, "duplicate"},
		{"stored-parse-error", `{}`, 200, []error{writeErr, nil}, "parse_error"},
		{"unstored-503", "busy", 503, []error{writeErr, writeErr, writeErr}, "sink_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := sdk.NewManualReader()
			provider := sdk.NewMeterProvider(sdk.WithReader(reader))
			defer provider.Shutdown(t.Context())
			start := testMinute.Add(10 * time.Second)
			now := start
			var first Result
			writes, fetches := 0, 0
			sink := sinkFunc(func(_ context.Context, r Result) error {
				if writes == 0 {
					first = r
				}
				if r != first || writes >= len(tc.writes) || now.Sub(start) != time.Duration(writes)*time.Second {
					t.Fatalf("unexpected Record call %d at %s, fetch attempt %d", writes+1, now, r.Attempt)
				}
				err := tc.writes[writes]
				writes++
				return err
			})
			c := newCollector(t, testConfig(t), single(Coinbase), sink, provider, io.Discard)
			c.clock.now = func() time.Time { return now }
			c.clock.waitUntil = func(_ context.Context, at time.Time) bool { now = at; return true }
			c.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				fetches++
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			obs := c.collectSource(t.Context(), Coinbase, testMinute)
			if fetches != 1 || writes != len(tc.writes) || (obs != nil) != (tc.final == "ok") {
				t.Fatalf("fetches=%d writes=%d observation=%v", fetches, writes, obs)
			}
			m := readMetrics(t, reader)
			counts := map[string]int64{}
			for _, p := range m["kaivo.market.fetches"].Data.(metricdata.Sum[int64]).DataPoints {
				outcome, _ := p.Attributes.Value("outcome")
				counts[outcome.AsString()] = p.Value
			}
			want := map[string]int64{"sink_error": int64(writes - 1)}
			want[tc.final]++
			if !maps.Equal(counts, want) {
				t.Fatalf("fetches by outcome=%v, want %v", counts, want)
			}
			if p := m["kaivo.market.fetch.duration"].Data.(metricdata.Histogram[float64]).DataPoints; len(p) != 1 || p[0].Count != 1 {
				t.Fatal("fetch duration count", p)
			}
			success, ok := m["kaivo.market.last_success.timestamp"]
			if ok != (tc.final == "ok") || ok && success.Data.(metricdata.Gauge[float64]).DataPoints[0].Value != float64(testMinute.Unix()) {
				t.Fatal("last success", success)
			}
		})
	}
}

func TestFailureMetrics(t *testing.T) {
	reader := sdk.NewManualReader()
	provider := sdk.NewMeterProvider(sdk.WithReader(reader))
	defer provider.Shutdown(t.Context())
	c := newCollector(t, testConfig(t), single(OKX), &records{}, provider, io.Discard)
	c.clock.now = func() time.Time { return testMinute.Add(41 * time.Second) }
	for _, outcome := range []Outcome{TransportError, HTTPStatus, ParseError, InsufficientSamples} {
		c.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			switch outcome {
			case TransportError:
				return nil, context.DeadlineExceeded
			case HTTPStatus:
				return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
			case InsufficientSamples:
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"sell":[]}}`))}, nil
			default:
				return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
			}
		})
		c.collectMinute(t.Context(), testMinute)
	}
	m := readMetrics(t, reader)
	p := m["kaivo.market.fetches"].Data.(metricdata.Sum[int64]).DataPoints
	if len(p) != 4 {
		t.Fatal(p)
	}
	for _, v := range p {
		labels(t, v.Attributes, map[string][]string{"source": {"okx"}, "outcome": {"transport_error", "parse_error", "insufficient_samples", "http_status"}})
	}
	if m["kaivo.market.samples"].Data.(metricdata.Gauge[int64]).DataPoints[0].Value != 0 {
		t.Fatal("wrong insufficient sample count")
	}
}

func TestPairRequiresBothCommittedSources(t *testing.T) {
	bodies := map[string]string{"www.okx.com": string(fixture(t, OKX)), "p2p.binance.com": string(fixture(t, Binance))}
	for _, tc := range []struct {
		name, limit               string
		binanceFailures           int
		wantDeviation, wantUsable bool
	}{
		{"CNY within threshold", "0.01", 0, true, true},
		{"deviation without threshold", "", 0, true, false},
		{"one source fails all writes", "0.01", 3, false, false},
		{"one source succeeds on retry", "0.01", 2, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				reader := sdk.NewManualReader()
				provider := sdk.NewMeterProvider(sdk.WithReader(reader))
				defer provider.Shutdown(t.Context())
				sink := sinkFunc(func(_ context.Context, r Result) error {
					if r.Source == Binance && tc.binanceFailures > 0 {
						tc.binanceFailures--
						return errors.New("failed insert")
					}
					return nil
				})
				// The order of requested sources must not change the reference price.
				s := Schedule{Sources: []Source{Binance, OKX}, Every: time.Minute, Pair: [2]Source{OKX, Binance}, MaxDeviation: tc.limit}
				c := newCollector(t, testConfig(t), s, sink, provider, io.Discard)
				c.clock = mockClock(testMinute.Add(10 * time.Second))
				c.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(bodies[r.URL.Host]))}, nil
				})
				c.collectMinute(t.Context(), testMinute)
				m := readMetrics(t, reader)
				dev, ok := m["kaivo.market.deviation"]
				if ok != tc.wantDeviation {
					t.Fatal("unexpected deviation series")
				}
				if ok {
					d := dev.Data.(metricdata.Gauge[float64]).DataPoints
					if len(d) != 1 || math.Abs(d[0].Value-0.01/6.71) > 1e-12 {
						t.Fatal(d)
					}
					labels(t, d[0].Attributes, map[string][]string{"pair": {"okx_binance"}})
				}
				if _, ok := m["kaivo.market.usable_minute.timestamp"]; ok != tc.wantUsable {
					t.Fatal("unexpected usable minute series")
				}
			})
		})
	}
}
