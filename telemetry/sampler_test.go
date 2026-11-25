package telemetry

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestSamplerCacheFailureAndTimeout(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	var logs bytes.Buffer
	s := NewSampler(provider, Options{Interval: 100 * time.Millisecond, Timeout: 25 * time.Millisecond, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	var fail atomic.Bool
	var count atomic.Int64
	attrs := attribute.NewSet(attribute.String("status", "pending"))
	if err := s.RegisterInt64("orders", "kaivo.payment.orders", []string{"status"}, func(ctx context.Context) ([]Point[int64], error) {
		count.Add(1)
		if fail.Load() {
			return nil, errors.New("sensitive database error")
		}
		return []Point[int64]{{Value: 12, Attributes: attrs}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var calls atomic.Int64
	if err := s.RegisterSeconds("age", "kaivo.payment.age", nil, func(ctx context.Context) ([]Point[float64], error) {
		calls.Add(1)
		<-release // Deliberately ignores deadline. Run must still stop.
		return []Point[float64]{{Value: 42}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() {
		stop()
		<-done
		close(release)
		if strings.Contains(logs.String(), "sensitive") {
			t.Fatal("raw error logged")
		}
	}()
	snapshot := func() (ok bool, failures map[string]int64) {
		t.Helper()
		var data metricdata.ResourceMetrics
		if err := reader.Collect(ctx, &data); err != nil {
			t.Fatal(err)
		}
		failures = map[string]int64{}
		for _, scope := range data.ScopeMetrics {
			for _, m := range scope.Metrics {
				switch m.Name {
				case "kaivo.payment.orders":
					p := m.Data.(metricdata.Gauge[int64]).DataPoints[0]
					if p.Value != 12 || p.Attributes != attrs || m.Unit != "" {
						t.Fatal(m)
					}
					ok = true
				case "kaivo.metrics.sample.failures":
					if m.Unit != "" {
						t.Fatal(m)
					}
					for _, p := range m.Data.(metricdata.Sum[int64]).DataPoints {
						v, found := p.Attributes.Value("sampler")
						if !found || p.Attributes.Len() != 1 {
							t.Fatal(p)
						}
						failures[v.AsString()] = p.Value
					}
				default:
					t.Fatal("unexpected metric", m.Name)
				}
			}
		}
		return
	}
	until := func(want func() bool) {
		t.Helper()
		deadline := time.Now().Add(time.Second * 3)
		for !want() {
			if time.Now().After(deadline) {
				t.Fatal("sample did not converge")
			}
			time.Sleep(time.Millisecond)
		}
	}
	until(func() bool { ok, f := snapshot(); return ok && f["age"] >= 1 })
	before := count.Load()
	for range 5 {
		if ok, _ := snapshot(); !ok {
			t.Fatal("cache lost")
		}
	}
	if count.Load() > before+1 {
		t.Fatal("collection triggered queries")
	}
	fail.Store(true)
	until(func() bool { ok, f := snapshot(); return !ok && f["orders"] > 0 && f["age"] >= 2 })
	if calls.Load() != 1 {
		t.Fatal("timed out queries accumulated")
	}
}

func TestRegistrationAndNilProvider(t *testing.T) {
	s := NewSampler(nil, Options{})
	if s.opts.Interval != 30*time.Second || s.opts.Timeout != 5*time.Second {
		t.Fatal(s.opts)
	}
	sample := func(context.Context) ([]Point[int64], error) {
		t.Error("nil provider executed sampler")
		return nil, nil
	}
	for _, tc := range []struct {
		name, metric string
		keys         []string
	}{
		{"With.dot", "kaivo.a", nil}, {"ok", "kaivo..a", nil}, {"ok", "kaivo.A", nil}, {"ok", "kaivo.a", []string{"bad.key"}}, {"ok", "kaivo.a", []string{"same", "same"}},
	} {
		if s.RegisterInt64(tc.name, tc.metric, tc.keys, sample) == nil {
			t.Fatal(tc)
		}
	}
	if err := s.RegisterInt64("a", "kaivo.a", nil, sample); err != nil {
		t.Fatal(err)
	}
	if len(s.jobs) != 0 {
		t.Fatal("disabled sampler registered background work")
	}
}

func TestSecondsAndUnregisteredAttribute(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	s := NewSampler(mp, Options{Interval: time.Hour})
	if err := s.RegisterSeconds("age", "kaivo.test.age", nil, func(context.Context) ([]Point[float64], error) { return []Point[float64]{{Value: 1.25}}, nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterInt64("count", "kaivo.test.count", []string{"status"}, func(context.Context) ([]Point[int64], error) {
		return []Point[int64]{{Attributes: attribute.NewSet(attribute.String("unregistered", "x")), Value: 8}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() { stop(); <-done }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var data metricdata.ResourceMetrics
		if err := reader.Collect(ctx, &data); err != nil {
			t.Fatal(err)
		}
		age, failed := false, false
		for _, scope := range data.ScopeMetrics {
			for _, m := range scope.Metrics {
				switch m.Name {
				case "kaivo.test.age":
					p := m.Data.(metricdata.Gauge[float64]).DataPoints[0]
					age = m.Unit == "s" && p.Value == 1.25 && p.Attributes.Len() == 0
				case "kaivo.metrics.sample.failures":
					p := m.Data.(metricdata.Sum[int64]).DataPoints[0]
					failed = p.Value == 1 && p.Attributes == attribute.NewSet(attribute.String("sampler", "count"))
				default:
					t.Fatalf("unexpected gauge %s", m.Name)
				}
			}
		}
		if age && failed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("missing immediately sampled gauges")
}
