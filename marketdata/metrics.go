package marketdata

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/Kaivodev/servicekit/internal/instruments"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type metrics struct {
	fetches                    metric.Int64Counter
	duration                   metric.Float64Histogram
	samples                    metric.Int64Gauge
	success, deviation, usable metric.Float64Gauge

	// Older minutes may complete after newer minutes. Keep gauges ordered by
	// their target minute, independently for each series.
	mu                        sync.Mutex
	lastSamples, lastSuccess  map[Source]time.Time
	lastDeviation, lastUsable time.Time
}

func newMetrics(provider metric.MeterProvider) (*metrics, error) {
	m := instruments.Meter(provider, "marketdata")
	g := &metrics{lastSamples: make(map[Source]time.Time), lastSuccess: make(map[Source]time.Time)}
	var errs [6]error
	g.fetches, errs[0] = m.Int64Counter("kaivo.market.fetches")
	g.duration, errs[1] = m.Float64Histogram("kaivo.market.fetch.duration", metric.WithUnit("s"))
	g.samples, errs[2] = m.Int64Gauge("kaivo.market.samples")
	g.success, errs[3] = m.Float64Gauge("kaivo.market.last_success.timestamp", metric.WithUnit("s"))
	g.deviation, errs[4] = m.Float64Gauge("kaivo.market.deviation", metric.WithUnit("1"))
	g.usable, errs[5] = m.Float64Gauge("kaivo.market.usable_minute.timestamp", metric.WithUnit("s"))
	return g, errors.Join(errs[:]...)
}

func (m *metrics) countOutcome(ctx context.Context, source Source, outcome string) {
	m.fetches.Add(ctx, 1, metric.WithAttributes(attribute.String("source", string(source)), attribute.String("outcome", outcome)))
}

func (m *metrics) attempt(ctx context.Context, r attemptResult, outcome string, elapsed time.Duration) {
	label := metric.WithAttributes(attribute.String("source", string(r.Source)))
	m.duration.Record(ctx, elapsed.Seconds(), label)
	m.mu.Lock()
	defer m.mu.Unlock()
	if (r.Outcome == OK || r.Outcome == InsufficientSamples) && !r.Minute.Before(m.lastSamples[r.Source]) {
		m.samples.Record(ctx, int64(r.samples), label)
		m.lastSamples[r.Source] = r.Minute
	}
	if outcome == string(OK) && r.Minute.After(m.lastSuccess[r.Source]) {
		m.success.Record(ctx, float64(r.Minute.Unix()), label)
		m.lastSuccess[r.Source] = r.Minute
	}
}

func (m *metrics) pair(ctx context.Context, a, b *Observation, limit *big.Rat) {
	ref, _ := new(big.Rat).SetString(a.Value)
	value, _ := new(big.Rat).SetString(b.Value)
	diff := new(big.Rat).Sub(value, ref)
	diff.Quo(diff.Abs(diff), ref)
	label := metric.WithAttributes(attribute.String("pair", string(a.Source)+"_"+string(b.Source)))
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.Minute.After(m.lastDeviation) {
		v, _ := diff.Float64() // Only the exported measurement is floating point.
		m.deviation.Record(ctx, v, label)
		m.lastDeviation = a.Minute
	}
	if limit != nil && diff.Cmp(limit) <= 0 && a.Minute.After(m.lastUsable) {
		m.usable.Record(ctx, float64(a.Minute.Unix()), label)
		m.lastUsable = a.Minute
	}
}
