package marketdata

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
)

type clock struct {
	now       func() time.Time
	waitUntil func(context.Context, time.Time) bool
	jitter    func() time.Duration
}

func realClock() clock {
	return clock{
		now:    time.Now,
		jitter: func() time.Duration { return 5*time.Second + rand.N(10*time.Second+1) },
		waitUntil: func(ctx context.Context, target time.Time) bool {
			timer := time.NewTimer(time.Until(target))
			defer timer.Stop()
			select {
			case <-timer.C:
				return ctx.Err() == nil
			case <-ctx.Done():
				return false
			}
		},
	}
}

func (c clock) waitForRetry(ctx context.Context, delay time.Duration, cutoff time.Time) bool {
	at := c.now().Add(delay)
	return ctx.Err() == nil && at.Before(cutoff) && c.waitUntil(ctx, at) &&
		ctx.Err() == nil && c.now().Before(cutoff)
}

// Collector independently schedules the sources of one domain.
type Collector struct {
	settings  settings
	schedule  Schedule
	limit     *big.Rat
	endpoints map[Source]endpoint
	transport http.RoundTripper
	clock     clock
	sink      Sink
	log       *slog.Logger
	metrics   *metrics
	runMu     sync.Mutex
}

// NewCollector validates a domain schedule and binds its sink and telemetry.
// A nil provider disables metrics and a nil logger uses slog.Default.
func NewCollector(cfg Config, schedule Schedule, sink Sink, provider metric.MeterProvider, log *slog.Logger) (*Collector, error) {
	s, err := cfg.settings()
	if err != nil {
		return nil, err
	}
	if sink == nil {
		return nil, errors.New("market collector requires a sink")
	}
	limit, err := schedule.validate()
	if err != nil {
		return nil, err
	}
	m, err := newMetrics(provider)
	if err != nil {
		return nil, err
	}
	schedule.Sources = slices.Clone(schedule.Sources)
	if log == nil {
		log = slog.Default()
	}
	return &Collector{
		settings: s, schedule: schedule, limit: limit, endpoints: endpoints(),
		transport: newTransport(s.proxy, cfg.RequestTimeout), clock: realClock(),
		sink: sink, log: log, metrics: m,
	}, nil
}

func (s Schedule) validate() (*big.Rat, error) {
	if len(s.Sources) == 0 {
		return nil, errors.New("at least one market source required")
	}
	for i, source := range s.Sources {
		switch source {
		case OKX, Binance:
			if s.Every != time.Minute {
				return nil, errors.New("C2C sources require one-minute intervals")
			}
		case Coinbase, Kraken:
			if s.Every != 5*time.Minute {
				return nil, errors.New("ticker sources require five-minute intervals")
			}
		default:
			return nil, errors.New("unknown market source")
		}
		if slices.Contains(s.Sources[:i], source) {
			return nil, errors.New("duplicate market source")
		}
	}
	if s.Pair != [2]Source{} {
		if (s.Pair != [2]Source{OKX, Binance} && s.Pair != [2]Source{Coinbase, Kraken}) || !slices.Contains(s.Sources, s.Pair[0]) || !slices.Contains(s.Sources, s.Pair[1]) {
			return nil, errors.New("invalid market source pair")
		}
	}
	if s.MaxDeviation == "" {
		return nil, nil
	}
	if s.Pair == [2]Source{} || !inputDecimal.MatchString(s.MaxDeviation) {
		return nil, errors.New("MaxDeviation requires a pair and a nonnegative decimal")
	}
	return decimal(s.MaxDeviation)
}

func firstMinute(now time.Time, every time.Duration) time.Time {
	m := now.UTC().Truncate(every)
	if !now.Before(m.Add(40 * time.Second)) {
		return m.Add(every)
	}
	return m
}

// Run blocks until cancellation and waits for in-flight requests and Sink
// calls. Only one scheduler may run on this Collector at a time.
func (c *Collector) Run(ctx context.Context) error {
	if !c.runMu.TryLock() {
		return errors.New("market collector is already running")
	}
	defer c.runMu.Unlock()
	var wg sync.WaitGroup
	defer wg.Wait()
	every := c.schedule.Every
	for m := firstMinute(c.clock.now(), every); ctx.Err() == nil; {
		if !c.clock.waitUntil(ctx, m.Add(c.clock.jitter())) {
			break
		}
		now := c.clock.now()
		if ctx.Err() == nil && !now.Before(m) && now.Before(m.Add(40*time.Second)) {
			minute := m
			wg.Go(func() { c.collectMinute(ctx, minute) })
		}
		next := m.Add(every)
		m = firstMinute(c.clock.now(), every)
		if m.Before(next) {
			m = next
		}
	}
	return nil
}

func (c *Collector) collectMinute(ctx context.Context, minute time.Time) {
	observations := make([]*Observation, len(c.schedule.Sources))
	var wg sync.WaitGroup
	for i, source := range c.schedule.Sources {
		wg.Go(func() { observations[i] = c.collectSource(ctx, source, minute) })
	}
	wg.Wait()
	if c.schedule.Pair == [2]Source{} {
		return
	}
	a := observations[slices.Index(c.schedule.Sources, c.schedule.Pair[0])]
	b := observations[slices.Index(c.schedule.Sources, c.schedule.Pair[1])]
	if a != nil && b != nil {
		c.metrics.pair(ctx, a, b, c.limit)
	}
}

func (c *Collector) collectSource(ctx context.Context, source Source, minute time.Time) *Observation {
	for attempt := 1; attempt <= 2 && ctx.Err() == nil; attempt++ {
		start := c.clock.now()
		r := c.fetch(ctx, source, minute, attempt)
		duration := c.clock.now().Sub(start)
		outcome := c.recordOutcome(ctx, r.Result)
		digest := ""
		if r.Raw != nil {
			digest = hex.EncodeToString(r.Raw.SHA256[:])
		}
		c.metrics.attempt(ctx, r, outcome, duration)
		c.log.InfoContext(ctx, "market fetch", "source", source, "minute", minute, "attempt", attempt, "outcome", outcome, "samples", r.samples, "duration", duration, "sha256", digest)
		if outcome == string(OK) {
			return r.Observation
		}
		if !r.retry || attempt == 2 || outcome != string(r.Outcome) {
			break
		}
		if !c.clock.waitForRetry(ctx, 3*time.Second, minute.Add(40*time.Second)) {
			break
		}
	}
	return nil
}

func (c *Collector) recordOutcome(ctx context.Context, r Result) string {
	for write := 1; ; write++ {
		outcome := string(r.Outcome)
		if r.Raw != nil {
			switch err := c.sink.Record(ctx, r); {
			case errors.Is(err, ErrDuplicate):
				outcome = "duplicate"
			case err != nil:
				outcome = "sink_error"
			}
		}
		c.metrics.countOutcome(ctx, r.Source, outcome)
		if outcome != "sink_error" || write == 3 || !c.clock.waitForRetry(ctx, time.Second, r.Minute.Add(50*time.Second)) {
			return outcome
		}
	}
}
