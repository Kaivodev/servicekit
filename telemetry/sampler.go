// Package telemetry samples service-owned gauges outside the metrics export path.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kaivodev/servicekit/internal/instruments"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type Options struct {
	Interval, Timeout time.Duration
	Log               *slog.Logger
}

// Point contains an immutable set of registered labels. Values must come from
// deployment configuration or fixed enums controlled by the registering service.
type Point[T int64 | float64] struct {
	Attributes attribute.Set
	Value      T
}

type Sampler struct {
	opts     Options
	meter    metric.Meter
	failures metric.Int64Counter
	disabled bool
	mu       sync.Mutex
	running  bool
	jobs     []func(context.Context)
}

func NewSampler(provider metric.MeterProvider, opts Options) *Sampler {
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	meter := instruments.Meter(provider, "telemetry")
	failures, _ := meter.Int64Counter("kaivo.metrics.sample.failures")
	return &Sampler{opts: opts, meter: meter, failures: failures, disabled: provider == nil}
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// RegisterInt64 registers a unitless gauge. Register all gauges before Run.
func (s *Sampler) RegisterInt64(name, instrument string, keys []string, sample func(context.Context) ([]Point[int64], error)) error {
	return register(s, name, instrument, keys, sample, func(g *sampledGauge[int64]) (metric.Registration, error) {
		gauge, err := s.meter.Int64ObservableGauge(instrument)
		if err != nil {
			return nil, err
		}
		return s.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
			for _, p := range g.points() {
				o.ObserveInt64(gauge, p.Value, metric.WithAttributeSet(p.Attributes))
			}
			return nil
		}, gauge)
	})
}

// RegisterSeconds registers a floating-point gauge in seconds.
func (s *Sampler) RegisterSeconds(name, instrument string, keys []string, sample func(context.Context) ([]Point[float64], error)) error {
	return register(s, name, instrument, keys, sample, func(g *sampledGauge[float64]) (metric.Registration, error) {
		gauge, err := s.meter.Float64ObservableGauge(instrument, metric.WithUnit("s"))
		if err != nil {
			return nil, err
		}
		return s.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
			for _, p := range g.points() {
				o.ObserveFloat64(gauge, p.Value, metric.WithAttributeSet(p.Attributes))
			}
			return nil
		}, gauge)
	})
}

type sampledGauge[T int64 | float64] struct {
	keys   []attribute.Key
	sample func(context.Context) ([]Point[T], error)
	cache  atomic.Pointer[[]Point[T]]
	busy   atomic.Bool
}

func (g *sampledGauge[T]) points() []Point[T] {
	if p := g.cache.Load(); p != nil {
		return *p
	}
	return nil
}

func register[T int64 | float64](s *Sampler, name, instrument string, keys []string, sample func(context.Context) ([]Point[T], error), bind func(*sampledGauge[T]) (metric.Registration, error)) error {
	if !identifier.MatchString(name) || instrument == "" || len(instrument) > 255 || sample == nil {
		return errors.New("invalid sampler registration")
	}
	for part := range strings.SplitSeq(instrument, ".") {
		if !identifier.MatchString(part) {
			return errors.New("invalid gauge name")
		}
	}
	g := &sampledGauge[T]{sample: sample}
	for _, k := range keys {
		key := attribute.Key(k)
		if !identifier.MatchString(k) || slices.Contains(g.keys, key) {
			return errors.New("invalid sampler attribute")
		}
		g.keys = append(g.keys, key)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("register gauges before running the sampler")
	}
	if !s.disabled {
		s.jobs = append(s.jobs, func(ctx context.Context) {
			reg, err := bind(g)
			if err != nil {
				s.failed(ctx, name)
				return
			}
			defer reg.Unregister()
			ticker := time.NewTicker(s.opts.Interval)
			defer ticker.Stop()
			for ctx.Err() == nil {
				query, cancel := context.WithTimeout(ctx, s.opts.Timeout)
				ok := g.refresh(query)
				cancel()
				if !ok && ctx.Err() == nil {
					s.failed(ctx, name)
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		})
	}
	return nil
}

// One outstanding query per registration, even if owner code ignores its
// deadline. Late results cannot overwrite subsequent samples.
func (g *sampledGauge[T]) refresh(ctx context.Context) bool {
	var snapshot *[]Point[T]
	if g.busy.CompareAndSwap(false, true) {
		result := make(chan *[]Point[T], 1)
		go func() {
			points := g.read(ctx)
			g.busy.Store(false)
			result <- points
		}()
		select {
		case snapshot = <-result:
		case <-ctx.Done():
		}
	}
	if ctx.Err() != nil {
		snapshot = nil
	}
	g.cache.Store(snapshot)
	return snapshot != nil
}

func (g *sampledGauge[T]) read(ctx context.Context) (snapshot *[]Point[T]) {
	defer func() {
		if recover() != nil {
			snapshot = nil
		}
	}()
	points, err := g.sample(ctx)
	if err != nil {
		return nil
	}
	for _, p := range points {
		if p.Attributes.Len() != len(g.keys) {
			return nil
		}
		for _, k := range g.keys {
			if !p.Attributes.HasValue(k) {
				return nil
			}
		}
	}
	points = slices.Clone(points)
	return &points
}

func (s *Sampler) failed(ctx context.Context, name string) {
	s.failures.Add(ctx, 1, metric.WithAttributes(attribute.String("sampler", name)))
	s.opts.Log.WarnContext(ctx, "metric sample failed", "sampler", name)
}

// Run samples immediately and until cancellation. Start it in a goroutine with
// the service lifecycle context. Export callbacks only read completed samples.
func (s *Sampler) Run(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	jobs := slices.Clone(s.jobs)
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Go(func() { job(ctx) })
	}
	<-ctx.Done()
	wg.Wait()
}
