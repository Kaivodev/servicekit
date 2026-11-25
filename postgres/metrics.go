package postgres

import (
	"context"
	"errors"
	"regexp"

	"github.com/Kaivodev/servicekit/internal/instruments"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var poolName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// ObservePool reads one in-memory Stat snapshot per collection. Unregister
// before closing the pool or reusing the same label for a replacement pool.
func ObservePool(provider metric.MeterProvider, pool string, p *pgxpool.Pool) (unregister func() error, err error) {
	if !poolName.MatchString(pool) || p == nil {
		return nil, errors.New("invalid pool observation configuration")
	}
	m := instruments.Meter(provider, "postgres")
	conns, e1 := m.Int64ObservableGauge("kaivo.db.pool.connections")
	maxConns, e2 := m.Int64ObservableGauge("kaivo.db.pool.max_connections")
	acquires, e3 := m.Int64ObservableCounter("kaivo.db.pool.acquires")
	empty, e4 := m.Int64ObservableCounter("kaivo.db.pool.empty_acquires")
	wait, e5 := m.Float64ObservableCounter("kaivo.db.pool.empty_acquire.wait", metric.WithUnit("s"))
	canceled, e6 := m.Int64ObservableCounter("kaivo.db.pool.canceled_acquires")
	if errors.Join(e1, e2, e3, e4, e5, e6) != nil {
		return nil, errors.New("create pool metrics failed")
	}
	label := attribute.String("pool", pool)
	opts := metric.WithAttributes(label)
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		s := p.Stat()
		o.ObserveInt64(conns, int64(s.IdleConns()), metric.WithAttributes(label, attribute.String("state", "idle")))
		o.ObserveInt64(conns, int64(s.AcquiredConns()), metric.WithAttributes(label, attribute.String("state", "acquired")))
		o.ObserveInt64(conns, int64(s.ConstructingConns()), metric.WithAttributes(label, attribute.String("state", "constructing")))
		o.ObserveInt64(maxConns, int64(s.MaxConns()), opts)
		o.ObserveInt64(acquires, s.AcquireCount(), opts)
		o.ObserveInt64(empty, s.EmptyAcquireCount(), opts)
		o.ObserveFloat64(wait, s.EmptyAcquireWaitTime().Seconds(), opts)
		o.ObserveInt64(canceled, s.CanceledAcquireCount(), opts)
		return nil
	}, conns, maxConns, acquires, empty, wait, canceled)
	if err != nil {
		return nil, errors.New("register pool metrics failed")
	}
	return reg.Unregister, nil
}
