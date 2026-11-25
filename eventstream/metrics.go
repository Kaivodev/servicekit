package eventstream

import (
	"context"
	"errors"
	"math"
	"strings"

	"github.com/Kaivodev/servicekit/internal/instruments"
	"github.com/Kaivodev/servicekit/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ObserveLag exports the most recent successful CheckHead comparison.
func (p *Puller) ObserveLag(provider metric.MeterProvider) (func() error, error) {
	m := instruments.Meter(provider, "eventstream")
	g, err := m.Int64ObservableGauge("kaivo.eventstream.lag.events")
	if err != nil {
		return nil, errors.New("create event lag gauge failed")
	}
	opts := metric.WithAttributes(attribute.String("stream", p.verifier.Stream))
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		if p.hasLag.Load() {
			o.ObserveInt64(g, int64(min(p.lag.Load(), uint64(math.MaxInt64))), opts)
		}
		return nil
	}, g)
	if err != nil {
		return nil, errors.New("register event lag gauge failed")
	}
	return reg.Unregister, nil
}

// RegisterSamples registers cached gauges for a single configured receiver.
func RegisterReceiverSamples(s *telemetry.Sampler, db DB, t ReceiverTables, stream string) error {
	cursors, inbox, err := t.sanitize()
	if err != nil || s == nil || db == nil || !ValidStream(stream) {
		return errors.New("invalid receiver sample configuration")
	}
	label := attribute.String("stream", stream)
	suffix := strings.ReplaceAll(stream, ".", "_")
	args := []any{stream}
	// A receiver whose cursor row is not seeded yet is not stopped; report 0
	// instead of counting a sample failure on every interval.
	if err := registerInt(s, db, "stopped_"+suffix, "kaivo.eventstream.stopped", label, "SELECT coalesce((SELECT (state = 'stopped')::int FROM "+cursors+" WHERE stream = $1), 0)", args); err != nil {
		return err
	}
	return registerPending(s, db, "inbox_"+suffix, "kaivo.eventstream.inbox", label, " FROM "+inbox+" WHERE stream = $1 AND status = 'pending'", args)
}

// RegisterOutboxSamples registers the backlog of one signed-event outbox.
func RegisterOutboxSamples(s *telemetry.Sampler, db DB, outbox string) error {
	quoted, err := table(outbox)
	if err != nil || s == nil || db == nil {
		return errors.New("invalid outbox sample configuration")
	}
	return registerPending(s, db, outbox, "kaivo.outbox", attribute.String("outbox", outbox), " FROM "+quoted+" WHERE sequence IS NULL", nil)
}

func registerPending(s *telemetry.Sampler, db DB, name, prefix string, label attribute.KeyValue, from string, args []any) error {
	if err := registerInt(s, db, name+"_pending", prefix+".pending", label, "SELECT count(*)"+from, args); err != nil {
		return err
	}
	attrs := attribute.NewSet(label)
	return s.RegisterSeconds(name+"_oldest_pending", prefix+".oldest_pending", []string{string(label.Key)}, func(ctx context.Context) ([]telemetry.Point[float64], error) {
		var age float64
		err := db.QueryRow(ctx, "SELECT coalesce(extract(epoch FROM now() - min(recorded_at)), 0)::float8"+from, args...).Scan(&age)
		return []telemetry.Point[float64]{{Attributes: attrs, Value: age}}, err
	})
}

func registerInt(s *telemetry.Sampler, db DB, name, instrument string, label attribute.KeyValue, sql string, args []any) error {
	attrs := attribute.NewSet(label)
	return s.RegisterInt64(name, instrument, []string{string(label.Key)}, func(ctx context.Context) ([]telemetry.Point[int64], error) {
		var n int64
		err := db.QueryRow(ctx, sql, args...).Scan(&n)
		return []telemetry.Point[int64]{{Attributes: attrs, Value: n}}, err
	})
}
