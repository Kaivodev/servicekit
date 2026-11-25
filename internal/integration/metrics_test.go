//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Kaivodev/observability/asynqobs"
	"github.com/Kaivodev/servicekit/eventstream"
	"github.com/Kaivodev/servicekit/queue"
	"github.com/Kaivodev/servicekit/telemetry"
	"github.com/hibiken/asynq"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/trace/noop"
)

func readMetrics(t *testing.T, r *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var data metricdata.ResourceMetrics
	if err := r.Collect(t.Context(), &data); err != nil {
		t.Fatal("collect metrics failed")
	}
	out := map[string]metricdata.Metrics{}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func TestQueueInspectorMetrics(t *testing.T) {
	cfg := testQueueConfig(t)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	tp := noop.NewTracerProvider()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	producer, err := queue.NewProducer(t.Context(), cfg, tp, log, queue.ProducerOptions{MeterProvider: mp, TaskTypes: []string{"work"}})
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	enqueue := func(options ...asynq.Option) {
		t.Helper()
		if _, err := producer.Enqueue(t.Context(), asynqobs.Message{Type: "work"}, options...); err != nil {
			t.Fatal(err)
		}
	}
	enqueue()
	enqueue(asynq.ProcessIn(time.Hour))
	before := readMetrics(t, reader)
	if len(before) != 1 || before["kaivo.queue.enqueued"].Name == "" {
		t.Fatalf("producer instruments: %v", before)
	}
	worker, err := queue.NewWorker(t.Context(), cfg, tp, log, log, asynq.HandlerFunc(func(context.Context, *asynq.Task) error { return nil }), queue.WorkerOptions{MeterProvider: mp})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	metrics := readMetrics(t, reader)
	tasks := metrics["kaivo.queue.tasks"]
	states := map[string]int64{"pending": 1, "active": 0, "scheduled": 1, "retry": 0, "archived": 0}
	label := attribute.String("queue", cfg.Name)
	for _, p := range tasks.Data.(metricdata.Gauge[int64]).DataPoints {
		value, _ := p.Attributes.Value("state")
		state := value.AsString()
		expected, ok := states[state]
		if !ok || p.Value != expected || tasks.Unit != "" || p.Attributes != attribute.NewSet(label, attribute.String("state", state)) {
			t.Fatal(p)
		}
		delete(states, state)
	}
	if len(states) != 0 {
		t.Fatal(states)
	}
	latency := metrics["kaivo.queue.latency"]
	points := latency.Data.(metricdata.Gauge[float64]).DataPoints
	if len(points) != 1 || points[0].Attributes != attribute.NewSet(label) || points[0].Value < 0 || latency.Unit != "s" {
		t.Fatal(latency)
	}
	worker.Close()
	if len(readMetrics(t, reader)) != 1 {
		t.Fatal("inspector still registered")
	}
}

// checkEventSamples uses the signed-event fixture and its real stopped cursor.
// The pending outbox row remains unsequenced and therefore outside the stream head.
func checkEventSamples(t *testing.T, producer, receiver eventstream.DB, puller *eventstream.Puller) {
	t.Helper()
	ctx, stop := context.WithCancel(t.Context())
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	unreg, err := puller.ObserveLag(mp)
	if err != nil {
		t.Fatal(err)
	}
	defer unreg()
	sampler := telemetry.NewSampler(mp, telemetry.Options{Interval: 25 * time.Millisecond})
	if err := eventstream.RegisterOutboxSamples(sampler, producer, "payment_outbox"); err != nil {
		t.Fatal(err)
	}
	if err := eventstream.RegisterReceiverSamples(sampler, receiver, eventstream.ReceiverTables{Cursors: "ledger_stream_cursors", Inbox: "ledger_inbox"}, "payment.orders"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); sampler.Run(ctx) }()
	defer func() { stop(); <-done }()
	check := func(pending int64) {
		t.Helper()
		eventually(t, 3*time.Second, "cached event gauges", func() bool {
			ms := readMetrics(t, reader)
			if len(ms) != 6 {
				return false
			}
			for _, tc := range []struct {
				name, key, label string
				n                int64
			}{
				{"kaivo.eventstream.lag.events", "stream", "payment.orders", 3},
				{"kaivo.eventstream.stopped", "stream", "payment.orders", 1},
				{"kaivo.eventstream.inbox.pending", "stream", "payment.orders", 2},
				{"kaivo.outbox.pending", "outbox", "payment_outbox", pending},
			} {
				m := ms[tc.name]
				points := m.Data.(metricdata.Gauge[int64]).DataPoints
				if len(points) != 1 || m.Unit != "" || points[0].Attributes != attribute.NewSet(attribute.String(tc.key, tc.label)) {
					t.Fatal(m)
				}
				if points[0].Value != tc.n {
					return false
				}
			}
			for _, tc := range []struct{ name, key, label string }{{"kaivo.outbox.oldest_pending", "outbox", "payment_outbox"}, {"kaivo.eventstream.inbox.oldest_pending", "stream", "payment.orders"}} {
				m := ms[tc.name]
				points := m.Data.(metricdata.Gauge[float64]).DataPoints
				if len(points) != 1 || m.Unit != "s" || points[0].Attributes != attribute.NewSet(attribute.String(tc.key, tc.label)) {
					t.Fatal(m)
				}
				v := points[0].Value
				if tc.key == "outbox" {
					if pending == 0 && v != 0 || pending == 1 && (v < 60 || v > 90) {
						return false
					}
				} else if v <= 0 {
					return false
				}
			}
			return true
		})
	}
	check(0)
	_, err = producer.Exec(ctx, `INSERT INTO payment_outbox(event_id,stream,event_type,schema_version,occurred_at,recorded_at,payload,payload_digest)
 VALUES(gen_random_uuid(),'payment.orders','OrderPaid',1,now(),now()-interval '1 minute','x',sha256('x'::bytea))`)
	if err != nil {
		t.Fatal("insert pending fixture failed")
	}
	check(1)
}
