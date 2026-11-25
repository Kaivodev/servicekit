package queue

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kaivodev/observability/asynqobs"
	"github.com/hibiken/asynq"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/trace/noop"
)

type testEnqueuer struct{ err error }

func (e *testEnqueuer) EnqueueContext(context.Context, *asynq.Task, ...asynq.Option) (*asynq.TaskInfo, error) {
	if e.err != nil {
		return nil, e.err
	}
	return &asynq.TaskInfo{}, nil
}

func TestAttemptAndEnqueueMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	m := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tp := noop.NewTracerProvider()
	worker, err := asynqobs.NewWorker(tp, logger, logger, 256)
	if err != nil {
		t.Fatal(err)
	}
	labels := taskLabels{"jobs", []string{"known"}}
	handler := observeAttempts(m, labels, worker, asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
		switch string(t.Payload()) {
		case "failed":
			return errors.New("task handler panicked")
		case "panicked":
			panic("private")
		case "skipped":
			return errors.Join(asynq.SkipRetry, errors.New("private"))
		default:
			return nil
		}
	}))
	for _, result := range []string{"succeeded", "failed", "skipped", "panicked"} {
		kind := "known"
		if result == "failed" {
			kind = "dynamic"
		}
		err := handler.ProcessTask(t.Context(), asynq.NewTask(kind, []byte(result)))
		if (err == nil) != (result == "succeeded") || errors.Is(err, asynq.SkipRetry) != (result == "skipped") {
			t.Fatalf("%s: %v", result, err)
		}
	}
	broker := new(testEnqueuer)
	observer, err := asynqobs.NewProducer(broker, tp, logger, 256)
	if err != nil {
		t.Fatal(err)
	}
	counter, _ := m.Int64Counter("kaivo.queue.enqueued")
	p := Producer{enqueued: counter, labels: labels, observer: observer}
	for _, e := range []error{nil, asynq.ErrTaskIDConflict, asynq.ErrDuplicateTask, errors.New("private")} {
		broker.err = e
		kind := "known"
		if e != nil && enqueueResult(e) == "error" {
			kind = "unregistered"
		}
		_, err = p.Enqueue(t.Context(), asynqobs.Message{Type: kind})
		if !errors.Is(err, e) {
			t.Fatal(err)
		}
	}
	var data metricdata.ResourceMetrics
	if err = reader.Collect(t.Context(), &data); err != nil {
		t.Fatal(err)
	}
	attrs := func(kind, result string) attribute.Set {
		return attribute.NewSet(attribute.String("queue", "jobs"), attribute.String("task_type", kind), attribute.String("result", result))
	}
	if len(data.ScopeMetrics[0].Metrics) != 2 {
		t.Fatal(data)
	}
	for _, m := range data.ScopeMetrics[0].Metrics {
		switch m.Name {
		case "kaivo.queue.task.duration":
			points := m.Data.(metricdata.Histogram[float64]).DataPoints
			want := map[attribute.Set]bool{attrs("known", "succeeded"): true, attrs("other", "failed"): true, attrs("known", "skipped"): true, attrs("known", "panicked"): true}
			for _, p := range points {
				if !want[p.Attributes] || p.Count != 1 || m.Unit != "s" || !slices.Equal(p.Bounds, []float64{.01, .05, .1, .5, 1, 5, 10, 30, 60, 300}) {
					t.Fatal(m)
				}
				delete(want, p.Attributes)
			}
			if len(want) != 0 {
				t.Fatal(want)
			}
		case "kaivo.queue.enqueued":
			want := map[attribute.Set]int64{attrs("known", "ok"): 1, attrs("known", "duplicate"): 2, attrs("other", "error"): 1}
			sum := m.Data.(metricdata.Sum[int64])
			if m.Unit != "" || !sum.IsMonotonic {
				t.Fatal(m)
			}
			for _, p := range sum.DataPoints {
				if want[p.Attributes] != p.Value {
					t.Fatal(p)
				}
				delete(want, p.Attributes)
			}
			if len(want) != 0 {
				t.Fatal(want)
			}
		default:
			t.Fatal(m)
		}
	}
}

func TestInspectorCallbackDeadline(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	m := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	var calls atomic.Int64
	release := make(chan struct{})
	defer close(release)
	reg := observeQueue(t.Context(), m, "jobs", func(string) (*asynq.QueueInfo, error) { calls.Add(1); <-release; return nil, errors.New("private") })
	defer reg.Unregister()
	var data metricdata.ResourceMetrics
	start := time.Now()
	if err := reader.Collect(t.Context(), &data); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < 1900*time.Millisecond || elapsed > 3*time.Second || len(data.ScopeMetrics) != 0 {
		t.Fatalf("duration %s, data %v", elapsed, data)
	}
	if err := reader.Collect(t.Context(), &data); err != nil || calls.Load() != 1 || len(data.ScopeMetrics) != 0 {
		t.Fatalf("concurrent inspection: %v, %v", err, data)
	}
}
