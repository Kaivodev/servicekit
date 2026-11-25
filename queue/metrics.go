package queue

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/Kaivodev/observability/asynqobs"
	"github.com/hibiken/asynq"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type taskLabels struct {
	queue string
	types []string
}

func (l taskLabels) result(kind, result string) metric.MeasurementOption {
	if !slices.Contains(l.types, kind) {
		kind = "other"
	}
	return metric.WithAttributes(attribute.String("queue", l.queue), attribute.String("task_type", kind), attribute.String("result", result))
}

func enqueueResult(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, asynq.ErrTaskIDConflict), errors.Is(err, asynq.ErrDuplicateTask):
		return "duplicate"
	default:
		return "error"
	}
}

type panicKey struct{}

// asynqobs recovers and wraps panics in a private error type. Mark the
// attempt inside its recovery boundary, then let its original recovery run.
// Measure outside that boundary to include admission/metadata and cancellation errors.
func observeAttempts(m metric.Meter, labels taskLabels, observer *asynqobs.Worker, handler asynq.Handler) asynq.Handler {
	h, _ := m.Float64Histogram("kaivo.queue.task.duration", metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(.01, .05, .1, .5, 1, 5, 10, 30, 60, 300))
	observed := observer.Middleware(asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
		defer func() {
			if p := recover(); p != nil {
				*ctx.Value(panicKey{}).(*bool) = true
				panic(p)
			}
		}()
		return handler.ProcessTask(ctx, t)
	}))
	return asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
		start := time.Now()
		panicked := false
		err := observed.ProcessTask(context.WithValue(ctx, panicKey{}, &panicked), t)
		result := "succeeded"
		switch {
		case panicked:
			result = "panicked"
		case errors.Is(err, asynq.SkipRetry):
			result = "skipped"
		case err != nil:
			result = "failed"
		}
		var kind string
		if t != nil {
			kind = t.Type()
		}
		h.Record(ctx, time.Since(start).Seconds(), labels.result(kind, result))
		return err
	})
}

func observeQueue(lifetime context.Context, m metric.Meter, queue string, inspect func(string) (*asynq.QueueInfo, error)) metric.Registration {
	tasks, _ := m.Int64ObservableGauge("kaivo.queue.tasks")
	latency, _ := m.Float64ObservableGauge("kaivo.queue.latency", metric.WithUnit("s"))
	// GetQueueInfo has no context parameter. Bound the export callback and
	// permit at most one outstanding Redis operation across all readers.
	busy := make(chan struct{}, 1)
	label := attribute.String("queue", queue)
	reg, _ := m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		if lifetime.Err() != nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		select {
		case busy <- struct{}{}:
		default:
			return nil
		}
		result := make(chan *asynq.QueueInfo, 1)
		go func() {
			defer func() { <-busy }()
			info, err := inspect(queue)
			if err != nil {
				info = nil
			}
			result <- info
		}()
		select {
		case <-lifetime.Done():
			return nil
		case <-ctx.Done():
			return nil
		case info := <-result:
			if info == nil || ctx.Err() != nil {
				return nil
			}
			for state, n := range map[string]int{"pending": info.Pending, "active": info.Active, "scheduled": info.Scheduled, "retry": info.Retry, "archived": info.Archived} {
				o.ObserveInt64(tasks, int64(n), metric.WithAttributes(label, attribute.String("state", state)))
			}
			o.ObserveFloat64(latency, info.Latency.Seconds(), metric.WithAttributes(label))
			return nil
		}
	}, tasks, latency)
	return reg
}
