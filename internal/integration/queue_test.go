//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kaivodev/observability/asynqobs"
	"github.com/Kaivodev/observability/logging"
	"github.com/Kaivodev/servicekit/queue"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
)

func queueInspector(t *testing.T, cfg queue.Config) *asynq.Inspector {
	t.Helper()
	options, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	return asynq.NewInspectorFromRedisClient(client)
}
func TestQueueFailureOutcomesAndTimeoutCorrelation(t *testing.T) {
	sink, endpoint := startSink(t)
	var logs traceBuffer
	rt := traceRuntime(t, endpoint, "queue-failures", &logs)
	cfg := testQueueConfig(t)
	cfg.Concurrency = 4
	cfg.MaxRetry = 0
	cfg.TaskTimeout = time.Second
	logger := logging.New(&logs, slog.LevelInfo)
	producer, err := queue.NewProducer(context.Background(), cfg, rt.Provider(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	mux := asynq.NewServeMux()
	var revoked atomic.Bool
	mux.HandleFunc("fixture.panic", func(context.Context, *asynq.Task) error { panic("panic-secret") })
	mux.HandleFunc("fixture.skip", func(context.Context, *asynq.Task) error {
		return errors.Join(asynq.SkipRetry, errors.New("error-secret"))
	})
	mux.HandleFunc("fixture.revoke", func(context.Context, *asynq.Task) error {
		revoked.Store(true)
		return errors.Join(asynq.RevokeTask, errors.New("error-secret"))
	})
	mux.HandleFunc("fixture.timeout", func(ctx context.Context, _ *asynq.Task) error { <-ctx.Done(); return ctx.Err() })
	inspector := queueInspector(t, cfg)
	ids := map[string]string{}
	for _, kind := range []string{"panic", "skip", "revoke", "timeout", "unknown"} {
		info, err := producer.Enqueue(context.Background(), asynqobs.NewMessage(context.Background(), "fixture."+kind, []byte("payload-secret")))
		if err != nil {
			t.Fatal(err)
		}
		ids[kind] = info.ID
	}
	done, stop := startQueue(t, cfg, rt, &logs, mux)
	for kind, id := range ids {
		if kind == "revoke" {
			continue
		}
		eventually(t, 8*time.Second, "archived "+kind, func() bool {
			info, err := inspector.GetTaskInfo(cfg.Name, id)
			return err == nil && info.State == asynq.TaskStateArchived
		})
		info, _ := inspector.GetTaskInfo(cfg.Name, id)
		if strings.Contains(info.LastErr, "secret") {
			t.Fatalf("%s leaked LastErr", kind)
		}
	}
	eventually(t, 3*time.Second, "revoked task removed", func() bool {
		_, err := inspector.GetTaskInfo(cfg.Name, ids["revoke"])
		return revoked.Load() && errors.Is(err, asynq.ErrTaskNotFound)
	})
	stop()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = rt.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "secret") {
		t.Fatal("queue failure leaked payload or error")
	}
	outcomes := map[string]int{}
	timeoutCorrelated := false
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var row map[string]any
		if err = json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row["msg"] == "queue task execution" {
			id, _ := row["task_id"].(string)
			outcomes[id]++
			if row["failed"] != true {
				t.Fatal("failed task reported success")
			}
		}
		if row["msg"] == "task requires failure handling" && row["task_id"] == ids["timeout"] {
			timeoutCorrelated = row["trace_id"] != nil && row["span_id"] != nil
		}
	}
	for kind, id := range ids {
		if outcomes[id] != 1 {
			t.Fatalf("%s execution logs=%d", kind, outcomes[id])
		}
	}
	if !timeoutCorrelated {
		t.Fatal("framework timeout error lost active execution context")
	}
	if len(sink.snapshot()) == 0 {
		t.Fatal("failure spans not exported")
	}
}

func TestQueuedCarrierSurvivesWorkerAndProducerRestart(t *testing.T) {
	sink, endpoint := startSink(t)
	var logs traceBuffer
	rt := traceRuntime(t, endpoint, "queue-restart", &logs)
	cfg := testQueueConfig(t)
	log := logging.New(&logs, slog.LevelInfo)
	// A real worker starts and drains before an origin request persists its task.
	noop := asynq.HandlerFunc(func(context.Context, *asynq.Task) error { return nil })
	done, stop := startQueue(t, cfg, rt, &logs, noop)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	origin, cancel := context.WithCancel(context.Background())
	origin, span := rt.Tracer("test").Start(origin, "origin")
	traceID := span.SpanContext().TraceID()
	message := asynqobs.NewMessage(origin, "fixture.restart", []byte("payload-secret"))
	span.End()
	cancel()
	producer, err := queue.NewProducer(context.Background(), cfg, rt.Provider(), log)
	if err != nil {
		t.Fatal(err)
	}
	info, err := producer.Enqueue(context.Background(), message, asynq.Retention(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err = producer.Close(); err != nil {
		t.Fatal(err)
	}
	// New instances have no references to the original request or producer.
	var runs atomic.Int32
	done, stop = startQueue(t, cfg, rt, &logs, asynq.HandlerFunc(func(ctx context.Context, _ *asynq.Task) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		runs.Add(1)
		return nil
	}))
	inspector := queueInspector(t, cfg)
	eventually(t, 5*time.Second, "restarted worker completion", func() bool {
		task, err := inspector.GetTaskInfo(cfg.Name, info.ID)
		return err == nil && task.State == asynq.TaskStateCompleted
	})
	stop()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	_ = rt.Shutdown(context.Background())
	if runs.Load() != 1 {
		t.Fatal("restart task execution count")
	}
	consumers := 0
	for _, resource := range sink.snapshot() {
		for _, scope := range resource.ScopeSpans {
			for _, s := range scope.Spans {
				if s.Name == "process fixture.restart" {
					consumers++
					if string(s.TraceId) != string(traceID[:]) {
						t.Fatal("restart split trace")
					}
				}
			}
		}
	}
	if consumers != 1 {
		t.Fatal("restart span missing")
	}
}

func TestQueueGracefulAndForcedDrain(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "forced"}[forced], func(t *testing.T) {
			_, endpoint := startSink(t)
			var logs traceBuffer
			rt := traceRuntime(t, endpoint, "queue-drain", &logs)
			cfg := testQueueConfig(t)
			if forced {
				cfg.ShutdownTimeout = 300 * time.Millisecond
			}
			logger := logging.New(&logs, slog.LevelInfo)
			producer, err := queue.NewProducer(context.Background(), cfg, rt.Provider(), logger)
			if err != nil {
				t.Fatal(err)
			}
			defer producer.Close()
			entered := make(chan context.Context, 1)
			release := make(chan struct{})
			exited := make(chan struct{})
			worker, err := queue.NewWorker(context.Background(), cfg, rt.Provider(), logger, logger, asynq.HandlerFunc(func(ctx context.Context, _ *asynq.Task) error {
				defer close(exited)
				entered <- ctx
				<-release
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			done := make(chan error, 1)
			go func() { done <- worker.Run(ctx) }()
			if _, err = producer.Enqueue(context.Background(), asynqobs.NewMessage(context.Background(), "fixture.drain", nil)); err != nil {
				t.Fatal(err)
			}
			var taskCtx context.Context
			select {
			case taskCtx = <-entered:
			case <-time.After(4 * time.Second):
				t.Fatal("handler never started")
			}
			start := time.Now()
			stop()
			eventually(t, time.Second, "worker no longer ready", func() bool { return worker.Check(context.Background()) != nil })
			if !forced {
				select {
				case <-taskCtx.Done():
					t.Fatal("signal canceled active task before drain")
				case <-time.After(30 * time.Millisecond):
				}
				close(release)
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			} else {
				select {
				case err = <-done:
					if !errors.Is(err, queue.ErrShutdownTimeout) {
						t.Fatalf("forced drain=%v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("forced drain exceeded deadline")
				}
				if time.Since(start) > time.Second {
					t.Fatal("uncooperative task escaped deadline")
				}
				close(release)
			}
			<-exited
			select {
			case <-worker.Done():
			case <-time.After(6 * time.Second):
				t.Fatal("Asynq cleanup did not release Redis")
			}
		})
	}
}
