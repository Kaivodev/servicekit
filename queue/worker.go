package queue

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aipay-dev/observability/asynqobs"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/trace"
)

var ErrShutdownTimeout = errors.New("queue shutdown exceeded its drain deadline")

// WorkerOptions holds owner-selected retry policy. A nil function uses Asynq's
// exponential backoff; retry scheduling never changes task identity or payload.
type WorkerOptions struct {
	RetryDelay asynq.RetryDelayFunc
}

type Worker struct {
	server    *asynq.Server
	client    *redis.Client
	handler   asynq.Handler
	config    Config
	log       *slog.Logger
	cancel    context.CancelFunc
	started   atomic.Bool
	running   atomic.Bool
	draining  atomic.Bool
	deadline  atomic.Pointer[time.Time]
	closeOnce sync.Once
	closed    chan struct{}
}

// NewWorker needs a real owner-supplied handler or mux. Merely configuring Redis
// does not register placeholder jobs or start a worker in any service.
func NewWorker(ctx context.Context, cfg Config, provider trace.TracerProvider, access, runtime *slog.Logger, handler asynq.Handler, options ...WorkerOptions) (*Worker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if provider == nil || access == nil || runtime == nil || handler == nil {
		return nil, errors.New("queue worker requires tracing, logging and an explicit handler")
	}
	if len(options) > 1 {
		return nil, errors.New("queue worker accepts at most one options value")
	}
	var retryDelay asynq.RetryDelayFunc
	if len(options) == 1 {
		retryDelay = options[0].RetryDelay
	}
	pool, err := open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	observer, err := asynqobs.NewWorker(provider, access, runtime, cfg.MaxPayloadBytes)
	if err != nil {
		_ = pool.Close()
		return nil, err
	}
	// A termination signal first stops new admissions; it must not immediately
	// cancel already-running tasks. Asynq keeps each task's own deadline.
	base, cancel := context.WithCancel(context.Background())
	server := asynq.NewServerFromRedisClient(pool, asynq.Config{Concurrency: cfg.Concurrency, Queues: map[string]int{cfg.Name: 1}, BaseContext: func() context.Context { return observer.BaseContext(base) }, ShutdownTimeout: cfg.ShutdownTimeout, Logger: asynqobs.NewFrameworkLogger(runtime), ErrorHandler: observer, RetryDelayFunc: retryDelay})
	return &Worker{server: server, client: pool, handler: observer.Middleware(handler), config: cfg, log: runtime, cancel: cancel, closed: make(chan struct{})}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	if !w.started.CompareAndSwap(false, true) {
		return errors.New("queue worker can only run once")
	}
	if ctx.Err() != nil {
		w.release()
		return nil
	}
	if err := w.server.Start(w.handler); err != nil {
		w.release()
		return errors.New("start queue worker failed")
	}
	w.running.Store(true)
	<-ctx.Done()
	w.draining.Store(true)
	w.running.Store(false)
	deadline := time.Now().Add(w.config.ShutdownTimeout)
	w.deadline.Store(&deadline)
	done := make(chan struct{})
	go func() { w.server.Stop(); w.server.Shutdown(); w.release(); close(done) }()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		w.cancel()
		w.log.Warn("queue shutdown forced after drain deadline")
		return ErrShutdownTimeout
	}
}
func (w *Worker) Check(ctx context.Context) error {
	if !w.running.Load() || w.draining.Load() {
		return errors.New("queue worker is not accepting tasks")
	}
	if err := w.client.Ping(ctx).Err(); err != nil {
		return errors.New("queue Redis is unavailable")
	}
	return nil
}
func (w *Worker) ShutdownDeadline() time.Time {
	if d := w.deadline.Load(); d != nil {
		return *d
	}
	return time.Now().Add(w.config.ShutdownTimeout)
}

// Done closes after Asynq has stopped all framework goroutines and released its
// Redis pool. On forced drain Run returns first so the process can honor its
// deadline; cleanup finishes asynchronously. Never close a shared Redis pool
// while Asynq's cancellation subscriber is still using it.
func (w *Worker) Done() <-chan struct{} { return w.closed }

// Close releases a never-started worker. Once Run starts, its context owns stop.
func (w *Worker) Close() {
	if w.started.CompareAndSwap(false, true) {
		w.release()
	}
}
func (w *Worker) release() {
	w.closeOnce.Do(func() { w.cancel(); _ = w.client.Close(); close(w.closed) })
}
