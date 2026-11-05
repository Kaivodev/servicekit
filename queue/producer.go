package queue

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Kaivodev/observability/asynqobs"
	"github.com/Kaivodev/servicekit/config"
	redisinfra "github.com/Kaivodev/servicekit/redis"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/trace"
)

type Producer struct {
	client   *redis.Client
	observer *asynqobs.Producer
	config   Config
}

func NewProducer(ctx context.Context, cfg Config, provider trace.TracerProvider, access *slog.Logger) (*Producer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if provider == nil || access == nil {
		return nil, errors.New("queue producer requires tracing and access logging")
	}
	pool, err := open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	observed, err := asynqobs.NewProducer(asynq.NewClientFromRedisClient(pool), provider, access, cfg.MaxPayloadBytes)
	if err != nil {
		_ = pool.Close()
		return nil, err
	}
	return &Producer{client: pool, observer: observed, config: cfg}, nil
}
func (p *Producer) Enqueue(ctx context.Context, message asynqobs.Message, options ...asynq.Option) (*asynq.TaskInfo, error) {
	for _, option := range options {
		if option == nil {
			return nil, errors.New("queue task option must not be nil")
		}
		if option.Type() == asynq.TimeoutOpt {
			d, ok := option.Value().(time.Duration)
			if !ok || d < time.Second || d%time.Second != 0 {
				return nil, errors.New("queue task timeout must be a positive whole number of seconds")
			}
		}
	}
	defaults := []asynq.Option{asynq.Timeout(p.config.TaskTimeout), asynq.MaxRetry(p.config.MaxRetry)}
	defaults = append(defaults, options...)
	// This producer owns one explicitly configured destination; task callers
	// cannot accidentally override it with a queue option from another service.
	defaults = append(defaults, asynq.Queue(p.config.Name))
	return p.observer.Enqueue(ctx, message, defaults...)
}
func (p *Producer) Check(ctx context.Context) error {
	if err := p.client.Ping(ctx).Err(); err != nil {
		return errors.New("queue Redis is unavailable")
	}
	return nil
}
func (p *Producer) Close() error {
	if err := p.client.Close(); err != nil {
		return errors.New("close queue producer failed")
	}
	return nil
}
func open(ctx context.Context, cfg Config) (*redis.Client, error) {
	return redisinfra.Open(ctx, config.Redis{URL: cfg.RedisURL, PoolSize: cfg.PoolSize, Timeout: cfg.RedisTimeout})
}
