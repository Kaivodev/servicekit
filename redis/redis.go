package redis

import (
	"context"
	"errors"

	"github.com/Kaivodev/servicekit/config"
	goredis "github.com/redis/go-redis/v9"
)

// Open is only called when Redis is an explicitly configured dependency.
func Open(ctx context.Context, cfg config.Redis) (*goredis.Client, error) {
	if cfg.URL == "" || cfg.PoolSize < 1 || cfg.Timeout <= 0 {
		return nil, errors.New("invalid Redis pool configuration")
	}
	options, err := goredis.ParseURL(cfg.URL)
	if err != nil {
		return nil, errors.New("invalid Redis connection configuration")
	}
	options.PoolSize, options.DialTimeout, options.ReadTimeout, options.WriteTimeout, options.PoolTimeout = cfg.PoolSize, cfg.Timeout, cfg.Timeout, cfg.Timeout, cfg.Timeout
	options.ContextTimeoutEnabled = true
	client := goredis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, errors.New("Redis connection check failed; check connectivity and credentials")
	}
	return client, nil
}
