package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/aipay-dev/servicekit/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, service string, cfg config.Database) (*pgxpool.Pool, error) {
	if !config.ValidService(service) || cfg.MaxConns < 1 || cfg.MinConns < 0 || cfg.MinConns > cfg.MaxConns || cfg.MaxConnLifetime <= 0 {
		return nil, errors.New("invalid PostgreSQL pool configuration")
	}
	if err := config.ValidateDatabase(cfg.URL); err != nil {
		return nil, err
	}
	options, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	options.MaxConns, options.MinConns, options.MaxConnLifetime = cfg.MaxConns, cfg.MinConns, cfg.MaxConnLifetime
	options.ConnConfig.RuntimeParams["timezone"] = "UTC"
	options.ConnConfig.RuntimeParams["application_name"] = "aipay-" + service
	pool, err := pgxpool.NewWithConfig(ctx, options)
	if err != nil {
		return nil, errors.New("create PostgreSQL pool failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("PostgreSQL connection check failed; check connectivity and credentials")
	}
	return pool, nil
}

// CheckSchema verifies both version and service ownership. Each service ships
// its own schema_service_identity migration in its own database.
func CheckSchema(ctx context.Context, pool *pgxpool.Pool, service string, expected uint) error {
	var version uint
	var dirty bool
	if err := pool.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty); err != nil {
		return errors.New("database schema is unavailable; run migrate up")
	}
	if dirty || version != expected {
		return fmt.Errorf("database schema mismatch: expected %d, got %d (dirty=%t)", expected, version, dirty)
	}
	var owner string
	if err := pool.QueryRow(ctx, "SELECT service FROM schema_service_identity WHERE singleton = true").Scan(&owner); err != nil {
		return errors.New("database service identity is unavailable")
	}
	if owner != service {
		return errors.New("database belongs to another service")
	}
	return nil
}

// Close waits within the caller's remaining shutdown budget. Context-aware
// handlers must release acquired connections when their RPC is canceled.
func Close(ctx context.Context, pool *pgxpool.Pool) error {
	done := make(chan struct{})
	go func() { pool.Close(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errors.New("PostgreSQL close exceeded shutdown deadline")
	}
}
