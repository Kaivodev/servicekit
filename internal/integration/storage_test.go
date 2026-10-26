//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/migration"
	"github.com/aipay-dev/servicekit/postgres"
	redisinfra "github.com/aipay-dev/servicekit/redis"
	"github.com/jackc/pgx/v5"
)

func TestStorageOwnershipAndLifecycle(t *testing.T) {
	raw := os.Getenv("AIPAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Fatal("AIPAY_TEST_DATABASE_URL must name an isolated PostgreSQL instance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatal("connect isolated database failed")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("servicekit_test_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	cfg := config.Database{URL: u.String(), MaxConns: 3, MinConns: 0, MaxConnLifetime: time.Minute}
	pool, err := postgres.Open(ctx, "iam", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = postgres.CheckSchema(ctx, pool, "iam", 1); err == nil {
		t.Fatal("empty schema accepted")
	}
	files := fstest.MapFS{
		"000001_identity.up.sql":   {Data: []byte("CREATE TABLE schema_service_identity(singleton boolean PRIMARY KEY CHECK(singleton),service text NOT NULL); INSERT INTO schema_service_identity VALUES(true,'iam');")},
		"000001_identity.down.sql": {Data: []byte("DROP TABLE schema_service_identity;")},
	}
	run, err := migration.Open(u.String(), files, ".", "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Up(); err != nil {
		t.Fatal(err)
	}
	if err = run.Up(); err != nil {
		t.Fatal("repeat migration:", err)
	}
	if err = postgres.CheckSchema(ctx, pool, "iam", 1); err != nil {
		t.Fatal(err)
	}
	if err = postgres.CheckSchema(ctx, pool, "ledger", 1); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if err = postgres.CheckSchema(ctx, pool, "iam", 2); err == nil {
		t.Fatal("wrong version accepted")
	}
	if _, err = pool.Exec(ctx, "UPDATE schema_migrations SET dirty=true"); err != nil {
		t.Fatal(err)
	}
	if err = postgres.CheckSchema(ctx, pool, "iam", 1); err == nil {
		t.Fatal("dirty schema accepted")
	}
	if _, err = pool.Exec(ctx, "UPDATE schema_migrations SET dirty=false"); err != nil {
		t.Fatal(err)
	}
	// A second migration must not pass ownership checks until the first closes.
	blocked := make(chan error, 1)
	go func() {
		second, e := migration.Open(u.String(), files, ".", "ledger")
		if second != nil {
			_ = second.Close()
		}
		blocked <- e
	}()
	select {
	case <-blocked:
		t.Fatal("migration ownership lock did not serialize runners")
	case <-time.After(100 * time.Millisecond):
	}
	if err = run.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-blocked:
		if err == nil {
			t.Fatal("cross-service migration accepted")
		}
	case <-ctx.Done():
		t.Fatal("ownership lock not released")
	}
	run, err = migration.Open(u.String(), files, ".", "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err = run.DownOne(); err != nil {
		t.Fatal(err)
	}
	if err = run.Close(); err != nil {
		t.Fatal(err)
	}
	run, err = migration.Open(u.String(), files, ".", "iam")
	if err != nil {
		t.Fatal("re-open rolled-back database:", err)
	}
	if err = run.Up(); err != nil {
		t.Fatal(err)
	}
	if err = run.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "DROP TABLE schema_service_identity"); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := migration.Open(u.String(), files, ".", "iam"); err == nil {
		_ = unexpected.Close()
		t.Fatal("unowned existing migration history accepted")
	}
	// An acquired connection cannot make shutdown exceed the caller's budget.
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stop, stopCancel := context.WithTimeout(ctx, 50*time.Millisecond)
	start := time.Now()
	err = postgres.Close(stop, pool)
	stopCancel()
	held.Release()
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("pool close did not respect deadline")
	}
}

func TestRedisAndSafeFailures(t *testing.T) {
	raw := os.Getenv("AIPAY_TEST_REDIS_URL")
	if raw == "" {
		t.Fatal("AIPAY_TEST_REDIS_URL must name an isolated Redis instance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := redisinfra.Open(ctx, config.Redis{URL: raw, PoolSize: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	for _, raw := range []string{"postgres://credential:never-log-this@127.0.0.1:1/test", "bad://never-log-this"} {
		_, err := postgres.Open(cancelled, "iam", config.Database{URL: raw, MaxConns: 1, MaxConnLifetime: time.Minute})
		if err == nil || strings.Contains(err.Error(), "never-log-this") {
			t.Fatal("PostgreSQL failure leaked input or was accepted")
		}
	}
	_, err = redisinfra.Open(cancelled, config.Redis{URL: "redis://:never-log-this@127.0.0.1:1", PoolSize: 1, Timeout: time.Millisecond})
	if err == nil || strings.Contains(err.Error(), "never-log-this") {
		t.Fatal("Redis failure leaked input or was accepted")
	}
}
