// Package migration runs service-owned embedded migrations. It never migrates
// automatically when starting a service and never stores another service's SQL.
package migration

import (
	"context"
	"errors"
	"io/fs"
	"net/url"
	"sync"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
)

type Runner struct {
	m         *migrate.Migrate
	lease     *pgx.Conn
	service   string
	closeOnce sync.Once
	closeErr  error
}

func Open(rawURL string, files fs.FS, directory, service string) (*Runner, error) {
	if err := config.ValidateDatabase(rawURL); err != nil {
		return nil, err
	}
	if !config.ValidService(service) {
		return nil, errors.New("invalid migration service identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lease, err := pgx.Connect(ctx, rawURL)
	if err != nil {
		return nil, errors.New("connect to migration ownership guard failed")
	}
	cleanup := func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
		defer closeCancel()
		_ = lease.Close(closeCtx)
	}
	// Serialize ownership verification with all servicekit migrations sharing this
	// database/schema. The migrate driver also keeps its own migration lock.
	if _, err := lease.Exec(ctx, "SELECT pg_advisory_lock(1095323737, hashtext(current_schema()))"); err != nil {
		cleanup()
		return nil, errors.New("acquire migration ownership lock failed")
	}
	if err := checkOwner(ctx, lease, service); err != nil {
		cleanup()
		return nil, err
	}
	u, _ := url.Parse(rawURL)
	u.Scheme = "pgx5"
	query := u.Query()
	if query.Get("connect_timeout") == "" {
		query.Set("connect_timeout", "10")
	}
	if query.Get("x-statement-timeout") == "" {
		query.Set("x-statement-timeout", "60000")
	}
	u.RawQuery = query.Encode()
	source, err := iofs.New(files, directory)
	if err != nil {
		cleanup()
		return nil, errors.New("open embedded migrations failed")
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, u.String())
	if err != nil {
		_ = source.Close()
		cleanup()
		return nil, errors.New("open migrations failed; check PostgreSQL connectivity, credentials and schema permissions")
	}
	m.LockTimeout = 15 * time.Second
	return &Runner{m: m, lease: lease, service: service}, nil
}

func (r *Runner) Up() error {
	if err := safe(r.m.Up()); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return checkOwner(ctx, r.lease, r.service)
}
func (r *Runner) DownOne() error               { return safe(r.m.Steps(-1)) }
func (r *Runner) Version() (uint, bool, error) { return r.m.Version() }
func (r *Runner) Close() error {
	r.closeOnce.Do(func() {
		a, b := r.m.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r.closeErr = errors.Join(safe(a), safe(b))
		if err := r.lease.Close(ctx); err != nil {
			r.closeErr = errors.Join(r.closeErr, errors.New("close migration ownership connection failed"))
		}
	})
	return r.closeErr
}

func checkOwner(ctx context.Context, connection *pgx.Conn, service string) error {
	var exists bool
	if err := connection.QueryRow(ctx, "SELECT to_regclass('schema_service_identity') IS NOT NULL").Scan(&exists); err != nil {
		return errors.New("inspect database service ownership failed")
	}
	if exists {
		var owner string
		if err := connection.QueryRow(ctx, "SELECT service FROM schema_service_identity WHERE singleton = true").Scan(&owner); err != nil || owner != service {
			return errors.New("migration database service identity does not match")
		}
		return nil
	}
	if err := connection.QueryRow(ctx, "SELECT to_regclass('schema_migrations') IS NOT NULL").Scan(&exists); err != nil {
		return errors.New("inspect database migration history failed")
	}
	if exists {
		var rows int
		if err := connection.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&rows); err != nil || rows != 0 {
			return errors.New("refusing to migrate a database with existing history but no service identity")
		}
	}
	return nil
}

func safe(err error) error {
	if errors.Is(err, migrate.ErrNoChange) {
		return nil
	}
	if err != nil {
		return errors.New("database migration failed; inspect schema version and the database's protected diagnostics")
	}
	return nil
}
