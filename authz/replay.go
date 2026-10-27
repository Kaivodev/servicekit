package authz

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

var tablePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// PostgresReplayGuard writes jti values to the service's used-assertion table
// (jti primary key, method, subject, used_at, expires_at). The interceptor
// consumes the ID before the handler runs, so a failed command still burns it;
// the caller retries with a new assertion from IAM.
type PostgresReplayGuard struct {
	db            Execer
	insert, purge string
}

func NewPostgresReplayGuard(db Execer, table string) (*PostgresReplayGuard, error) {
	if db == nil || !tablePattern.MatchString(table) {
		return nil, errors.New("replay guard requires a database and table name")
	}
	name := pgx.Identifier{table}.Sanitize()
	return &PostgresReplayGuard{db: db,
		insert: "INSERT INTO " + name + " (jti, method, subject, expires_at) VALUES ($1, $2, $3, $4)",
		purge:  "DELETE FROM " + name + " WHERE expires_at < $1",
	}, nil
}

func (g *PostgresReplayGuard) Consume(ctx context.Context, use Use) error {
	_, err := g.db.Exec(ctx, g.insert, use.ID, use.Method, use.Subject, use.ExpiresAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrReplayed
	}
	if err != nil {
		return errors.New("record used identity assertion failed")
	}
	return nil
}

// DeleteExpired removes IDs of assertions that no verifier can still accept
// at now: expired for longer than the largest allowed leeway.
func (g *PostgresReplayGuard) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := g.db.Exec(ctx, g.purge, now.Add(-MaxLeeway))
	if err != nil {
		return 0, errors.New("delete expired identity assertions failed")
	}
	return tag.RowsAffected(), nil
}
