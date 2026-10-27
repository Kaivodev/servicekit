package eventstream

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// TxStarter is satisfied by *pgxpool.Pool and *pgx.Conn.
type TxStarter interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Pool is satisfied by *pgxpool.Pool and *pgx.Conn.
type Pool interface {
	DB
	TxStarter
}

// ProducerTables names a service's <p>_stream_heads and <p>_outbox tables.
type ProducerTables struct {
	StreamHeads string
	Outbox      string
}

// ReceiverTables names a service's <p>_stream_cursors and <p>_inbox tables.
type ReceiverTables struct {
	Cursors string
	Inbox   string
}

var tablePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func table(name string) (string, error) {
	if !tablePattern.MatchString(name) {
		return "", errors.New("invalid table name")
	}
	return pgx.Identifier{name}.Sanitize(), nil
}

func (t ProducerTables) sanitize() (heads, outbox string, err error) {
	heads, err = table(t.StreamHeads)
	if err == nil {
		outbox, err = table(t.Outbox)
	}
	return heads, outbox, err
}

func (t ReceiverTables) sanitize() (cursors, inbox string, err error) {
	cursors, err = table(t.Cursors)
	if err == nil {
		inbox, err = table(t.Inbox)
	}
	return cursors, inbox, err
}

func digest32(raw []byte) ([32]byte, error) {
	var d [32]byte
	if len(raw) != 32 {
		return d, errors.New("stored digest must be 32 bytes")
	}
	copy(d[:], raw)
	return d, nil
}

func rollback(ctx context.Context, tx pgx.Tx) {
	// Rollback after commit is a no-op; a cancelled ctx must not leak the tx.
	_ = tx.Rollback(context.WithoutCancel(ctx))
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
