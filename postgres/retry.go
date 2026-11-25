package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Retry calls attempt until it succeeds, the context ends, or PostgreSQL itself
// rejects the request. Network failures while a new pod's address is still being
// admitted by NetworkPolicy, or while the database starts, are transient; server
// errors such as failed authentication or missing privileges are returned at once.
func Retry(ctx context.Context, attempt func(context.Context) error) error {
	delay := 250 * time.Millisecond
	for {
		err := attempt(ctx)
		if err == nil || !Transient(err) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
		delay = min(2*delay, 2*time.Second)
	}
}

// Transient reports whether err happened before PostgreSQL answered the request.
func Transient(err error) bool {
	var server *pgconn.PgError
	return err != nil && !errors.As(err, &server) && !errors.Is(err, context.Canceled)
}
