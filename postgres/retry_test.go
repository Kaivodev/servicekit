package postgres

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRetryTransientUntilSuccess(t *testing.T) {
	calls := 0
	refused := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	err := Retry(context.Background(), func(context.Context) error {
		calls++
		if calls < 3 {
			return refused
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestRetryStopsOnServerError(t *testing.T) {
	calls := 0
	auth := &pgconn.PgError{Code: "28P01"}
	err := Retry(context.Background(), func(context.Context) error { calls++; return auth })
	if !errors.Is(err, auth) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestRetryHonoursDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	refused := errors.New("dial tcp: connection refused")
	start := time.Now()
	err := Retry(ctx, func(context.Context) error { return refused })
	if !errors.Is(err, refused) || time.Since(start) > 2*time.Second {
		t.Fatalf("err=%v elapsed=%s", err, time.Since(start))
	}
}
