//go:build integration

package tools_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	collectionv1 "github.com/Kaivodev/protobuf/gen/go/aipay/collection/v1"
	eventsv1 "github.com/Kaivodev/protobuf/gen/go/aipay/events/v1"
	"github.com/Kaivodev/servicekit/dev/tools/internal/collection"
	"github.com/Kaivodev/servicekit/eventstream"
	"github.com/Kaivodev/servicekit/signing"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type failedSigner struct{ signing.Signer }

func (failedSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

func TestPostgresAddRestartReplay(t *testing.T) {
	dsn := os.Getenv("AIPAY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("set AIPAY_TEST_DATABASE_URL to an isolated database")
	}
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	admin, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
	if err != nil {
		t.Fatal("open isolated test database")
	}
	defer admin.Close()
	schema := "devcollection_test_" + uuid.New().String()[:8]
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal("create isolated test schema")
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	open := func() *pgxpool.Pool {
		p, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
		if err != nil {
			t.Fatal("open test pool")
		}
		return p
	}
	pool := open()
	t.Cleanup(pool.Close)
	if err := collection.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	env := keyFiles(t)
	file := filepath.Join(fixtures(t), "scenario.json")
	claim := readClaim(t, file, "normal")
	signer := openKey(t, env)
	if _, err := collection.Append(ctx, pool, signer, "normal", claim, true); err == nil {
		t.Fatal("replayed missing key")
	}
	if _, err := collection.Append(ctx, pool, failedSigner{signer}, "normal", claim, false); err == nil {
		t.Fatal("signing failure must roll back the key and outbox row")
	}
	if n, _, err := collection.Head(ctx, pool); err != nil || n != 0 {
		t.Fatal("failed signature advanced head", err)
	}
	var group sync.WaitGroup
	ids := make([]string, 8)
	for i := range ids {
		group.Go(func() {
			id, err := collection.Append(ctx, pool, signer, "normal", claim, false)
			if err != nil {
				t.Error(err)
			}
			ids[i] = id
		})
	}
	group.Wait()
	for _, id := range ids {
		if id == "" || id != ids[0] {
			t.Fatal("concurrent add was not idempotent")
		}
	}
	if _, err := collection.Append(ctx, pool, signer, "normal", readClaim(t, file, "mismatch"), false); err == nil {
		t.Fatal("reused key with changed claim")
	}
	pool.Close()
	pool = open()
	t.Cleanup(pool.Close)
	if err := collection.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	signer = openKey(t, env)
	if id, err := collection.Append(ctx, pool, signer, "normal", claim, false); err != nil || id != ids[0] {
		t.Fatal("lost original after restart", err)
	}
	replay, err := collection.Append(ctx, pool, signer, "normal", claim, true)
	if err != nil || replay == ids[0] {
		t.Fatal("expected new envelope", err)
	}
	connect := startReader(t, pool)
	client, err := connect("ledger")
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListEvents(ctx, &eventsv1.ListEventsRequest{Stream: collection.Stream, Limit: 10})
	if err != nil || len(page.GetEvents()) != 2 {
		t.Fatal("read signed events", err)
	}
	var cursor eventstream.Cursor
	verify := verifier(t, env)
	for i, e := range page.Events {
		cursor, err = verify.Next(cursor, e)
		if err != nil {
			t.Fatal(err)
		}
		if e.EventId != []string{ids[0], replay}[i] || !bytes.Equal(e.Payload, page.Events[0].Payload) {
			t.Fatal("replay changed receipt bytes")
		}
	}
	var stored collectionv1.ReceiptConfirmed
	if proto.Unmarshal(page.Events[0].Payload, &stored) != nil || uuid.MustParse(stored.ReceiptId).Version() != 7 || stored.ChainTransactionId != claim.ChainTransactionId || stored.TransferIndex != claim.TransferIndex {
		t.Fatal("invalid stored receipt or transfer tuple")
	}
	head, err := client.GetStreamHead(ctx, &eventsv1.GetStreamHeadRequest{Stream: collection.Stream})
	if err != nil || head.GetHead().GetSequence() != 2 || !bytes.Equal(head.Head.EventDigest, cursor.Digest[:]) {
		t.Fatal("incorrect signed head", err)
	}
}
