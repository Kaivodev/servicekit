//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aipay-dev/observability/logging"
	eventsv1 "github.com/aipay-dev/protobuf/gen/go/aipay/events/v1"
	"github.com/aipay-dev/servicekit/authz"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/devcert"
	"github.com/aipay-dev/servicekit/eventstream"
	"github.com/aipay-dev/servicekit/mtls"
	"github.com/aipay-dev/servicekit/rpc"
	"github.com/aipay-dev/servicekit/signing"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The shared producer, receiver and used-assertion templates of the database
// design, including the one-time-write and append-only triggers they require.
const producerSchema = `
CREATE FUNCTION payment_outbox_seal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    sealed text[] := ARRAY['sequence', 'prev_digest', 'event_digest', 'key_id', 'signature', 'sequenced_at'];
BEGIN
    IF TG_OP <> 'UPDATE' OR OLD.sequence IS NOT NULL THEN
        RAISE EXCEPTION 'payment_outbox: signed events are immutable' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - sealed) IS DISTINCT FROM (to_jsonb(OLD) - sealed) THEN
        RAISE EXCEPTION 'payment_outbox: only signature columns may be written' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
CREATE TABLE payment_stream_heads (
    stream            TEXT PRIMARY KEY CHECK (stream ~ '^[a-z]+\.[a-z_]+$'),
    last_sequence     BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_event_digest BYTEA NOT NULL DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(last_event_digest) = 32),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE payment_outbox (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id       UUID NOT NULL UNIQUE,
    stream         TEXT NOT NULL REFERENCES payment_stream_heads (stream),
    event_type     TEXT NOT NULL CHECK (event_type ~ '^[A-Z][A-Za-z]+$'),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    occurred_at    TIMESTAMPTZ NOT NULL,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    payload        BYTEA NOT NULL CHECK (octet_length(payload) <= 1048576),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    sequence       BIGINT CHECK (sequence > 0),
    prev_digest    BYTEA CHECK (octet_length(prev_digest) = 32),
    event_digest   BYTEA CHECK (octet_length(event_digest) = 32),
    key_id         TEXT,
    signature      BYTEA,
    sequenced_at   TIMESTAMPTZ,
    UNIQUE (stream, sequence),
    CHECK ((sequence IS NULL) = (signature IS NULL) AND (sequence IS NULL) = (event_digest IS NULL)
       AND (sequence IS NULL) = (prev_digest IS NULL) AND (sequence IS NULL) = (key_id IS NULL)
       AND (sequence IS NULL) = (sequenced_at IS NULL))
);
CREATE INDEX payment_outbox_unsequenced_idx ON payment_outbox (stream, id) WHERE sequence IS NULL;
CREATE TRIGGER payment_outbox_seal BEFORE UPDATE OR DELETE ON payment_outbox FOR EACH ROW EXECUTE FUNCTION payment_outbox_seal();
`

const receiverSchema = `
CREATE FUNCTION ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END $$;
CREATE FUNCTION ledger_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    arg text;
    transitions text[] := '{}';
    mutable text[] := ARRAY['status', 'version', 'updated_at'];
    old_row jsonb := to_jsonb(OLD);
    new_row jsonb := to_jsonb(NEW);
BEGIN
    FOREACH arg IN ARRAY TG_ARGV LOOP
        IF arg LIKE 'col:%' THEN
            mutable := mutable || substr(arg, 5);
        ELSE
            transitions := transitions || arg;
        END IF;
    END LOOP;
    IF (new_row - mutable) IS DISTINCT FROM (old_row - mutable) THEN
        RAISE EXCEPTION '%: immutable column changed', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF new_row->>'status' IS DISTINCT FROM old_row->>'status'
       AND NOT ((old_row->>'status') || '>' || (new_row->>'status')) = ANY (transitions) THEN
        RAISE EXCEPTION '%: illegal transition % -> %', TG_TABLE_NAME, old_row->>'status', new_row->>'status' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
CREATE TABLE ledger_stream_cursors (
    stream            TEXT PRIMARY KEY,
    producer          TEXT NOT NULL,
    last_sequence     BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_event_digest BYTEA NOT NULL DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(last_event_digest) = 32),
    state             TEXT NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'stopped')),
    stopped_reason    TEXT,
    stopped_at        TIMESTAMPTZ,
    resume_request_id UUID,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((state = 'stopped') = (stopped_at IS NOT NULL))
);
CREATE TABLE ledger_inbox (
    stream            TEXT NOT NULL REFERENCES ledger_stream_cursors (stream),
    sequence          BIGINT NOT NULL CHECK (sequence > 0),
    event_id          UUID NOT NULL UNIQUE,
    producer          TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    schema_version    INTEGER NOT NULL,
    occurred_at       TIMESTAMPTZ NOT NULL,
    recorded_at       TIMESTAMPTZ NOT NULL,
    payload           BYTEA NOT NULL,
    payload_digest    BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    prev_digest       BYTEA NOT NULL CHECK (octet_length(prev_digest) = 32),
    event_digest      BYTEA NOT NULL CHECK (octet_length(event_digest) = 32),
    key_id            TEXT NOT NULL,
    signature         BYTEA NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'quarantined', 'ignored')),
    processed_at      TIMESTAMPTZ,
    quarantine_reason TEXT,
    PRIMARY KEY (stream, sequence),
    CHECK ((status = 'pending') = (processed_at IS NULL)),
    CHECK ((status = 'quarantined') = (quarantine_reason IS NOT NULL))
);
CREATE TRIGGER ledger_inbox_guard BEFORE UPDATE ON ledger_inbox FOR EACH ROW EXECUTE FUNCTION ledger_guard_update(
    'pending>applied', 'pending>quarantined', 'pending>ignored', 'col:processed_at', 'col:quarantine_reason');
CREATE TRIGGER ledger_inbox_no_delete BEFORE DELETE ON ledger_inbox FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation();
CREATE TABLE ledger_used_assertions (
    jti        TEXT PRIMARY KEY CHECK (char_length(jti) BETWEEN 16 AND 64),
    method     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    used_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
`

// isolatedPool creates a schema with ddl and returns a pool bound to it.
func isolatedPool(t *testing.T, ctx context.Context, admin *pgx.Conn, raw, prefix, ddl string) *pgxpool.Pool {
	t.Helper()
	schema := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err = pool.Exec(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	return pool
}

// serveEvents serves reader as payment's EventStreamService over mutual TLS,
// authorized by the published method policy, and returns generated clients
// for the receivers ledger and settlement.
func serveEvents(t *testing.T, reader *eventstream.Reader) map[string]eventsv1.EventStreamServiceClient {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"payment", "ledger", "settlement"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	material := map[string]*mtls.Material{}
	for _, name := range []string{"payment", "ledger", "settlement"} {
		m, err := mtls.Load(config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, name, "tls.crt"), KeyFile: filepath.Join(dir, name, "tls.key"), TrustDomain: "aipay.test"}, name)
		if err != nil {
			t.Fatal(err)
		}
		material[name] = m
	}
	log := logging.New(io.Discard, slog.LevelInfo)
	policies, err := authz.LoadPolicies(eventsv1.File_aipay_events_v1_event_stream_proto.Services().ByName("EventStreamService"))
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authz.New(authz.Options{Service: "payment", Policies: policies, Peer: material["payment"].Peer, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	server, err := rpc.NewServer(rpc.ServerOptions{RPC: config.RPC{Address: "127.0.0.1:0", ServerName: "payment", AllowedPeers: []string{"ledger", "settlement"}, CallTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20, MaxConcurrentStreams: 16},
		HealthTimeout: time.Second, HealthInterval: 20 * time.Millisecond, ShutdownTimeout: 2 * time.Second, Authorizer: authorizer}, material["payment"], log, log, nil,
		func(r grpc.ServiceRegistrar) { eventsv1.RegisterEventStreamServiceServer(r, reader) })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, 3*time.Second, "event server readiness", func() bool { return server.Ready() })
	clients := map[string]eventsv1.EventStreamServiceClient{}
	for _, receiver := range []string{"ledger", "settlement"} {
		connectCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := rpc.Connect(connectCtx, material[receiver], rpc.ClientOptions{Address: server.Address(), ServerName: "payment", ExpectedService: "payment", CallTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20})
		stop()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		clients[receiver] = eventsv1.NewEventStreamServiceClient(conn)
	}
	return clients
}

func insertEvents(ctx context.Context, pool *pgxpool.Pool, stream, eventType string, n int) error {
	for i := 0; i < n; i++ {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		payload := []byte(fmt.Sprintf("payload-%s", id))
		// The business transaction writes the payload and its digest only.
		if _, err = pool.Exec(ctx, "INSERT INTO payment_outbox (event_id, stream, event_type, schema_version, occurred_at, payload, payload_digest) VALUES ($1, $2, $3, 1, clock_timestamp(), $4, sha256($4))",
			id.String(), stream, eventType, payload); err != nil {
			return err
		}
	}
	return nil
}

func sequenceAll(ctx context.Context, sequencer *eventstream.Sequencer, stream string) error {
	for {
		n, err := sequencer.SequenceStream(ctx, stream)
		if err != nil || n == 0 {
			return err
		}
	}
}

func pullAll(ctx context.Context, puller *eventstream.Puller) (int, error) {
	total := 0
	for {
		n, err := puller.Pull(ctx)
		total += n
		if errors.Is(err, eventstream.ErrCursorMoved) {
			continue
		}
		if err != nil || n == 0 {
			return total, err
		}
	}
}

func TestSignedEventPipelineOnPostgres(t *testing.T) {
	raw := os.Getenv("AIPAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Fatal("AIPAY_TEST_DATABASE_URL must name an isolated PostgreSQL instance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatal("connect isolated database failed")
	}
	defer admin.Close(context.Background())
	producer := isolatedPool(t, ctx, admin, raw, "payment_test", producerSchema)
	receiver := isolatedPool(t, ctx, admin, raw, "ledger_test", receiverSchema)
	for _, stream := range []string{"payment.orders", "payment.pricing"} {
		if _, err = producer.Exec(ctx, "INSERT INTO payment_stream_heads (stream) VALUES ($1)", stream); err != nil {
			t.Fatal(err)
		}
		if _, err = receiver.Exec(ctx, "INSERT INTO ledger_stream_cursors (stream, producer) VALUES ($1, 'payment')", stream); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := signing.Open(ctx, signing.Config{Environment: config.Development, Backend: signing.BackendMemory, KeyID: "payment-dev-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tables := eventstream.ProducerTables{StreamHeads: "payment_stream_heads", Outbox: "payment_outbox"}
	sequencer, err := eventstream.NewSequencer(producer, "payment", tables, signer, 7)
	if err != nil {
		t.Fatal(err)
	}

	// Concurrent business writers and two sequencers never produce a gap or fork.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- insertEvents(ctx, producer, "payment.orders", "OrderPaid", 25) }()
	}
	stop := make(chan struct{})
	var sequencers sync.WaitGroup
	for i := 0; i < 2; i++ {
		sequencers.Add(1)
		go func() {
			defer sequencers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := sequencer.SequenceStream(ctx, "payment.orders"); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	sequencers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = sequenceAll(ctx, sequencer, "payment.orders"); err != nil {
		t.Fatal(err)
	}
	var count, maxSequence int64
	if err = producer.QueryRow(ctx, "SELECT count(*), max(sequence) FROM payment_outbox WHERE stream = 'payment.orders' AND sequence IS NOT NULL").Scan(&count, &maxSequence); err != nil || count != 100 || maxSequence != 100 {
		t.Fatalf("count=%d max=%d err=%v", count, maxSequence, err)
	}

	// Signed rows are written once and never change.
	_, err = producer.Exec(ctx, "UPDATE payment_outbox SET payload = 'x' WHERE sequence = 1")
	requireCode(t, err, "55000")
	_, err = producer.Exec(ctx, "UPDATE payment_outbox SET signature = 'x' WHERE sequence = 1")
	requireCode(t, err, "55000")
	_, err = producer.Exec(ctx, "DELETE FROM payment_outbox WHERE sequence = 1")
	requireCode(t, err, "55000")

	reader, err := eventstream.NewReader(producer, "payment", tables, map[string][]string{"payment.orders": {"ledger", "reconciliation"}, "payment.pricing": {"ledger"}})
	if err != nil {
		t.Fatal(err)
	}
	clients := serveEvents(t, reader)
	if _, err = clients["settlement"].ListEvents(ctx, &eventsv1.ListEventsRequest{Stream: "payment.orders", Limit: 10}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unlisted receiver: %v", err)
	}
	if _, err = clients["ledger"].ListEvents(ctx, &eventsv1.ListEventsRequest{Stream: "payment.withdrawals", Limit: 10}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown stream: %v", err)
	}
	if _, err = clients["ledger"].ListEvents(ctx, &eventsv1.ListEventsRequest{Stream: "payment.orders", Limit: 501}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized limit: %v", err)
	}

	keys, err := signing.NewPublicKeys(map[string]*ecdsa.PublicKey{"payment-dev-1": signer.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	known := func(eventType string, version uint32) bool { return eventType == "OrderPaid" && version == 1 }
	receiverTables := eventstream.ReceiverTables{Cursors: "ledger_stream_cursors", Inbox: "ledger_inbox"}
	puller, err := eventstream.NewPuller(receiver, clients["ledger"], eventstream.Verifier{Producer: "payment", Stream: "payment.orders", Keys: keys, Known: known}, receiverTables, 30)
	if err != nil {
		t.Fatal(err)
	}
	if pulled, err := pullAll(ctx, puller); err != nil || pulled != 100 {
		t.Fatalf("pulled=%d err=%v", pulled, err)
	}
	if lag, err := puller.CheckHead(ctx); err != nil || lag != 0 {
		t.Fatalf("lag=%d err=%v", lag, err)
	}

	// Inbox outcomes are recorded once, in order, inside the business transaction.
	inbox, err := eventstream.NewInbox(receiverTables, "payment.orders")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := receiver.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := inbox.Pending(ctx, tx, 3)
	if err != nil || len(pending) != 3 || pending[0].GetSequence() != 1 || pending[2].GetSequence() != 3 {
		t.Fatalf("pending=%d err=%v", len(pending), err)
	}
	if err = inbox.Resolve(ctx, tx, 1, eventstream.Applied, ""); err != nil {
		t.Fatal(err)
	}
	if err = inbox.Resolve(ctx, tx, 2, eventstream.Quarantined, "pricing version mismatch"); err != nil {
		t.Fatal(err)
	}
	if err = inbox.Resolve(ctx, tx, 1, eventstream.Ignored, ""); !errors.Is(err, eventstream.ErrResolved) {
		t.Fatalf("second outcome: %v", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = receiver.Exec(ctx, "UPDATE ledger_inbox SET status = 'pending', processed_at = NULL WHERE sequence = 1")
	requireCode(t, err, "55000")
	_, err = receiver.Exec(ctx, "UPDATE ledger_inbox SET payload = 'x' WHERE sequence = 3")
	requireCode(t, err, "55000")

	// A database administrator who rewrites a signed event cannot get it past
	// the receiver: the verified prefix is stored and the stream stops.
	if err = insertEvents(ctx, producer, "payment.orders", "OrderPaid", 5); err != nil {
		t.Fatal(err)
	}
	if err = sequenceAll(ctx, sequencer, "payment.orders"); err != nil {
		t.Fatal(err)
	}
	tamper := func(sql string) {
		t.Helper()
		if _, err := producer.Exec(ctx, "ALTER TABLE payment_outbox DISABLE TRIGGER payment_outbox_seal; "+sql+"; ALTER TABLE payment_outbox ENABLE TRIGGER payment_outbox_seal"); err != nil {
			t.Fatal(err)
		}
	}
	tamper("UPDATE payment_outbox SET payload = 'forged', payload_digest = sha256('forged') WHERE stream = 'payment.orders' AND sequence = 103")
	pulled, err := pullAll(ctx, puller)
	var stopErr *eventstream.StopError
	if pulled != 2 || !errors.As(err, &stopErr) || stopErr.Reason != eventstream.ReasonBadSignature || stopErr.Sequence != 103 || !errors.Is(err, eventstream.ErrStopped) {
		t.Fatalf("pulled=%d err=%v", pulled, err)
	}
	var state, reason string
	var last int64
	if err = receiver.QueryRow(ctx, "SELECT state, stopped_reason, last_sequence FROM ledger_stream_cursors WHERE stream = 'payment.orders'").Scan(&state, &reason, &last); err != nil {
		t.Fatal(err)
	}
	if state != "stopped" || !strings.Contains(reason, eventstream.ReasonBadSignature) || last != 102 {
		t.Fatalf("state=%s reason=%s last=%d", state, reason, last)
	}
	if _, err = puller.Pull(ctx); !errors.Is(err, eventstream.ErrStopped) {
		t.Fatalf("stopped stream pulled again: %v", err)
	}

	// Rewriting history the receiver already verified is detected from the head.
	pricing, err := eventstream.NewPuller(receiver, clients["ledger"], eventstream.Verifier{Producer: "payment", Stream: "payment.pricing", Keys: keys,
		Known: func(eventType string, version uint32) bool {
			return eventType == "PricingVersionApproved" && version == 1
		}}, receiverTables, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertEvents(ctx, producer, "payment.pricing", "PricingVersionApproved", 3); err != nil {
		t.Fatal(err)
	}
	if err = sequenceAll(ctx, sequencer, "payment.pricing"); err != nil {
		t.Fatal(err)
	}
	if pulled, err := pullAll(ctx, pricing); err != nil || pulled != 3 {
		t.Fatalf("pulled=%d err=%v", pulled, err)
	}
	if _, err = producer.Exec(ctx, "UPDATE payment_stream_heads SET last_sequence = 2 WHERE stream = 'payment.pricing'"); err != nil {
		t.Fatal(err)
	}
	if _, err = pricing.CheckHead(ctx); !errors.As(err, &stopErr) || stopErr.Reason != eventstream.ReasonHeadRegressed {
		t.Fatalf("regressed head: %v", err)
	}
}

func TestUnknownEventTypeStopsStream(t *testing.T) {
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
	producer := isolatedPool(t, ctx, admin, raw, "payment_test", producerSchema)
	receiver := isolatedPool(t, ctx, admin, raw, "ledger_test", receiverSchema)
	if _, err = producer.Exec(ctx, "INSERT INTO payment_stream_heads (stream) VALUES ('payment.orders')"); err != nil {
		t.Fatal(err)
	}
	if _, err = receiver.Exec(ctx, "INSERT INTO ledger_stream_cursors (stream, producer) VALUES ('payment.orders', 'payment')"); err != nil {
		t.Fatal(err)
	}
	signer, _ := signing.Open(ctx, signing.Config{Environment: config.Development, Backend: signing.BackendMemory, KeyID: "payment-dev-1"}, nil)
	tables := eventstream.ProducerTables{StreamHeads: "payment_stream_heads", Outbox: "payment_outbox"}
	sequencer, _ := eventstream.NewSequencer(producer, "payment", tables, signer, 50)
	if err = insertEvents(ctx, producer, "payment.orders", "OrderPaid", 2); err != nil {
		t.Fatal(err)
	}
	if err = insertEvents(ctx, producer, "payment.orders", "OrderVanished", 1); err != nil {
		t.Fatal(err)
	}
	if err = sequenceAll(ctx, sequencer, "payment.orders"); err != nil {
		t.Fatal(err)
	}
	reader, _ := eventstream.NewReader(producer, "payment", tables, map[string][]string{"payment.orders": {"ledger"}})
	clients := serveEvents(t, reader)
	keys, _ := signing.NewPublicKeys(map[string]*ecdsa.PublicKey{"payment-dev-1": signer.PublicKey()})
	puller, err := eventstream.NewPuller(receiver, clients["ledger"], eventstream.Verifier{Producer: "payment", Stream: "payment.orders", Keys: keys,
		Known: func(eventType string, version uint32) bool { return eventType == "OrderPaid" && version == 1 }}, eventstream.ReceiverTables{Cursors: "ledger_stream_cursors", Inbox: "ledger_inbox"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	pulled, err := puller.Pull(ctx)
	var stopErr *eventstream.StopError
	if pulled != 2 || !errors.As(err, &stopErr) || stopErr.Reason != eventstream.ReasonUnknownEvent {
		t.Fatalf("pulled=%d err=%v", pulled, err)
	}
}

func TestReplayGuardOnPostgres(t *testing.T) {
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
	pool := isolatedPool(t, ctx, admin, raw, "settlement_test", receiverSchema)
	guard, err := authz.NewPostgresReplayGuard(pool, "ledger_used_assertions")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	use := authz.Use{ID: "jti-0123456789abcdef", Method: "/aipay.settlement.v1.WithdrawalService/CreateWithdrawal", Subject: "user-1", ExpiresAt: now.Add(time.Minute)}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- guard.Consume(ctx, use) }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case !errors.Is(err, authz.ErrReplayed):
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("%d concurrent uses of one assertion accepted", accepted)
	}
	// Rows stay until no verifier could still accept the assertion.
	if deleted, err := guard.DeleteExpired(ctx, now.Add(time.Minute+10*time.Second)); err != nil || deleted != 0 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	if deleted, err := guard.DeleteExpired(ctx, now.Add(2*time.Minute)); err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %v", code, err)
	}
}
