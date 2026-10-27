package eventstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Source is a producer's EventStreamService as seen by a receiver; services
// adapt the generated gRPC client to it. Transport errors are returned as is
// and never stop the stream.
type Source interface {
	ListEvents(ctx context.Context, stream string, afterSequence uint64, limit uint32) ([]Envelope, error)
	GetStreamHead(ctx context.Context, stream string) (Head, error)
}

var (
	// ErrStopped means the stream cursor is stopped. Resuming it needs a person
	// and a two-approver request; the puller never resumes on its own.
	ErrStopped = errors.New("event stream is stopped")
	// ErrCursorMoved means another puller advanced the cursor concurrently;
	// retrying is safe.
	ErrCursorMoved = errors.New("event stream cursor moved concurrently")
)

// Puller pulls one producer stream into the receiver's inbox. Verified
// envelopes are inserted unchanged and the cursor advances in the same
// transaction; any verification failure stores the verified prefix and stops
// the stream with its reason.
type Puller struct {
	db           Pool
	source       Source
	verifier     Verifier
	limit        uint32
	readCursor   string
	lockCursor   string
	insertInbox  string
	advance      string
	stopCursor   string
	updateCursor string
}

func NewPuller(db Pool, source Source, verifier Verifier, tables ReceiverTables, limit uint32) (*Puller, error) {
	cursors, inbox, err := tables.sanitize()
	if err != nil || db == nil || source == nil || verifier.check() != nil || limit < 1 || limit > MaxBatch {
		return nil, errors.New("invalid event puller configuration")
	}
	return &Puller{db: db, source: source, verifier: verifier, limit: limit,
		readCursor:   "SELECT producer, last_sequence, last_event_digest, state FROM " + cursors + " WHERE stream = $1",
		lockCursor:   "SELECT producer, last_sequence, last_event_digest, state FROM " + cursors + " WHERE stream = $1 FOR UPDATE",
		insertInbox:  "INSERT INTO " + inbox + " (stream, sequence, event_id, producer, event_type, schema_version, occurred_at, recorded_at, payload, payload_digest, prev_digest, event_digest, key_id, signature) VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
		updateCursor: "UPDATE " + cursors + " SET last_sequence = $2, last_event_digest = $3, updated_at = now() WHERE stream = $1 AND state = 'running'",
		stopCursor:   "UPDATE " + cursors + " SET state = 'stopped', stopped_reason = $2, stopped_at = now(), updated_at = now() WHERE stream = $1 AND state = 'running'",
	}, nil
}

type cursorRow struct {
	producer string
	cursor   Cursor
	state    string
}

func (p *Puller) scanCursor(row pgx.Row) (cursorRow, error) {
	var c cursorRow
	var sequence int64
	var digest []byte
	if err := row.Scan(&c.producer, &sequence, &digest, &c.state); err != nil {
		return c, errors.New("stream cursor is missing or unavailable")
	}
	d, err := digest32(digest)
	if err != nil || sequence < 0 {
		return c, errors.New("stream cursor is corrupt")
	}
	if c.producer != p.verifier.Producer {
		return c, errors.New("stream cursor belongs to another producer")
	}
	c.cursor = Cursor{Sequence: uint64(sequence), Digest: d}
	return c, nil
}

func (p *Puller) current(ctx context.Context, db DB, query string) (Cursor, error) {
	c, err := p.scanCursor(db.QueryRow(ctx, query, p.verifier.Stream))
	if err != nil {
		return Cursor{}, err
	}
	if c.state != "running" {
		return Cursor{}, ErrStopped
	}
	return c.cursor, nil
}

// Pull fetches and stores at most one batch. It returns the number of stored
// events; a *StopError (also matching ErrStopped) when this call stopped the
// stream; ErrStopped when it was already stopped.
func (p *Puller) Pull(ctx context.Context) (int, error) {
	start, err := p.current(ctx, p.db, p.readCursor)
	if err != nil {
		return 0, err
	}
	events, err := p.source.ListEvents(ctx, p.verifier.Stream, start.Sequence, p.limit)
	if err != nil {
		return 0, fmt.Errorf("list events: %w", err)
	}
	var stop *StopError
	if uint32(len(events)) > p.limit {
		stop = &StopError{Reason: ReasonBatchTooLarge, Sequence: start.Sequence + 1}
		events = nil
	}
	type verified struct {
		envelope Envelope
		digest   [32]byte
	}
	var valid []verified
	cursor := start
	for _, e := range events {
		next, err := p.verifier.Next(cursor, e)
		if err != nil {
			if !errors.As(err, &stop) {
				return 0, err
			}
			break
		}
		valid = append(valid, verified{e, next.Digest})
		cursor = next
	}
	if len(valid) == 0 && stop == nil {
		return 0, nil
	}
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return 0, errors.New("begin inbox transaction failed")
	}
	defer rollback(ctx, tx)
	locked, err := p.current(ctx, tx, p.lockCursor)
	if err != nil {
		return 0, err
	}
	if locked != start {
		return 0, ErrCursorMoved
	}
	for _, v := range valid {
		e := v.envelope
		_, err = tx.Exec(ctx, p.insertInbox, e.Stream, int64(e.Sequence), e.EventID, e.Producer, e.EventType, int32(e.SchemaVersion),
			e.OccurredAt, e.RecordedAt, e.Payload, e.PayloadDigest, e.PrevDigest, v.digest[:], e.KeyID, e.Signature)
		if uniqueViolation(err) {
			// The same event_id at another position means the producer reused an
			// identity: an integrity failure, not a harmless duplicate.
			rollback(ctx, tx)
			return 0, p.stopAfter(ctx, start, &StopError{Reason: ReasonDuplicateEvent, Sequence: e.Sequence})
		}
		if err != nil {
			return 0, errors.New("insert inbox envelope failed")
		}
	}
	if len(valid) > 0 {
		if tag, err := tx.Exec(ctx, p.updateCursor, p.verifier.Stream, int64(cursor.Sequence), cursor.Digest[:]); err != nil || tag.RowsAffected() != 1 {
			return 0, errors.New("advance stream cursor failed")
		}
	}
	if stop != nil {
		if tag, err := tx.Exec(ctx, p.stopCursor, p.verifier.Stream, stop.Error()); err != nil || tag.RowsAffected() != 1 {
			return 0, errors.New("stop stream cursor failed")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, errors.New("commit inbox transaction failed")
	}
	if stop != nil {
		return len(valid), stopped{stop}
	}
	return len(valid), nil
}

// stopped lets callers match both the reason and ErrStopped.
type stopped struct{ *StopError }

func (s stopped) Unwrap() []error { return []error{s.StopError, ErrStopped} }

func (p *Puller) stopAfter(ctx context.Context, expected Cursor, stop *StopError) error {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return errors.New("begin stop transaction failed")
	}
	defer rollback(ctx, tx)
	locked, err := p.current(ctx, tx, p.lockCursor)
	if err != nil {
		return err
	}
	if locked != expected {
		return ErrCursorMoved
	}
	if tag, err := tx.Exec(ctx, p.stopCursor, p.verifier.Stream, stop.Error()); err != nil || tag.RowsAffected() != 1 {
		return errors.New("stop stream cursor failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.New("commit stop transaction failed")
	}
	return stopped{stop}
}

// CheckHead compares the producer's head with the cursor and stops the stream
// when the producer reports less history or a different digest than the
// receiver already verified. It returns how many events are not yet pulled.
func (p *Puller) CheckHead(ctx context.Context) (uint64, error) {
	cursor, err := p.current(ctx, p.db, p.readCursor)
	if err != nil {
		return 0, err
	}
	head, err := p.source.GetStreamHead(ctx, p.verifier.Stream)
	if err != nil {
		return 0, fmt.Errorf("get stream head: %w", err)
	}
	switch {
	case head.Stream != p.verifier.Stream || len(head.EventDigest) != 32:
		return 0, p.stopAfter(ctx, cursor, &StopError{Reason: ReasonMalformed, Sequence: cursor.Sequence})
	case head.Sequence < cursor.Sequence:
		return 0, p.stopAfter(ctx, cursor, &StopError{Reason: ReasonHeadRegressed, Sequence: head.Sequence})
	case head.Sequence == cursor.Sequence && !bytes.Equal(head.EventDigest, cursor.Digest[:]):
		return 0, p.stopAfter(ctx, cursor, &StopError{Reason: ReasonHeadForked, Sequence: head.Sequence})
	}
	return head.Sequence - cursor.Sequence, nil
}

// Outcome is the one-time processing result of an inbox envelope.
type Outcome string

const (
	Applied     Outcome = "applied"
	Quarantined Outcome = "quarantined"
	Ignored     Outcome = "ignored"
)

// ErrResolved means the envelope is not pending: it was already processed.
var ErrResolved = errors.New("inbox envelope is not pending")

// Inbox reads pending envelopes and records their outcome. Call both inside
// the business transaction so the outcome commits with its effects.
type Inbox struct {
	stream      string
	pending     string
	resolve     string
	maxPerQuery int
}

func NewInbox(tables ReceiverTables, stream string) (*Inbox, error) {
	_, inbox, err := tables.sanitize()
	if err != nil || !ValidStream(stream) {
		return nil, errors.New("invalid inbox configuration")
	}
	return &Inbox{stream: stream, maxPerQuery: MaxBatch,
		pending: "SELECT event_id::text, producer, sequence, event_type, schema_version, occurred_at, recorded_at, payload, payload_digest, prev_digest, key_id, signature FROM " + inbox + " WHERE stream = $1 AND status = 'pending' ORDER BY sequence LIMIT $2",
		resolve: "UPDATE " + inbox + " SET status = $3, processed_at = now(), quarantine_reason = $4 WHERE stream = $1 AND sequence = $2 AND status = 'pending'",
	}, nil
}

// Pending returns up to limit pending envelopes in sequence order.
func (i *Inbox) Pending(ctx context.Context, db DB, limit int) ([]Envelope, error) {
	if limit < 1 || limit > i.maxPerQuery {
		return nil, errors.New("invalid inbox read limit")
	}
	rows, err := db.Query(ctx, i.pending, i.stream, limit)
	if err != nil {
		return nil, errors.New("read inbox failed")
	}
	defer rows.Close()
	var result []Envelope
	for rows.Next() {
		e := Envelope{Stream: i.stream}
		var sequence int64
		var version int32
		if err = rows.Scan(&e.EventID, &e.Producer, &sequence, &e.EventType, &version, &e.OccurredAt, &e.RecordedAt, &e.Payload, &e.PayloadDigest, &e.PrevDigest, &e.KeyID, &e.Signature); err != nil {
			return nil, errors.New("read inbox envelope failed")
		}
		e.Sequence, e.SchemaVersion = uint64(sequence), uint32(version)
		e.OccurredAt, e.RecordedAt = e.OccurredAt.UTC(), e.RecordedAt.UTC()
		result = append(result, e)
	}
	if rows.Err() != nil {
		return nil, errors.New("read inbox failed")
	}
	return result, nil
}

// Resolve records the outcome once; a quarantine needs a reason, the other
// outcomes take none.
func (i *Inbox) Resolve(ctx context.Context, db DB, sequence uint64, outcome Outcome, reason string) error {
	var stored any
	switch outcome {
	case Applied, Ignored:
		if reason != "" {
			return errors.New("only a quarantine records a reason")
		}
	case Quarantined:
		if reason == "" {
			return errors.New("a quarantine requires a reason")
		}
		stored = reason
	default:
		return errors.New("unknown inbox outcome")
	}
	tag, err := db.Exec(ctx, i.resolve, i.stream, int64(sequence), string(outcome), stored)
	if err != nil {
		return errors.New("record inbox outcome failed")
	}
	if tag.RowsAffected() != 1 {
		return ErrResolved
	}
	return nil
}
