package eventstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	eventsv1 "github.com/Kaivodev/protobuf/gen/go/aipay/events/v1"
	"github.com/Kaivodev/servicekit/authz"
	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/signing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Sequencer assigns sequence numbers to committed outbox rows of one producer.
// Business transactions insert outbox rows with payload and type only; the
// sequencer then, per stream and in one transaction, locks the stream head,
// assigns consecutive sequences in id order, chains prev_digest, signs, and
// writes each envelope exactly once. A failure only delays events: it never
// leaves a gap or a fork.
type Sequencer struct {
	db            TxStarter
	producer      string
	signer        signing.Signer
	batch         int
	selectHead    string
	selectPending string
	sealRow       string
	advanceHead   string
}

// NewSequencer signs at most batch (1 to MaxBatch) rows per transaction.
func NewSequencer(db TxStarter, producer string, tables ProducerTables, signer signing.Signer, batch int) (*Sequencer, error) {
	heads, outbox, err := tables.sanitize()
	if err != nil || db == nil || signer == nil || !config.ValidService(producer) || batch < 1 || batch > MaxBatch {
		return nil, errors.New("invalid event sequencer configuration")
	}
	return &Sequencer{db: db, producer: producer, signer: signer, batch: batch,
		// FOR NO KEY UPDATE serializes sequencers without blocking the foreign
		// key checks of business transactions inserting outbox rows.
		selectHead:    "SELECT last_sequence, last_event_digest FROM " + heads + " WHERE stream = $1 FOR NO KEY UPDATE",
		selectPending: "SELECT id, event_id::text, event_type, schema_version, occurred_at, recorded_at, payload, payload_digest FROM " + outbox + " WHERE stream = $1 AND sequence IS NULL ORDER BY id LIMIT $2",
		sealRow:       "UPDATE " + outbox + " SET sequence = $2, prev_digest = $3, event_digest = $4, key_id = $5, signature = $6, sequenced_at = clock_timestamp() WHERE id = $1 AND sequence IS NULL",
		advanceHead:   "UPDATE " + heads + " SET last_sequence = $2, last_event_digest = $3, updated_at = now() WHERE stream = $1 AND last_sequence = $4",
	}, nil
}

type pendingRow struct {
	id       int64
	envelope *eventsv1.SignedEvent
}

// SequenceStream signs up to one batch and returns how many rows it sealed;
// call it again while the result equals the batch size.
func (s *Sequencer) SequenceStream(ctx context.Context, stream string) (int, error) {
	if !ValidStream(stream) {
		return 0, errors.New("invalid stream name")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, errors.New("begin sequencing transaction failed")
	}
	defer rollback(ctx, tx)
	var last int64
	var lastDigest []byte
	if err = tx.QueryRow(ctx, s.selectHead, stream).Scan(&last, &lastDigest); err != nil {
		return 0, errors.New("stream head is missing or unavailable")
	}
	prev, err := digest32(lastDigest)
	if err != nil || last < 0 {
		return 0, errors.New("stream head is corrupt")
	}
	rows, err := tx.Query(ctx, s.selectPending, stream, s.batch)
	if err != nil {
		return 0, errors.New("read pending outbox rows failed")
	}
	var pending []pendingRow
	for rows.Next() {
		row := pendingRow{envelope: &eventsv1.SignedEvent{}}
		var version int32
		var occurred, recorded time.Time
		e := row.envelope
		if err = rows.Scan(&row.id, &e.EventId, &e.EventType, &version, &occurred, &recorded, &e.Payload, &e.PayloadDigest); err != nil {
			rows.Close()
			return 0, errors.New("read pending outbox row failed")
		}
		e.SchemaVersion, e.OccurredAt, e.RecordedAt = uint32(version), timestamppb.New(occurred), timestamppb.New(recorded)
		pending = append(pending, row)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, errors.New("read pending outbox rows failed")
	}
	sequence := uint64(last)
	for _, row := range pending {
		e := row.envelope
		e.Producer, e.Stream, e.Sequence, e.PrevDigest = s.producer, stream, sequence+1, bytes.Clone(prev[:])
		sealed, digest, err := Seal(ctx, s.signer, e)
		if err != nil {
			return 0, fmt.Errorf("outbox row %d cannot be sealed: %w", row.id, err)
		}
		tag, err := tx.Exec(ctx, s.sealRow, row.id, int64(sealed.GetSequence()), sealed.GetPrevDigest(), digest[:], sealed.GetKeyId(), sealed.GetSignature())
		if err != nil || tag.RowsAffected() != 1 {
			return 0, errors.New("seal outbox row failed")
		}
		sequence, prev = sealed.GetSequence(), digest
	}
	if len(pending) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, s.advanceHead, stream, int64(sequence), prev[:], last)
	if err != nil || tag.RowsAffected() != 1 {
		return 0, errors.New("advance stream head failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, errors.New("commit sequencing transaction failed")
	}
	return len(pending), nil
}

// Reader implements aipay.events.v1.EventStreamService for a producer from its
// outbox; register it on a server whose Authorizer loads the service's
// policy. Each stream is readable only by the receivers configured for it, in
// addition to the method policy that admits every possible receiver.
type Reader struct {
	eventsv1.UnimplementedEventStreamServiceServer
	db         DB
	producer   string
	acl        map[string]map[string]bool
	listEvents string
	readHead   string
}

// NewReader takes stream → allowed receiver services from the stream list.
func NewReader(db DB, producer string, tables ProducerTables, receivers map[string][]string) (*Reader, error) {
	heads, outbox, err := tables.sanitize()
	if err != nil || db == nil || !config.ValidService(producer) || len(receivers) == 0 {
		return nil, errors.New("invalid event reader configuration")
	}
	acl := map[string]map[string]bool{}
	for stream, services := range receivers {
		if !ValidStream(stream) || len(services) == 0 {
			return nil, errors.New("invalid stream receiver list")
		}
		acl[stream] = map[string]bool{}
		for _, service := range services {
			if !config.ValidService(service) {
				return nil, errors.New("invalid stream receiver list")
			}
			acl[stream][service] = true
		}
	}
	return &Reader{db: db, producer: producer, acl: acl,
		listEvents: "SELECT event_id::text, sequence, event_type, schema_version, occurred_at, recorded_at, payload, payload_digest, prev_digest, key_id, signature FROM " + outbox + " WHERE stream = $1 AND sequence > $2 ORDER BY sequence LIMIT $3",
		readHead:   "SELECT last_sequence, last_event_digest FROM " + heads + " WHERE stream = $1",
	}, nil
}

var errStreamDenied = status.Error(codes.PermissionDenied, "Stream is not available to this caller")

// authorize takes the caller only from the verified authorization context, so
// a Reader reached without the Authorizer serves nothing.
func (r *Reader) authorize(ctx context.Context, stream string) error {
	call, ok := authz.FromContext(ctx)
	if !ok || !r.acl[stream][call.Caller()] {
		// Unknown and unauthorized streams look the same to the caller.
		return errStreamDenied
	}
	return nil
}

func (r *Reader) ListEvents(ctx context.Context, request *eventsv1.ListEventsRequest) (*eventsv1.ListEventsResponse, error) {
	stream, after, limit := request.GetStream(), request.GetAfterSequence(), request.GetLimit()
	if err := r.authorize(ctx, stream); err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaxBatch || after > math.MaxInt64 {
		return nil, status.Error(codes.InvalidArgument, "limit must be between 1 and 500")
	}
	rows, err := r.db.Query(ctx, r.listEvents, stream, int64(after), int(limit))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "Events are temporarily unavailable")
	}
	defer rows.Close()
	response := &eventsv1.ListEventsResponse{}
	for rows.Next() {
		e := &eventsv1.SignedEvent{Producer: r.producer, Stream: stream}
		var sequence int64
		var version int32
		var occurred, recorded time.Time
		if err = rows.Scan(&e.EventId, &sequence, &e.EventType, &version, &occurred, &recorded, &e.Payload, &e.PayloadDigest, &e.PrevDigest, &e.KeyId, &e.Signature); err != nil {
			return nil, status.Error(codes.Internal, "Internal Server Error")
		}
		e.Sequence, e.SchemaVersion, e.OccurredAt, e.RecordedAt = uint64(sequence), uint32(version), timestamppb.New(occurred), timestamppb.New(recorded)
		if e.Sequence != after+uint64(len(response.Events))+1 {
			return nil, status.Error(codes.Internal, "Internal Server Error")
		}
		response.Events = append(response.Events, e)
	}
	if rows.Err() != nil {
		return nil, status.Error(codes.Unavailable, "Events are temporarily unavailable")
	}
	return response, nil
}

func (r *Reader) GetStreamHead(ctx context.Context, request *eventsv1.GetStreamHeadRequest) (*eventsv1.GetStreamHeadResponse, error) {
	stream := request.GetStream()
	if err := r.authorize(ctx, stream); err != nil {
		return nil, err
	}
	var sequence int64
	var digest []byte
	if err := r.db.QueryRow(ctx, r.readHead, stream).Scan(&sequence, &digest); err != nil {
		return nil, errStreamDenied
	}
	return &eventsv1.GetStreamHeadResponse{Head: &eventsv1.StreamHead{Stream: stream, Sequence: uint64(sequence), EventDigest: digest}}, nil
}
