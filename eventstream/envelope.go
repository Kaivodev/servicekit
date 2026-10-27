// Package eventstream implements the signed event protocol of the contract:
// producers sequence and sign outbox rows per stream, receivers pull, verify
// the hash chain and signatures, and store envelopes unchanged in an inbox.
//
// Envelope mirrors aipay.events.v1.SignedEvent; services convert between the
// generated message and this type at their gRPC boundary. Table names are
// supplied by the owning service; the expected columns follow the shared
// producer and receiver templates of the database design.
package eventstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/signing"
	"github.com/google/uuid"
)

const (
	// DomainTag starts every signing input, without a length prefix.
	DomainTag = "AIPAY-EVENT-V1"
	// MaxPayloadBytes matches the outbox template's payload limit.
	MaxPayloadBytes = 1 << 20
	// MaxBatch is the largest ListEvents limit the contract allows.
	MaxBatch        = 500
	maxSignatureLen = 72
)

var (
	streamPattern    = regexp.MustCompile(`^[a-z]+\.[a-z_]+$`)
	eventTypePattern = regexp.MustCompile(`^[A-Z][A-Za-z]+$`)
	// ZeroDigest is prev_digest of sequence 1 and the digest of an empty stream.
	ZeroDigest = [32]byte{}
	minNanos   = time.Unix(0, math.MinInt64)
	maxNanos   = time.Unix(0, math.MaxInt64)
)

func ValidStream(name string) bool { return streamPattern.MatchString(name) }

type Envelope struct {
	EventID       string
	Producer      string
	Stream        string
	Sequence      uint64
	EventType     string
	SchemaVersion uint32
	OccurredAt    time.Time
	RecordedAt    time.Time
	Payload       []byte
	PayloadDigest []byte
	PrevDigest    []byte
	KeyID         string
	Signature     []byte
}

// Cursor is the last verified position of a stream.
type Cursor struct {
	Sequence uint64
	Digest   [32]byte
}

// Head is a producer's reported stream head.
type Head struct {
	Stream      string
	Sequence    uint64
	EventDigest []byte
}

func validEventID(id string) bool {
	parsed, err := uuid.Parse(id)
	// The canonical lowercase form survives a round trip through a UUID column,
	// so an inbox copy re-verifies byte for byte.
	return err == nil && parsed.Version() == 7 && parsed.String() == id
}

// validTime requires microsecond precision: PostgreSQL TIMESTAMPTZ keeps no
// more, and a stored envelope must reproduce the signed nanoseconds exactly.
func validTime(t time.Time) bool {
	return !t.IsZero() && !t.Before(minNanos) && !t.After(maxNanos) && t.Nanosecond()%1000 == 0
}

func validateHeader(e Envelope) error {
	switch {
	case !validEventID(e.EventID):
		return errors.New("event_id must be a canonical lowercase UUIDv7")
	case !config.ValidService(e.Producer):
		return errors.New("invalid producer")
	case !ValidStream(e.Stream):
		return errors.New("invalid stream name")
	case e.Sequence == 0 || e.Sequence > math.MaxInt64:
		return errors.New("sequence must be between 1 and 2^63-1")
	case !eventTypePattern.MatchString(e.EventType):
		return errors.New("invalid event_type")
	case e.SchemaVersion == 0 || e.SchemaVersion > math.MaxInt32:
		return errors.New("invalid schema_version")
	case !validTime(e.OccurredAt):
		return errors.New("occurred_at must be a microsecond-precision time")
	case !validTime(e.RecordedAt):
		return errors.New("recorded_at must be a microsecond-precision time")
	case len(e.Payload) > MaxPayloadBytes:
		return errors.New("payload exceeds 1 MiB")
	case len(e.PayloadDigest) != 32 || len(e.PrevDigest) != 32:
		return errors.New("digests must be 32 bytes")
	}
	return nil
}

// Validate checks the envelope shape, including key_id and signature
// presence, without verifying the chain or the signature.
func Validate(e Envelope) error {
	if err := validateHeader(e); err != nil {
		return err
	}
	if !signing.ValidKeyID(e.KeyID) || len(e.Signature) == 0 || len(e.Signature) > maxSignatureLen {
		return errors.New("invalid key_id or signature")
	}
	return nil
}

// SigningInput returns the AIPAY-EVENT-V1 canonical bytes of e.
func SigningInput(e Envelope) ([]byte, error) {
	if err := validateHeader(e); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 256)
	b = append(b, DomainTag...)
	str := func(v []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	str([]byte(e.Producer))
	str([]byte(e.Stream))
	b = binary.BigEndian.AppendUint64(b, e.Sequence)
	str([]byte(e.EventID))
	str([]byte(e.EventType))
	b = binary.BigEndian.AppendUint64(b, uint64(e.SchemaVersion))
	b = binary.BigEndian.AppendUint64(b, uint64(e.OccurredAt.UnixNano()))
	str(e.PayloadDigest)
	str(e.PrevDigest)
	return b, nil
}

// Digest returns event_digest = SHA-256(signing input).
func Digest(e Envelope) ([32]byte, error) {
	input, err := SigningInput(e)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(input), nil
}

// Seal computes payload_digest when absent, then signs e with signer. It
// returns the sealed envelope and its event_digest.
func Seal(ctx context.Context, signer signing.Signer, e Envelope) (Envelope, [32]byte, error) {
	payload := sha256.Sum256(e.Payload)
	if e.PayloadDigest == nil {
		e.PayloadDigest = payload[:]
	} else if !bytes.Equal(e.PayloadDigest, payload[:]) {
		return Envelope{}, [32]byte{}, errors.New("stored payload_digest does not match payload")
	}
	e.KeyID = signer.KeyID()
	input, err := SigningInput(e)
	if err != nil {
		return Envelope{}, [32]byte{}, err
	}
	signature, err := signer.Sign(ctx, input)
	if err != nil {
		return Envelope{}, [32]byte{}, err
	}
	e.Signature = signature
	return e, sha256.Sum256(input), nil
}

// Stop reasons. Every one of them stops consumption of the stream until a
// person investigates; none is skipped automatically.
const (
	ReasonMalformed        = "malformed_envelope"
	ReasonProducerMismatch = "producer_mismatch"
	ReasonStreamMismatch   = "stream_mismatch"
	ReasonSequenceGap      = "sequence_gap"
	ReasonPrevDigest       = "prev_digest_mismatch"
	ReasonPayloadDigest    = "payload_digest_mismatch"
	ReasonUnknownKey       = "unknown_key"
	ReasonBadSignature     = "bad_signature"
	ReasonUnknownEvent     = "unknown_event_type"
	ReasonDuplicateEvent   = "duplicate_event"
	ReasonBatchTooLarge    = "batch_too_large"
	ReasonHeadRegressed    = "head_regressed"
	ReasonHeadForked       = "head_forked"
)

// StopError means the stream must stop: a verification failure, never a
// transport error.
type StopError struct {
	Reason   string
	Sequence uint64
}

func (e *StopError) Error() string {
	return fmt.Sprintf("event stream stopped: %s at sequence %d", e.Reason, e.Sequence)
}

// Verifier checks one producer's stream. Known decides which
// event_type/schema_version combinations this receiver understands.
type Verifier struct {
	Producer string
	Stream   string
	Keys     signing.PublicKeys
	Known    func(eventType string, schemaVersion uint32) bool
}

func (v Verifier) check() error {
	if !config.ValidService(v.Producer) || !ValidStream(v.Stream) || v.Keys.Len() == 0 || v.Known == nil {
		return errors.New("event verifier requires a producer, stream, public keys and known event types")
	}
	return nil
}

// Next verifies that e directly continues cursor and returns the new cursor.
func (v Verifier) Next(cursor Cursor, e Envelope) (Cursor, error) {
	if err := v.check(); err != nil {
		return cursor, err
	}
	stop := func(reason string) (Cursor, error) {
		return cursor, &StopError{Reason: reason, Sequence: cursor.Sequence + 1}
	}
	if err := Validate(e); err != nil {
		return stop(ReasonMalformed)
	}
	switch {
	case e.Producer != v.Producer:
		return stop(ReasonProducerMismatch)
	case e.Stream != v.Stream:
		return stop(ReasonStreamMismatch)
	case e.Sequence != cursor.Sequence+1:
		return stop(ReasonSequenceGap)
	case !bytes.Equal(e.PrevDigest, cursor.Digest[:]):
		return stop(ReasonPrevDigest)
	}
	if payload := sha256.Sum256(e.Payload); !bytes.Equal(payload[:], e.PayloadDigest) {
		return stop(ReasonPayloadDigest)
	}
	input, err := SigningInput(e)
	if err != nil {
		return stop(ReasonMalformed)
	}
	if err = v.Keys.Verify(e.KeyID, input, e.Signature); errors.Is(err, signing.ErrUnknownKey) {
		return stop(ReasonUnknownKey)
	} else if err != nil {
		return stop(ReasonBadSignature)
	}
	if !v.Known(e.EventType, e.SchemaVersion) {
		return stop(ReasonUnknownEvent)
	}
	return Cursor{Sequence: e.Sequence, Digest: sha256.Sum256(input)}, nil
}
