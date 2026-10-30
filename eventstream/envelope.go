// Package eventstream implements the signed event protocol of the contract:
// producers sequence and sign outbox rows per stream, receivers pull, verify
// the hash chain and signatures, and store envelopes unchanged in an inbox.
//
// Envelopes are the generated aipay.events.v1.SignedEvent messages: Reader
// implements EventStreamServiceServer and Puller reads through the generated
// client. Table names are supplied by the owning service; the expected columns
// follow the shared producer and receiver templates of the database design.
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

	eventsv1 "github.com/aipay-dev/protobuf/gen/go/aipay/events/v1"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/signing"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// Cursor is the last verified position of a stream.
type Cursor struct {
	Sequence uint64
	Digest   [32]byte
}

func validEventID(id string) bool {
	parsed, err := uuid.Parse(id)
	// The canonical lowercase form survives a round trip through a UUID column,
	// so an inbox copy re-verifies byte for byte.
	return err == nil && parsed.Version() == 7 && parsed.String() == id
}

// validTime requires microsecond precision: PostgreSQL TIMESTAMPTZ keeps no
// more, and a stored envelope must reproduce the signed nanoseconds exactly.
func validTime(ts *timestamppb.Timestamp) bool {
	if ts.CheckValid() != nil || ts.GetNanos()%1000 != 0 {
		return false
	}
	t := ts.AsTime()
	return !t.Before(minNanos) && !t.After(maxNanos)
}

func validateHeader(e *eventsv1.SignedEvent) error {
	if e == nil {
		return errors.New("missing envelope")
	}
	switch {
	case !validEventID(e.GetEventId()):
		return errors.New("event_id must be a canonical lowercase UUIDv7")
	case !config.ValidService(e.GetProducer()):
		return errors.New("invalid producer")
	case !ValidStream(e.GetStream()):
		return errors.New("invalid stream name")
	case e.GetSequence() == 0 || e.GetSequence() > math.MaxInt64:
		return errors.New("sequence must be between 1 and 2^63-1")
	case !eventTypePattern.MatchString(e.GetEventType()):
		return errors.New("invalid event_type")
	case e.GetSchemaVersion() == 0 || e.GetSchemaVersion() > math.MaxInt32:
		return errors.New("invalid schema_version")
	case !validTime(e.GetOccurredAt()):
		return errors.New("occurred_at must be a microsecond-precision time")
	case !validTime(e.GetRecordedAt()):
		return errors.New("recorded_at must be a microsecond-precision time")
	case len(e.GetPayload()) > MaxPayloadBytes:
		return errors.New("payload exceeds 1 MiB")
	case len(e.GetPayloadDigest()) != 32 || len(e.GetPrevDigest()) != 32:
		return errors.New("digests must be 32 bytes")
	}
	return nil
}

// Validate checks the envelope shape, including key_id and signature
// presence, without verifying the chain or the signature.
func Validate(e *eventsv1.SignedEvent) error {
	if err := validateHeader(e); err != nil {
		return err
	}
	if !signing.ValidKeyID(e.GetKeyId()) || len(e.GetSignature()) == 0 || len(e.GetSignature()) > maxSignatureLen {
		return errors.New("invalid key_id or signature")
	}
	return nil
}

// SigningInput returns the AIPAY-EVENT-V1 canonical bytes of e.
func SigningInput(e *eventsv1.SignedEvent) ([]byte, error) {
	if err := validateHeader(e); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 256)
	b = append(b, DomainTag...)
	str := func(v []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	str([]byte(e.GetProducer()))
	str([]byte(e.GetStream()))
	b = binary.BigEndian.AppendUint64(b, e.GetSequence())
	str([]byte(e.GetEventId()))
	str([]byte(e.GetEventType()))
	b = binary.BigEndian.AppendUint64(b, uint64(e.GetSchemaVersion()))
	b = binary.BigEndian.AppendUint64(b, uint64(e.GetOccurredAt().AsTime().UnixNano()))
	str(e.GetPayloadDigest())
	str(e.GetPrevDigest())
	return b, nil
}

// Digest returns event_digest = SHA-256(signing input).
func Digest(e *eventsv1.SignedEvent) ([32]byte, error) {
	input, err := SigningInput(e)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(input), nil
}

// Seal returns a signed copy of e: payload_digest is computed when absent
// (and must match when present), key_id is the signer's, and the signature
// covers the AIPAY-EVENT-V1 signing input. It also returns the event_digest.
func Seal(ctx context.Context, signer signing.Signer, e *eventsv1.SignedEvent) (*eventsv1.SignedEvent, [32]byte, error) {
	if e == nil {
		return nil, [32]byte{}, errors.New("missing envelope")
	}
	sealed := proto.Clone(e).(*eventsv1.SignedEvent)
	payload := sha256.Sum256(sealed.GetPayload())
	if sealed.PayloadDigest == nil {
		sealed.PayloadDigest = payload[:]
	} else if !bytes.Equal(sealed.GetPayloadDigest(), payload[:]) {
		return nil, [32]byte{}, errors.New("stored payload_digest does not match payload")
	}
	sealed.KeyId = signer.KeyID()
	input, err := SigningInput(sealed)
	if err != nil {
		return nil, [32]byte{}, err
	}
	signature, err := signer.Sign(ctx, input)
	if err != nil {
		return nil, [32]byte{}, err
	}
	sealed.Signature = signature
	return sealed, sha256.Sum256(input), nil
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
func (v Verifier) Next(cursor Cursor, e *eventsv1.SignedEvent) (Cursor, error) {
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
	case e.GetProducer() != v.Producer:
		return stop(ReasonProducerMismatch)
	case e.GetStream() != v.Stream:
		return stop(ReasonStreamMismatch)
	case e.GetSequence() != cursor.Sequence+1:
		return stop(ReasonSequenceGap)
	case !bytes.Equal(e.GetPrevDigest(), cursor.Digest[:]):
		return stop(ReasonPrevDigest)
	}
	if payload := sha256.Sum256(e.GetPayload()); !bytes.Equal(payload[:], e.GetPayloadDigest()) {
		return stop(ReasonPayloadDigest)
	}
	input, err := SigningInput(e)
	if err != nil {
		return stop(ReasonMalformed)
	}
	if err = v.Keys.Verify(e.GetKeyId(), input, e.GetSignature()); errors.Is(err, signing.ErrUnknownKey) {
		return stop(ReasonUnknownKey)
	} else if err != nil {
		return stop(ReasonBadSignature)
	}
	if !v.Known(e.GetEventType(), e.GetSchemaVersion()) {
		return stop(ReasonUnknownEvent)
	}
	return Cursor{Sequence: e.GetSequence(), Digest: sha256.Sum256(input)}, nil
}
