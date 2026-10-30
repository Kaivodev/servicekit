package eventstream

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	eventsv1 "github.com/aipay-dev/protobuf/gen/go/aipay/events/v1"
	"github.com/aipay-dev/protobuf/testvectors"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/signing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type vectorEnvelope struct {
	EventID       string `json:"event_id"`
	Producer      string `json:"producer"`
	Stream        string `json:"stream"`
	Sequence      string `json:"sequence"`
	EventType     string `json:"event_type"`
	SchemaVersion string `json:"schema_version"`
	OccurredAt    string `json:"occurred_at_unix_nanos"`
	RecordedAt    string `json:"recorded_at_unix_nanos"`
	Payload       string `json:"payload"`
	PayloadDigest string `json:"payload_digest"`
	PrevDigest    string `json:"prev_digest"`
	KeyID         string `json:"key_id"`
	Signature     string `json:"signature"`
}

func (v vectorEnvelope) envelope(t *testing.T) *eventsv1.SignedEvent {
	t.Helper()
	number := func(s string) uint64 {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	raw := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return &eventsv1.SignedEvent{EventId: v.EventID, Producer: v.Producer, Stream: v.Stream, Sequence: number(v.Sequence), EventType: v.EventType,
		SchemaVersion: uint32(number(v.SchemaVersion)), OccurredAt: timestamppb.New(time.Unix(0, int64(number(v.OccurredAt)))), RecordedAt: timestamppb.New(time.Unix(0, int64(number(v.RecordedAt)))),
		Payload: raw(v.Payload), PayloadDigest: raw(v.PayloadDigest), PrevDigest: raw(v.PrevDigest), KeyId: v.KeyID, Signature: raw(v.Signature)}
}

func anyEvent(string, uint32) bool { return true }

// The contract vectors published with the protobuf SDK.
func TestContractVectors(t *testing.T) {
	var doc struct {
		Producer   string `json:"producer"`
		Stream     string `json:"stream"`
		PublicKeys []struct {
			KeyID   string `json:"key_id"`
			SPKIDER string `json:"spki_der"`
		} `json:"public_keys"`
		Events []struct {
			Envelope     vectorEnvelope `json:"envelope"`
			SigningInput string         `json:"signing_input"`
			EventDigest  string         `json:"event_digest"`
		} `json:"events"`
		Invalid []struct {
			Name   string `json:"name"`
			Cursor struct {
				Sequence    string `json:"sequence"`
				EventDigest string `json:"event_digest"`
			} `json:"cursor"`
			Envelope vectorEnvelope `json:"envelope"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(testvectors.EventSigningV1(), &doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, key := range doc.PublicKeys {
		der, _ := hex.DecodeString(key.SPKIDER)
		public, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatal(err)
		}
		keys[key.KeyID] = public.(*ecdsa.PublicKey)
	}
	registry, err := signing.NewPublicKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	verifier := Verifier{Producer: doc.Producer, Stream: doc.Stream, Keys: registry, Known: anyEvent}
	cursor := Cursor{}
	for _, vector := range doc.Events {
		e := vector.Envelope.envelope(t)
		input, err := SigningInput(e)
		if err != nil || hex.EncodeToString(input) != vector.SigningInput {
			t.Fatalf("signing input differs from the contract vector: %v", err)
		}
		if cursor, err = verifier.Next(cursor, e); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(cursor.Digest[:]) != vector.EventDigest {
			t.Fatal("event digest differs from the contract vector")
		}
	}
	want := map[string]string{
		"payload_tampered": ReasonPayloadDigest, "signature_tampered": ReasonBadSignature, "prev_digest_broken": ReasonPrevDigest,
		"sequence_gap": ReasonSequenceGap, "wrong_signing_key": ReasonBadSignature, "unregistered_key_id": ReasonUnknownKey, "producer_mismatch": ReasonProducerMismatch,
	}
	for _, invalid := range doc.Invalid {
		sequence, _ := strconv.ParseUint(invalid.Cursor.Sequence, 10, 64)
		digest, _ := hex.DecodeString(invalid.Cursor.EventDigest)
		start := Cursor{Sequence: sequence}
		copy(start.Digest[:], digest)
		_, err := verifier.Next(start, invalid.Envelope.envelope(t))
		var stop *StopError
		if !errors.As(err, &stop) || stop.Reason != want[invalid.Name] {
			t.Fatalf("%s: got %v, want %s", invalid.Name, err, want[invalid.Name])
		}
	}
}

func developmentSigner(t *testing.T, id string) signing.Signer {
	t.Helper()
	signer, err := signing.Open(context.Background(), signing.Config{Environment: config.Development, Backend: signing.BackendMemory, KeyID: id}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func sealedChain(t *testing.T, signer signing.Signer, n int) []*eventsv1.SignedEvent {
	t.Helper()
	prev := ZeroDigest
	var events []*eventsv1.SignedEvent
	base := time.Date(2026, 10, 26, 8, 0, 0, 123456000, time.UTC)
	for i := 1; i <= n; i++ {
		e, digest, err := Seal(context.Background(), signer, &eventsv1.SignedEvent{
			EventId: "019a1f40-8b00-7000-8000-00000000000" + strconv.Itoa(i), Producer: "payment", Stream: "payment.orders", Sequence: uint64(i),
			EventType: "OrderPaid", SchemaVersion: 1, OccurredAt: timestamppb.New(base.Add(time.Duration(i) * time.Second)), RecordedAt: timestamppb.New(base.Add(time.Minute)),
			Payload: []byte{byte(i)}, PrevDigest: bytes.Clone(prev[:]),
		})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
		prev = digest
	}
	return events
}

func TestChainVerificationStopsOnEveryBreak(t *testing.T) {
	signer := developmentSigner(t, "payment-dev")
	registry, err := signing.NewPublicKeys(map[string]*ecdsa.PublicKey{"payment-dev": signer.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	events := sealedChain(t, signer, 3)
	verifier := Verifier{Producer: "payment", Stream: "payment.orders", Keys: registry, Known: func(eventType string, version uint32) bool {
		return eventType == "OrderPaid" && version == 1
	}}
	cursor := Cursor{}
	for _, e := range events {
		if cursor, err = verifier.Next(cursor, e); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := verifier.Next(Cursor{}, events[0])
	other := developmentSigner(t, "payment-dev")
	resigned, _, _ := Seal(context.Background(), other, events[1])
	shift := func(ts *timestamppb.Timestamp, d time.Duration) *timestamppb.Timestamp {
		return timestamppb.New(ts.AsTime().Add(d))
	}
	cases := map[string]struct {
		cursor Cursor
		edit   func(*eventsv1.SignedEvent) *eventsv1.SignedEvent
		want   string
	}{
		"gap":    {first, func(*eventsv1.SignedEvent) *eventsv1.SignedEvent { return events[2] }, ReasonSequenceGap},
		"replay": {cursor, func(*eventsv1.SignedEvent) *eventsv1.SignedEvent { return events[2] }, ReasonSequenceGap},
		"fork": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			e.PrevDigest = bytes.Repeat([]byte{1}, 32)
			return e
		}, ReasonPrevDigest},
		"payload": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent { e.Payload = []byte("forged"); return e }, ReasonPayloadDigest},
		"recomputed hash": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			e.Payload = []byte("forged")
			d := sha256.Sum256(e.Payload)
			e.PayloadDigest = d[:]
			return e
		}, ReasonBadSignature},
		"occurred_at": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			e.OccurredAt = shift(e.OccurredAt, time.Microsecond)
			return e
		}, ReasonBadSignature},
		"event type":  {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent { e.EventType = "OrderReversed"; return e }, ReasonBadSignature},
		"other key":   {first, func(*eventsv1.SignedEvent) *eventsv1.SignedEvent { return resigned }, ReasonBadSignature},
		"unknown key": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent { e.KeyId = "payment-old"; return e }, ReasonUnknownKey},
		"stream":      {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent { e.Stream = "payment.pricing"; return e }, ReasonStreamMismatch},
		"uppercase id": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			e.EventId = "019A1F40-8B00-7000-8000-000000000002"
			return e
		}, ReasonMalformed},
		"uuid v4": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			e.EventId = "019a1f40-8b00-4000-8000-000000000002"
			return e
		}, ReasonMalformed},
		"nanoseconds": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			e.OccurredAt = shift(e.OccurredAt, time.Nanosecond)
			return e
		}, ReasonMalformed},
		"no occurred_at": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent { e.OccurredAt = nil; return e }, ReasonMalformed},
		"missing sig":    {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent { e.Signature = nil; return e }, ReasonMalformed},
		"nil envelope":   {first, func(*eventsv1.SignedEvent) *eventsv1.SignedEvent { return nil }, ReasonMalformed},
		"unknown version": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			return mustSeal(t, signer, e, func(x *eventsv1.SignedEvent) { x.SchemaVersion = 2 })
		}, ReasonUnknownEvent},
		"unknown event": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			return mustSeal(t, signer, e, func(x *eventsv1.SignedEvent) { x.EventType = "OrderVanished" })
		}, ReasonUnknownEvent},
		"producer differs": {first, func(e *eventsv1.SignedEvent) *eventsv1.SignedEvent {
			return mustSeal(t, signer, e, func(x *eventsv1.SignedEvent) { x.Producer = "ledger" })
		}, ReasonProducerMismatch},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := tc.edit(proto.Clone(events[1]).(*eventsv1.SignedEvent))
			next, err := verifier.Next(tc.cursor, e)
			var stop *StopError
			if !errors.As(err, &stop) || stop.Reason != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if next != tc.cursor {
				t.Fatal("a failed verification advanced the cursor")
			}
		})
	}
}

func mustSeal(t *testing.T, signer signing.Signer, e *eventsv1.SignedEvent, edit func(*eventsv1.SignedEvent)) *eventsv1.SignedEvent {
	t.Helper()
	edit(e)
	sealed, _, err := Seal(context.Background(), signer, e)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestSealRejectsMismatchedPayloadDigest(t *testing.T) {
	signer := developmentSigner(t, "payment-dev")
	e := sealedChain(t, signer, 1)[0]
	e.Payload = []byte("changed")
	if _, _, err := Seal(context.Background(), signer, e); err == nil {
		t.Fatal("sealed a payload whose stored digest differs")
	}
	original := sealedChain(t, signer, 1)[0]
	unsigned := proto.Clone(original).(*eventsv1.SignedEvent)
	unsigned.Signature, unsigned.KeyId = nil, ""
	if _, _, err := Seal(context.Background(), signer, unsigned); err != nil || unsigned.Signature != nil {
		t.Fatal("Seal modified its input instead of returning a sealed copy")
	}
}

// Without the authorization context a Reader serves nothing.
func TestReaderRequiresAuthorizationContext(t *testing.T) {
	reader, err := NewReader(unusedDB{}, "payment", ProducerTables{StreamHeads: "payment_stream_heads", Outbox: "payment_outbox"}, map[string][]string{"payment.orders": {"ledger"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ListEvents(context.Background(), &eventsv1.ListEventsRequest{Stream: "payment.orders", Limit: 10}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListEvents without authorization: %v", err)
	}
	if _, err = reader.GetStreamHead(context.Background(), &eventsv1.GetStreamHeadRequest{Stream: "payment.orders"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetStreamHead without authorization: %v", err)
	}
}

type unusedDB struct{ DB }
