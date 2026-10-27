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
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/signing"
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

func (v vectorEnvelope) envelope(t *testing.T) Envelope {
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
	return Envelope{EventID: v.EventID, Producer: v.Producer, Stream: v.Stream, Sequence: number(v.Sequence), EventType: v.EventType,
		SchemaVersion: uint32(number(v.SchemaVersion)), OccurredAt: time.Unix(0, int64(number(v.OccurredAt))).UTC(), RecordedAt: time.Unix(0, int64(number(v.RecordedAt))).UTC(),
		Payload: raw(v.Payload), PayloadDigest: raw(v.PayloadDigest), PrevDigest: raw(v.PrevDigest), KeyID: v.KeyID, Signature: raw(v.Signature)}
}

func anyEvent(string, uint32) bool { return true }

// The contract vectors, published by the protobuf repository.
func TestContractVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/event_signing_v1.json")
	if err != nil {
		t.Fatal(err)
	}
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
	if err = json.Unmarshal(raw, &doc); err != nil {
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

func sealedChain(t *testing.T, signer signing.Signer, n int) []Envelope {
	t.Helper()
	prev := ZeroDigest
	var events []Envelope
	base := time.Date(2026, 10, 26, 8, 0, 0, 123456000, time.UTC)
	for i := 1; i <= n; i++ {
		e, digest, err := Seal(context.Background(), signer, Envelope{
			EventID: "019a1f40-8b00-7000-8000-00000000000" + strconv.Itoa(i), Producer: "payment", Stream: "payment.orders", Sequence: uint64(i),
			EventType: "OrderPaid", SchemaVersion: 1, OccurredAt: base.Add(time.Duration(i) * time.Second), RecordedAt: base.Add(time.Minute),
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
	cases := map[string]struct {
		cursor Cursor
		edit   func(*Envelope)
		want   string
	}{
		"gap":              {first, func(e *Envelope) { *e = events[2] }, ReasonSequenceGap},
		"replay":           {cursor, func(e *Envelope) { *e = events[2] }, ReasonSequenceGap},
		"fork":             {first, func(e *Envelope) { e.PrevDigest = bytes.Repeat([]byte{1}, 32) }, ReasonPrevDigest},
		"payload":          {first, func(e *Envelope) { e.Payload = []byte("forged") }, ReasonPayloadDigest},
		"recomputed hash":  {first, func(e *Envelope) { e.Payload = []byte("forged"); d := sha256.Sum256(e.Payload); e.PayloadDigest = d[:] }, ReasonBadSignature},
		"occurred_at":      {first, func(e *Envelope) { e.OccurredAt = e.OccurredAt.Add(time.Microsecond) }, ReasonBadSignature},
		"event type":       {first, func(e *Envelope) { e.EventType = "OrderReversed" }, ReasonBadSignature},
		"other key":        {first, func(e *Envelope) { *e = resigned }, ReasonBadSignature},
		"unknown key":      {first, func(e *Envelope) { e.KeyID = "payment-old" }, ReasonUnknownKey},
		"stream":           {first, func(e *Envelope) { e.Stream = "payment.pricing" }, ReasonStreamMismatch},
		"uppercase id":     {first, func(e *Envelope) { e.EventID = "019A1F40-8B00-7000-8000-000000000002" }, ReasonMalformed},
		"uuid v4":          {first, func(e *Envelope) { e.EventID = "019a1f40-8b00-4000-8000-000000000002" }, ReasonMalformed},
		"nanoseconds":      {first, func(e *Envelope) { e.OccurredAt = e.OccurredAt.Add(time.Nanosecond) }, ReasonMalformed},
		"missing sig":      {first, func(e *Envelope) { e.Signature = nil }, ReasonMalformed},
		"unknown version":  {first, func(e *Envelope) { *e = mustSeal(t, signer, *e, func(x *Envelope) { x.SchemaVersion = 2 }) }, ReasonUnknownEvent},
		"unknown event":    {first, func(e *Envelope) { *e = mustSeal(t, signer, *e, func(x *Envelope) { x.EventType = "OrderVanished" }) }, ReasonUnknownEvent},
		"producer differs": {first, func(e *Envelope) { *e = mustSeal(t, signer, *e, func(x *Envelope) { x.Producer = "ledger" }) }, ReasonProducerMismatch},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := events[1]
			e.Payload, e.PrevDigest = bytes.Clone(e.Payload), bytes.Clone(e.PrevDigest)
			tc.edit(&e)
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

func mustSeal(t *testing.T, signer signing.Signer, e Envelope, edit func(*Envelope)) Envelope {
	t.Helper()
	edit(&e)
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
}
