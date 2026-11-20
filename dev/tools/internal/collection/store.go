package collection

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"errors"

	collectionv1 "github.com/Kaivodev/protobuf/gen/go/aipay/collection/v1"
	"github.com/Kaivodev/servicekit/eventstream"
	"github.com/Kaivodev/servicekit/signing"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

//go:embed schema.sql
var schema string

var tables = eventstream.ProducerTables{StreamHeads: "devcollection_heads", Outbox: "devcollection_outbox"}

func Migrate(ctx context.Context, db eventstream.DB) error {
	if _, err := db.Exec(ctx, schema); err != nil {
		return errors.New("initialize development collection schema failed")
	}
	return nil
}

func Head(ctx context.Context, db eventstream.DB) (int64, []byte, error) {
	var sequence int64
	var digest []byte
	err := db.QueryRow(ctx, "SELECT last_sequence,last_event_digest FROM devcollection_heads WHERE stream=$1", Stream).Scan(&sequence, &digest)
	if err != nil {
		return 0, nil, errors.New("read collection head failed; run migrate first")
	}
	return sequence, digest, nil
}

func NewReader(db eventstream.DB) (*eventstream.Reader, error) {
	return eventstream.NewReader(db, "collection", tables, map[string][]string{Stream: {"ledger", "reconciliation"}})
}

// Append commits the idempotency key, original payload, signature and new head
// together. The servicekit sequencer uses a pgx savepoint inside this transaction.
func Append(ctx context.Context, db eventstream.TxStarter, signer signing.Signer, key string, claim *collectionv1.ReceiptConfirmed, replay bool) (string, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return "", errors.New("begin collection transaction failed")
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err = tx.Exec(ctx, "SELECT last_sequence FROM devcollection_heads WHERE stream=$1 FOR NO KEY UPDATE", Stream); err != nil {
		return "", errors.New("lock collection stream failed")
	}
	var originalID string
	var stored []byte
	err = tx.QueryRow(ctx, "SELECT event_id::text,payload FROM devcollection_outbox WHERE receipt_key=$1", key).Scan(&originalID, &stored)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("read original receipt failed")
	}
	event, err := prepareEvent(claim, stored, replay)
	if err != nil {
		return "", err
	}
	if event == nil {
		return originalID, nil
	}
	var receiptKey any
	if !replay {
		receiptKey = key
	}
	digest := sha256.Sum256(event.payload)
	_, err = tx.Exec(ctx, `INSERT INTO devcollection_outbox(receipt_key,event_id,stream,event_type,schema_version,occurred_at,payload,payload_digest)
		VALUES($1,$2,$3,'ReceiptConfirmed',1,$4,$5,$6)`, receiptKey, event.id, Stream, claim.ConfirmedAt.AsTime(), event.payload, digest[:])
	if err != nil {
		return "", errors.New("append receipt failed")
	}
	sequencer, err := eventstream.NewSequencer(tx, "collection", tables, signer, 1)
	if err != nil {
		return "", err
	}
	if n, err := sequencer.SequenceStream(ctx, Stream); err != nil || n != 1 {
		return "", errors.New("seal receipt failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return "", errors.New("commit collection event failed")
	}
	return event.id.String(), nil
}

type pendingEvent struct {
	id      uuid.UUID
	payload []byte
}

// An identical add has no new event. Replays preserve the originally signed
// payload byte-for-byte, including its receipt ID.
func prepareEvent(claim *collectionv1.ReceiptConfirmed, stored []byte, replay bool) (*pendingEvent, error) {
	receipt := proto.CloneOf(claim)
	if stored == nil {
		if replay {
			return nil, errors.New("add the original receipt before replay")
		}
		id, err := uuid.NewV7()
		if err != nil {
			return nil, errors.New("generate receipt ID failed")
		}
		receipt.ReceiptId = id.String()
	} else {
		var original collectionv1.ReceiptConfirmed
		if proto.Unmarshal(stored, &original) != nil {
			return nil, errors.New("invalid stored receipt")
		}
		receipt.ReceiptId = original.ReceiptId
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil {
		return nil, errors.New("encode receipt failed")
	}
	if stored != nil {
		if !bytes.Equal(stored, payload) {
			return nil, errors.New("receipt key already belongs to different content")
		}
		if !replay {
			return nil, nil
		}
		payload = stored
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, errors.New("generate event ID failed")
	}
	return &pendingEvent{id: id, payload: payload}, nil
}
