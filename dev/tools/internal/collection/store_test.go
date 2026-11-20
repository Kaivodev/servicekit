package collection

import (
	"bytes"
	"testing"

	collectionv1 "github.com/Kaivodev/protobuf/gen/go/aipay/collection/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestAddAndReplayOriginalReceipt(t *testing.T) {
	claim := &collectionv1.ReceiptConfirmed{ChainTransactionId: "tx", TransferIndex: 1}
	first, err := prepareEvent(claim, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var receipt collectionv1.ReceiptConfirmed
	if err = proto.Unmarshal(first.payload, &receipt); err != nil || uuid.MustParse(receipt.ReceiptId).Version() != 7 || claim.ReceiptId != "" {
		t.Fatal("incorrect receipt identity", err)
	}
	duplicate, err := prepareEvent(claim, first.payload, false)
	if err != nil || duplicate != nil {
		t.Fatal("repeat add must leave the head unchanged", err)
	}
	replay, err := prepareEvent(claim, first.payload, true)
	if err != nil || replay.id == first.id || replay.id.Version() != 7 || !bytes.Equal(replay.payload, first.payload) {
		t.Fatal("invalid replay", err)
	}
	claim.TransferIndex++
	if _, err = prepareEvent(claim, first.payload, true); err == nil {
		t.Fatal("replay accepted modified claim")
	}
	if _, err = prepareEvent(claim, nil, true); err == nil {
		t.Fatal("replay accepted missing receipt")
	}
}
