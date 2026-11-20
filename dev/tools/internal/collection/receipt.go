package collection

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	collectionv1 "github.com/Kaivodev/protobuf/gen/go/aipay/collection/v1"
	commonv1 "github.com/Kaivodev/protobuf/gen/go/aipay/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const Stream = "collection.deposits"
const usdt = "0x55d398326f99059fF775485246999027B3197955"

type transfer struct {
	Transaction string    `json:"chain_transaction_id"`
	Index       uint32    `json:"transfer_index"`
	Raw         string    `json:"raw_amount"`
	Units       int64     `json:"units"`
	Height      uint64    `json:"block_number"`
	Hash        string    `json:"block_hash"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

type scenario struct {
	ChainID   int                 `json:"chain_id"`
	AccountID string              `json:"account_id"`
	AddressID string              `json:"address_id"`
	Address   string              `json:"deposit_address"`
	Wallet    string              `json:"wallet_account_code"`
	Receipts  map[string]transfer `json:"receipts"`
}

func hexBytes(s string, size int) ([]byte, error) {
	if len(s) != 2+size*2 || !strings.HasPrefix(s, "0x") {
		return nil, errors.New("invalid hex field")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil || len(bytes.Trim(b, "\x00")) == 0 {
		return nil, errors.New("invalid zero or non-hex field")
	}
	return b, nil
}

func validUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.Version() == 7 && id.Variant() == uuid.RFC4122 && id.String() == value
}

// ReadReceipt materializes only the collector's claim. An ID is assigned by
// the store on first add. Replay uses the original stored protobuf bytes.
func ReadReceipt(path, key string) (*collectionv1.ReceiptConfirmed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read receipt scenario failed")
	}
	var s scenario
	if json.Unmarshal(data, &s) != nil || s.ChainID != 31337 || !validUUID(s.AccountID) || !validUUID(s.AddressID) || s.Wallet != "collection_wallet:USDT:BSC:"+s.AddressID {
		return nil, errors.New("invalid development receipt scenario")
	}
	t, ok := s.Receipts[key]
	if !ok || key == "" {
		return nil, errors.New("unknown receipt key")
	}
	hash, err := hexBytes(t.Hash, 32)
	_, txErr := hexBytes(t.Transaction, 32)
	_, addrErr := hexBytes(s.Address, 20)
	if err != nil || txErr != nil || addrErr != nil || t.Height == 0 || t.Height > math.MaxInt64 || t.ConfirmedAt.IsZero() {
		return nil, errors.New("invalid receipt location")
	}
	raw, ok := new(big.Int).SetString(t.Raw, 10)
	if !ok || raw.Sign() <= 0 || raw.BitLen() > 256 || raw.String() != t.Raw {
		return nil, errors.New("invalid raw amount")
	}
	units := new(big.Int).Quo(raw, big.NewInt(1_000_000_000_000))
	if !units.IsInt64() || units.Sign() == 0 || units.Int64() != t.Units {
		return nil, errors.New("invalid receipt units")
	}
	return &collectionv1.ReceiptConfirmed{
		AccountId:          s.AccountID,
		AddressId:          s.AddressID,
		ChainTransactionId: strings.ToLower(t.Transaction),
		TransferIndex:      t.Index,
		Asset: &commonv1.ChainAssetAmount{
			Chain:           commonv1.Chain_CHAIN_BSC,
			ContractAddress: usdt,
			RawAmount:       t.Raw,
			Amount:          &commonv1.Money{Currency: "USDT", Units: t.Units},
		},
		DepositAddress:    strings.ToLower(s.Address),
		WalletAccountCode: s.Wallet,
		BlockNumber:       t.Height,
		BlockHash:         hash,
		ConfirmedAt:       timestamppb.New(t.ConfirmedAt.UTC().Truncate(time.Microsecond)),
	}, nil
}
