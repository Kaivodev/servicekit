package main

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/Kaivodev/servicekit/approval"
)

const tronAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func tronChecksum(payload []byte) []byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return second[:4]
}

// Construct a TRON mainnet-format fixture from a label, without a wallet or private key.
func demoCoverageAddress() string {
	seed := sha256.Sum256([]byte("kaivo-demo/coverage/cold/v1"))
	payload := append([]byte{0x41}, seed[:20]...)
	n := new(big.Int).SetBytes(append(payload, tronChecksum(payload)...))
	base, rem := big.NewInt(58), new(big.Int)
	var digits []byte
	for n.Sign() != 0 {
		n.QuoRem(n, base, rem)
		digits = append(digits, tronAlphabet[rem.Int64()])
	}
	slices.Reverse(digits)
	return string(digits)
}

func validCoverageAddress(address string) bool {
	if len(address) != 34 {
		return false
	}
	n, base := new(big.Int), big.NewInt(58)
	for i := range len(address) {
		digit := strings.IndexByte(tronAlphabet, address[i])
		if digit < 0 {
			return false
		}
		n.Mul(n, base).Add(n, big.NewInt(int64(digit)))
	}
	b := n.Bytes()
	return len(b) == 25 && b[0] == 0x41 && bytes.Equal(b[21:], tronChecksum(b[:21]))
}

func coverageSubmission(address string, blockTime time.Time, blockHash []byte) object {
	require(validCoverageAddress(address) && len(blockHash) == sha256.Size, "invalid demo TRON address or block hash")
	return object{
		"observations": []object{{
			"chain": "TRON", "address": address, "raw_balance": "1000000000000", "block_number": "80000000",
			"block_hash": b64.EncodeToString(blockHash), "block_time": blockTime.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
			"source": "development", "evidence": "Synthetic cold-wallet balance for the Kaivo coverage demo.",
		}},
		"unrecorded_inflows": []object{}, "window_outflows": []object{},
	}
}

func coverageRevocationChallenge(user, key, attestationID string, digest []byte, reason string) [32]byte {
	require(len(digest) == sha256.Size, "invalid coverage revocation request digest")
	var b []byte
	for _, field := range []string{"aipay.reconciliation.coverage.revoke.v1", user, key, attestationID, string(digest), reason} {
		b = appendField(b, field)
	}
	return approval.Digest(b)
}
