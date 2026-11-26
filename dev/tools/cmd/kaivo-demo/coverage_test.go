package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/protobuf/testvectors"
)

func TestCoverageDemoAddressAndSubmission(t *testing.T) {
	const address = "TUTBBLUfdt2SPg47qXAVNu8yawzfT47RU4"
	if got := demoCoverageAddress(); got != address || !validCoverageAddress(got) {
		t.Fatal("incorrect deterministic mainnet-format address", got)
	}
	for _, bad := range []string{"", address[1:], address[:33] + "5", "0" + address[1:], "1" + address[1:]} {
		if validCoverageAddress(bad) {
			t.Fatal("accepted invalid address", bad)
		}
	}
	blockTime := time.Date(2026, 11, 21, 9, 12, 3, 123456789, time.FixedZone("test", -8*3600))
	hash := bytes.Repeat([]byte{0xfb}, 32)
	want := object{"unrecorded_inflows": []object{}, "window_outflows": []object{}, "observations": []object{{
		"chain": "TRON", "address": address, "block_time": "2026-11-21T17:12:03.123456Z",
		"raw_balance": "1000000000000", "block_number": "80000000", "source": "development",
		"block_hash": "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s",
		"evidence":   "Synthetic cold-wallet balance for the Kaivo coverage demo.",
	}}}
	if got := coverageSubmission(address, blockTime, hash); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected submission: %s", encoded(got))
	}
	expectFailure(t, func() { coverageSubmission(address, blockTime, hash[:31]) })
	expectFailure(t, func() { coverageSubmission(address[1:], blockTime, hash) })

	body := normalized(want)
	material := normalized(want)
	obs := obj(material["observations"].([]any)[0])
	delete(obs, "evidence")
	obs["evidence_sha256"], obs["role"] = "9OrCfy0TnqHY3jTp96pyEZU4IYKoUBC__KH3qypsTyY", "cold"
	checkCoverageSubmission(body, material)
	obs["raw_balance"] = "999"
	expectFailure(t, func() { checkCoverageSubmission(body, material) })
}

func TestCoverageDenialStates(t *testing.T) {
	for _, state := range []string{"none", "revoked", "expired"} {
		requireCoverageDenied(object{"state": state, "releases_allowed": false}, nil)
	}
	for _, state := range []string{"valid", "low_margin", "not_covered", "invalid"} {
		expectFailure(t, func() { requireCoverageDenied(object{"state": state, "releases_allowed": false}, nil) })
	}
	approved := object{"attestation_id": id(), "request_digest": b64.EncodeToString(random(32))}
	expired := object{"state": "expired", "releases_allowed": false, "attestation_id": approved["attestation_id"], "request_digest": approved["request_digest"]}
	requireCoverageDenied(expired, approved)
	expired["request_digest"] = b64.EncodeToString(random(32))
	expectFailure(t, func() { requireCoverageDenied(expired, approved) })
}

func TestCoverageChallenges(t *testing.T) {
	var vectors struct {
		Approvals   []object `json:"approval_vectors"`
		Revocations []object `json:"revocation_vectors"`
	}
	decode(testvectors.ReconciliationCoverageV1(), &vectors)
	if len(vectors.Approvals) == 0 || len(vectors.Revocations) == 0 {
		t.Fatal("missing published coverage vectors")
	}
	fromHex := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range vectors.Revocations {
		t.Run(str(v, "name"), func(t *testing.T) {
			got := coverageRevocationChallenge(str(v, "user_id"), str(v, "idempotency_key"), str(v, "attestation_id"),
				fromHex(str(v, "request_digest")), str(v, "reason"))
			if !bytes.Equal(got[:], fromHex(str(v, "challenge"))) {
				t.Fatal("revocation challenge differs from the published vector")
			}
		})
	}
	for _, v := range vectors.Approvals {
		t.Run(str(v, "name"), func(t *testing.T) {
			// Project the protobuf JSON vectors to the portal's base64url and enum spellings.
			m := obj(v["material"])
			proof := obj(m["coverage_attestation"])
			projectBytes := func(row object, keys ...string) {
				for _, k := range keys {
					row[k] = b64.EncodeToString(standard(str(row, k)))
				}
			}
			projectBytes(proof, "address_registry_version")
			projectBytes(obj(proof["ledger"]), "head_hash", "balances_digest")
			proof["result"] = strings.ToLower(strings.TrimPrefix(str(proof, "result"), "COVERAGE_RESULT_"))
			for _, obs := range proof["observations"].([]any) {
				row := obj(obs)
				row["role"] = strings.ToLower(strings.TrimPrefix(str(row, "role"), "COVERAGE_ADDRESS_ROLE_"))
				projectBytes(row, "block_hash", "evidence_sha256")
			}
			digest := fromHex(str(v, "request_digest"))
			header := object{"required_approvals": json.Number("2"), "id": m["approval_request_id"], "kind": m["kind"],
				"requested_by": m["requested_by"], "requested_at": m["requested_at"], "expires_at": m["expires_at"],
				"request_digest": b64.EncodeToString(digest), "request_bytes": b64.EncodeToString(fromHex(str(v, "request_bytes")))}
			res := object{"approval_request": header, "material": m}
			if !bytes.Equal(challenge("reconciliation", str(m, "requested_by"), res), digest) {
				t.Fatal("approval digest differs from the published vector")
			}
			proof["margin_units"] = "123456789"
			expectFailure(t, func() { challenge("reconciliation", str(m, "requested_by"), res) })
		})
	}
}
