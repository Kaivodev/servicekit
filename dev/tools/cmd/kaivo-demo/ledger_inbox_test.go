package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ledger "github.com/Kaivodev/protobuf/gen/go/aipay/ledger/v1"
	"github.com/Kaivodev/servicekit/approval"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestLedgerInboxChecksBothMaterialViewsAndRequestBytes(t *testing.T) {
	input := usdtAdjustment("Review platform posting", fundsLoss, "platform_capital:USDT", 1)
	m := input.material()
	expected := adjustmentFields(m)
	expected["approval_request_id"], expected["requested_by"] = ledgerTestID, ledgerTestUser
	expected["requested_at"], expected["expires_at"] = "1970-01-01T00:00:00Z", "1970-01-02T00:00:00Z"
	// Hand-built header followed by the locally generated adjustment payload.
	header, err := hex.DecodeString("01890f3e123470008000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	wire := append(appendField(nil, "aipay.ledger.adjustment.v1"), header...)
	wire = appendField(wire, ledgerTestUser)
	wire = append(wire, make([]byte, 8)...)
	wire = append(wire, 0, 0, 0x4e, 0x94, 0x91, 0x4f, 0, 0)
	wire = appendAdjustmentFields(wire, expected)
	digest := approval.Digest(wire)
	p := ledgerProposal{ID: ledgerTestID, Digest: digest[:], Expected: expected}
	canonical, err := protojson.Marshal(inboxMaterial("adjustment", expected, m))
	if err != nil {
		t.Fatal(err)
	}
	branch := maps.Clone(expected)
	branch["evidence_files"] = evidenceMetadata(m)
	branch["review"] = object{"accounts": []any{
		object{"account_code": fundsLoss, "currency": "USDT", "owner_kind": "platform"},
		object{"account_code": "platform_capital:USDT", "currency": "USDT", "owner_kind": "platform"},
	}}
	request := object{"id": ledgerTestID, "requested_by": ledgerTestUser, "kind": "adjustment", "status": "pending",
		"requested_at": expected["requested_at"], "expires_at": expected["expires_at"], "request_bytes": b64.EncodeToString(wire), "request_digest": b64.EncodeToString(digest[:])}
	view := object{"owner_service": "ledger", "request": request, "canonical_material_json": string(canonical), "ledger": object{"adjustment": branch}}
	checkInboxDetail(view, p, "adjustment", m)
	for name, edit := range map[string]func(object){
		"canonical lines": func(v object) {
			v["canonical_material_json"] = strings.ReplaceAll(string(canonical), "ENTRY_DIRECTION_DEBIT", "ENTRY_DIRECTION_CREDIT")
		},
		"typed reason":    func(v object) { obj(obj(v["ledger"])["adjustment"])["reason"] = "Other posting" },
		"review accounts": func(v object) { obj(obj(v["ledger"])["adjustment"])["review"] = object{"accounts": []any{}} },
		"request bytes": func(v object) {
			obj(v["request"])["request_bytes"] = b64.EncodeToString(append(bytes.Clone(wire), 0))
		},
		"manifest metadata": func(v object) { obj(obj(v["ledger"])["adjustment"])["evidence_files"] = []any{} },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := normalized(view)
			edit(wrong)
			expectFailure(t, func() { checkInboxDetail(wrong, p, "adjustment", m) })
		})
	}
}

func TestLedgerControlInboxMaterial(t *testing.T) {
	const at = "2026-11-27T00:00:00Z"
	for _, tc := range []struct {
		kind              string
		portal, canonical object
	}{
		{"read_only_exit",
			object{"read_only_reason": "dev_drill:inbox", "read_only_since": at, "note": "Reviewed journal", "head_seq": 5, "last_checkpoint_id": 3, "head_hash": strings.Repeat("ab", 32)},
			object{"read_only_reason": "dev_drill:inbox", "read_only_since": at, "note": "Reviewed journal", "head_seq": "5", "last_checkpoint_id": "3", "head_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))}},
		{"carryover",
			object{"period_id": "2026-11", "account_code": "unmatched_receipts:USDT:BSC", "units": "-7", "reason": "Reviewed receipts"},
			object{"period_id": "2026-11", "account_code": "unmatched_receipts:USDT:BSC", "units": "-7", "reason": "Reviewed receipts"}},
		{"usd_rate_policy",
			object{"version": 1, "expected_version": 0, "threshold_ppm": 3000, "ceiling_ppm": 10000, "reason": "Keep threshold"},
			object{"version": "1", "threshold_ppm": 3000, "ceiling_ppm": 10000, "reason": "Keep threshold"}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			header := object{"approval_request_id": ledgerTestID, "requested_by": ledgerTestUser, "requested_at": at, "expires_at": "2026-11-28T00:00:00Z"}
			expected := normalized(tc.portal)
			maps.Copy(expected, header)
			header["kind"], header[tc.kind] = tc.kind, tc.canonical
			var want ledger.LedgerApprovalMaterial
			if err := protojson.Unmarshal(encoded(header), &want); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(&want, inboxMaterial(tc.kind, expected, nil)) {
				t.Fatal("inbox control material differs from the canonical protobuf JSON")
			}
		})
	}
}

func TestLedgerInboxPagination(t *testing.T) {
	const at = "2026-10-17T03:00:00Z"
	for _, tc := range []struct {
		name, secondAsOf, secondID, secondTime string
		repeatCursor                           bool
	}{
		{"stable snapshot", at, "older", "2026-10-16T00:00:00Z", false},
		{"changed snapshot", "2026-10-18T03:00:00Z", "older", "2026-10-16T00:00:00Z", false},
		{"duplicate item", at, "newer", "2026-10-16T00:00:00Z", false},
		{"incorrect order", at, "older", "2026-10-17T01:00:00Z", false},
		{"repeated cursor", at, "older", "2026-10-16T00:00:00Z", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(t.TempDir(), "", ledgerApprovalsInbox)
			b := d.browser("approver1")
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				query := r.URL.Query()
				if calls > 2 || r.Method != "GET" || r.URL.Path != b.prefix+"/approvals" || query.Get("owner_service") != "ledger" || query.Get("kind") != "adjustment" || query.Get("limit") != "1" {
					t.Error("unexpected page request")
					http.Error(w, "invalid", 400)
					return
				}
				id, when, snapshot := "newer", "2026-10-17T00:00:00Z", at
				page := object{}
				if calls == 1 || tc.repeatCursor {
					page["next_cursor"] = "+opaque/cursor="
				}
				if calls == 2 {
					if query.Get("cursor") != "+opaque/cursor=" {
						t.Error("changed continuation cursor")
					}
					id, when, snapshot = tc.secondID, tc.secondTime, tc.secondAsOf
				}
				page["sources"] = object{"ledger": object{"as_of": snapshot}}
				page["items"] = []any{object{"owner_service": "ledger", "request": object{"id": id, "kind": "adjustment", "status": "pending", "requested_at": when}}}
				w.Write(encoded(object{"code": 200, "data": page}))
			}))
			defer server.Close()
			b.addr = strings.TrimPrefix(server.URL, "http://")
			read := func() {
				result := b.ledgerPages(ledgerInboxPath+"&kind=adjustment&limit=1", "adjustment", "pending", 1)
				if result.count != 2 || result.asOf != at || result.requests["older"] != "adjustment" || result.requests["newer"] != "adjustment" {
					t.Fatal("incorrect ledger pages")
				}
			}
			if tc.name == "stable snapshot" {
				read()
			} else {
				expectFailure(t, read)
			}
		})
	}
}
