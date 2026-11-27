package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"maps"
	"reflect"
	"testing"
	"time"

	ledger "github.com/Kaivodev/protobuf/gen/go/aipay/ledger/v1"
	"github.com/Kaivodev/protobuf/testvectors"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestLedgerAdjustmentVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name     string
			Material json.RawMessage
			Files    []*ledger.AdjustmentEvidenceUpload `json:"evidence_files"`
			Wire     string                             `json:"request_bytes"`
			Digest   string                             `json:"request_digest"`
		} `json:"approval_vectors"`
	}
	decode(testvectors.LedgerAdjustmentV1(), &fixture)
	if len(fixture.Vectors) != 2 {
		t.Fatal("expected both published adjustment vectors")
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			var header ledger.LedgerApprovalMaterial
			if err := protojson.Unmarshal(vector.Material, &header); err != nil {
				t.Fatal(err)
			}
			want := header.GetAdjustment()
			input := adjustmentInput{want.Reason, want.CorrectsSeq, want.Lines, vector.Files}
			m := input.material()
			if !proto.Equal(m, want) {
				t.Fatal("computed manifest or per-file metadata differs from vector")
			}
			expected := adjustmentFields(m)
			expected["requested_by"], expected["approval_request_id"] = header.RequestedBy, header.ApprovalRequestId
			expected["requested_at"] = header.RequestedAt.AsTime().Format(time.RFC3339Nano)
			expected["expires_at"] = header.ExpiresAt.AsTime().Format(time.RFC3339Nano)
			wire, err := hex.DecodeString(vector.Wire)
			if err != nil {
				t.Fatal(err)
			}
			request := object{"kind": header.Kind, "id": header.ApprovalRequestId, "requested_by": header.RequestedBy,
				"requested_at": expected["requested_at"], "expires_at": expected["expires_at"], "request_bytes": b64.EncodeToString(wire), "request_digest": vector.Digest}
			if got := hex.EncodeToString(ledgerChallenge(header.Kind, request, expected)); got != vector.Digest {
				t.Fatal("adjustment challenge differs from vector")
			}
			if !proto.Equal(inboxMaterial(header.Kind, expected, m), &header) {
				t.Fatal("inbox material differs from published protobuf JSON")
			}
			input.files[0].Data = append(bytes.Clone(input.files[0].Data), '!')
			tampered := maps.Clone(expected)
			tampered["evidence_sha256"] = hex.EncodeToString(input.material().EvidenceSha256)
			expectFailure(t, func() { ledgerChallenge(header.Kind, request, tampered) })
		})
	}
}

func TestAdjustmentAndPolicyWebCommandDigests(t *testing.T) {
	var wire bytes.Buffer
	number := func(value any) {
		t.Helper()
		if err := binary.Write(&wire, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	field := func(s string) {
		number(uint32(len(s)))
		wire.WriteString(s)
	}
	prefix := func(method string) {
		wire.Reset()
		field("aipay.web.command.v1")
		field(method)
		field(ledgerTestID)
	}
	const pdf = "%PDF-1.4\n%%EOF\n"
	const png = "\x89PNG\r\n\x1a\n"
	input := usdtAdjustment("Correct posting", fundsLoss, "platform_capital:USDT", 1<<33)
	input.corrects = 1 << 34
	input.files = adjustmentEvidence()
	// Construct the manifest from the original bytes, independently of the driver.
	field("aipay.ledger.adjustment_evidence.v1")
	number(uint32(2))
	file := func(name, media, data string) {
		field(name)
		field(media)
		number(uint32(len(data)))
		hash := sha256.Sum256([]byte(data))
		field(string(hash[:]))
	}
	file("receipt.pdf", "application/pdf", pdf)
	file("receipt.png", "image/png", png)
	manifest := sha256.Sum256(wire.Bytes())

	prefix("/aipay.ledger.v1.AdjustmentService/SubmitAdjustment")
	field("Correct posting")
	field(string(manifest[:]))
	number(uint64(1 << 34))
	number(uint32(2))
	field("funds_loss:USDT")
	number(uint32(1))
	field("USDT")
	number(int64(1 << 33))
	field("platform_capital:USDT")
	number(uint32(2))
	field("USDT")
	number(int64(1 << 33))
	number(uint32(2))
	field("receipt.pdf")
	field("application/pdf")
	field(pdf)
	field("receipt.png")
	field("image/png")
	field(png)
	c := input.command(ledgerTestID)
	if c.digest != sha256.Sum256(wire.Bytes()) || c.path != "/ledger/adjustments/requests" || c.template != c.path || c.permission != "ledger.adjustment.submit" {
		t.Fatal("adjustment web command binding differs from the hand-built command")
	}
	body := normalized(c.body)
	files := ledgerList(body, "evidence_files")
	if len(files) != 2 || obj(files[0])["data"] != base64.StdEncoding.EncodeToString([]byte(pdf)) ||
		obj(files[1])["data"] != base64.StdEncoding.EncodeToString([]byte(png)) || body["corrects_seq"] != "17179869184" ||
		obj(ledgerList(body, "lines")[1])["units"] != "8589934592" || body["evidence_sha256"] != nil {
		t.Fatal("incorrect adjustment upload encoding")
	}
	prefix("/aipay.ledger.v1.LedgerControlService/RequestUsdRatePolicy")
	number(uint64(1 << 34))
	number(uint32(50_000))
	field("Keep threshold")
	c = ratePolicyCommand(ledgerTestID, 1<<34, 50_000, "Keep threshold")
	if c.digest != sha256.Sum256(wire.Bytes()) || c.path != "/ledger/usd-rate-policy/requests" || c.template != c.path || c.permission != "ledger.rate_policy.submit" ||
		!reflect.DeepEqual(c.body, object{"expected_version": json.Number("17179869184"), "threshold_ppm": json.Number("50000"), "reason": "Keep threshold"}) {
		t.Fatal("policy web command binding differs from the hand-built command")
	}
}
