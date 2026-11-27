package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	ledger "github.com/Kaivodev/protobuf/gen/go/aipay/ledger/v1"
)

const (
	adjustmentPath = "/ledger/adjustments"
	ratePolicyPath = "/ledger/usd-rate-policy"
	fundsLoss      = "funds_loss:USDT"
	debit          = ledger.EntryDirection_ENTRY_DIRECTION_DEBIT
	credit         = ledger.EntryDirection_ENTRY_DIRECTION_CREDIT
)

type adjustmentInput struct {
	reason   string
	corrects uint64
	lines    []*ledger.AdjustmentLine
	files    []*ledger.AdjustmentEvidenceUpload
}

func adjustmentEvidence() []*ledger.AdjustmentEvidenceUpload {
	return []*ledger.AdjustmentEvidenceUpload{
		{FileName: "receipt.pdf", ContentType: "application/pdf", Data: []byte("%PDF-1.4\n%%EOF\n")},
		{FileName: "receipt.png", ContentType: "image/png", Data: []byte("\x89PNG\r\n\x1a\n")},
	}
}

func usdtAdjustment(reason, debitAccount, creditAccount string, amount int64) adjustmentInput {
	return adjustmentInput{
		reason: reason,
		lines: []*ledger.AdjustmentLine{
			{AccountCode: debitAccount, Direction: debit, Currency: "USDT", Units: amount},
			{AccountCode: creditAccount, Direction: credit, Currency: "USDT", Units: amount},
		},
		files: adjustmentEvidence()[:1],
	}
}

func (a adjustmentInput) material() *ledger.AdjustmentMaterial {
	m := &ledger.AdjustmentMaterial{Reason: a.reason, CorrectsSeq: a.corrects, Lines: a.lines}
	wire := appendField(nil, "aipay.ledger.adjustment_evidence.v1")
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(a.files)))
	for i, f := range a.files {
		hash := sha256.Sum256(f.Data)
		size := uint32(len(f.Data))
		wire = appendField(wire, f.FileName)
		wire = appendField(wire, f.ContentType)
		wire = binary.BigEndian.AppendUint32(wire, size)
		wire = appendField(wire, string(hash[:]))
		m.EvidenceFiles = append(m.EvidenceFiles, &ledger.AdjustmentEvidenceFile{
			FileNo: uint32(i + 1), FileName: f.FileName, ContentType: f.ContentType, SizeBytes: size, Sha256: hash[:],
		})
	}
	digest := sha256.Sum256(wire)
	m.EvidenceSha256 = digest[:]
	return m
}

func adjustmentFields(m *ledger.AdjustmentMaterial) object {
	lines := make([]any, 0, len(m.Lines))
	for _, l := range m.Lines {
		require(l.Direction == debit || l.Direction == credit, "invalid adjustment direction")
		direction := "debit"
		if l.Direction == credit {
			direction = "credit"
		}
		lines = append(lines, object{"account_code": l.AccountCode, "direction": direction, "currency": l.Currency, "units": strconv.FormatInt(l.Units, 10)})
	}
	return object{"reason": m.Reason, "corrects_seq": strconv.FormatUint(m.CorrectsSeq, 10), "lines": lines, "evidence_sha256": hex.EncodeToString(m.EvidenceSha256)}
}

func evidenceMetadata(m *ledger.AdjustmentMaterial) []any {
	files := make([]any, 0, len(m.EvidenceFiles))
	for _, f := range m.EvidenceFiles {
		files = append(files, normalized(object{"file_no": f.FileNo, "file_name": f.FileName, "content_type": f.ContentType,
			"size_bytes": f.SizeBytes, "sha256": hex.EncodeToString(f.Sha256)}))
	}
	return files
}

func (a adjustmentInput) command(key string) portalCommand {
	m := a.material()
	b := webCommandPrefix(ledger.AdjustmentService_SubmitAdjustment_FullMethodName, key)
	b = appendField(b, a.reason)
	b = appendField(b, string(m.EvidenceSha256))
	b = binary.BigEndian.AppendUint64(b, a.corrects)
	b = binary.BigEndian.AppendUint32(b, uint32(len(a.lines)))
	for _, l := range a.lines {
		b = appendField(b, l.AccountCode)
		b = binary.BigEndian.AppendUint32(b, uint32(l.Direction))
		b = appendField(b, l.Currency)
		b = binary.BigEndian.AppendUint64(b, uint64(l.Units))
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(a.files)))
	for _, f := range a.files {
		b = appendField(b, f.FileName)
		b = appendField(b, f.ContentType)
		b = appendField(b, string(f.Data))
	}
	body := adjustmentFields(m)
	delete(body, "evidence_sha256")
	body["evidence_files"] = a.files // encoding/json sends bytes as padded standard base64.
	path := adjustmentPath + "/requests"
	return portalCommand{path, path, "ledger.adjustment.submit", key, body, sha256.Sum256(b)}
}

func ratePolicyCommand(key string, version uint64, threshold uint32, reason string) portalCommand {
	b := webCommandPrefix(ledger.LedgerControlService_RequestUsdRatePolicy_FullMethodName, key)
	b = binary.BigEndian.AppendUint64(b, version)
	b = binary.BigEndian.AppendUint32(b, threshold)
	body := normalized(object{"expected_version": version, "threshold_ppm": threshold, "reason": reason})
	path := ratePolicyPath + "/requests"
	return portalCommand{path, path, "ledger.rate_policy.submit", key, body, sha256.Sum256(appendField(b, reason))}
}

func appendAdjustmentFields(b []byte, m object) []byte {
	b = appendField(b, str(m, "reason"))
	hash, err := hex.DecodeString(str(m, "evidence_sha256"))
	check(err)
	require(len(hash) == sha256.Size, "invalid adjustment evidence digest")
	b = appendField(b, string(hash))
	seq, err := strconv.ParseUint(str(m, "corrects_seq"), 10, 64)
	check(err)
	b = binary.BigEndian.AppendUint64(b, seq)
	lines := ledgerList(m, "lines")
	b = binary.BigEndian.AppendUint32(b, uint32(len(lines)))
	for _, item := range lines {
		line := obj(item)
		b = appendField(b, str(line, "account_code"))
		switch line["direction"] {
		case "debit":
			b = append(b, 'D')
		case "credit":
			b = append(b, 'C')
		default:
			stop("invalid adjustment direction")
		}
		b = appendField(b, str(line, "currency"))
		b = binary.BigEndian.AppendUint64(b, uint64(units(line, "units")))
	}
	return b
}
