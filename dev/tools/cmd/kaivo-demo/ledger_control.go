package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/Kaivodev/servicekit/approval"
	"github.com/google/uuid"
)

const (
	ledgerReadOnlyExit = "ledger-read-only-exit"
	ledgerCarryover    = "ledger-carryover"
	exitPath           = "/ledger/read-only-exit"
	carryoverPath      = "/ledger/carryovers"
	ledgerControlRPC   = "/aipay.ledger.v1.LedgerControlService/"
)

func isLedgerScenario(s string) bool { return s == ledgerReadOnlyExit || s == ledgerCarryover }

func (b *browser) submitLedgerCommand(c portalCommand) object {
	challenged := false
	reply := b.portalAPI("POST", c.path, c.key, c.body, "", func(digest []byte) string {
		require(bytes.Equal(digest, c.digest[:]), "reauthentication digest differs from the local command")
		challenged = true
		b.d.trace("Verified 428 command digest " + hex.EncodeToString(digest))
		return b.grant(c)
	})
	require(challenged, "command succeeded without the required 428 reauthentication challenge")
	b.d.evidence("reauthentication", object{"business_code": 428, "command_sha256": hex.EncodeToString(c.digest[:])})
	return reply
}

func exitCommand(key, note string) portalCommand {
	path := exitPath + "/requests"
	b := appendField(webCommandPrefix(ledgerControlRPC+"RequestReadOnlyExit", key), note)
	return portalCommand{path, path, "ledger.read_only_exit.submit", key, object{"note": note}, sha256.Sum256(b)}
}

func carryoverCommand(key, period, account string, amount int64, reason string) portalCommand {
	path := carryoverPath + "/requests"
	b := appendField(appendField(webCommandPrefix(ledgerControlRPC+"RecordCarryover", key), period), account)
	b = binary.BigEndian.AppendUint64(b, uint64(amount))
	body := object{"period_id": period, "account_code": account, "units": strconv.FormatInt(amount, 10), "reason": reason}
	return portalCommand{path, path, "ledger.carryover.submit", key, body, sha256.Sum256(appendField(b, reason))}
}

func ledgerTime(m object, field string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, str(m, field))
	check(err)
	require(t.Nanosecond()%1000 == 0 && t.Equal(time.Unix(0, t.UnixNano())), "invalid ledger timestamp "+field)
	return t
}

func ledgerUint(m object, field string) uint64 {
	n, ok := m[field].(json.Number)
	require(ok, "missing ledger number "+field)
	u, err := strconv.ParseUint(n.String(), 10, 64)
	check(err)
	return u
}

// The request header supplies the owner-assigned ID and lifetime. Expected fields
// come from the logged-in user, submitted command and independent episode snapshot.
func ledgerChallenge(kind string, request, expected object) []byte {
	require(request["kind"] == kind && request["requested_by"] == str(expected, "requested_by"), "unexpected ledger approval kind or requester")
	require(request["id"] == str(expected, "approval_request_id") && sameInstant(request["requested_at"], expected["requested_at"]) &&
		sameInstant(request["expires_at"], expected["expires_at"]), "ledger approval header mismatch")
	id, err := uuid.Parse(str(expected, "approval_request_id"))
	check(err)
	b := appendField(nil, "aipay.ledger."+kind+".v1")
	b = append(b, id[:]...)
	b = appendField(b, str(expected, "requested_by"))
	start, end := ledgerTime(expected, "requested_at"), ledgerTime(expected, "expires_at")
	require(end.Sub(start) == 24*time.Hour, "unexpected ledger approval lifetime")
	b = binary.BigEndian.AppendUint64(b, uint64(start.UnixNano()))
	b = binary.BigEndian.AppendUint64(b, uint64(end.UnixNano()))
	switch kind {
	case "read_only_exit":
		b = appendField(b, str(expected, "read_only_reason"))
		b = binary.BigEndian.AppendUint64(b, uint64(ledgerTime(expected, "read_only_since").UnixNano()))
		b = appendField(b, str(expected, "note"))
		b = binary.BigEndian.AppendUint64(b, ledgerUint(expected, "head_seq"))
		hash, err := hex.DecodeString(str(expected, "head_hash"))
		check(err)
		require(len(hash) == sha256.Size, "invalid ledger head hash")
		b = appendField(b, string(hash))
		b = binary.BigEndian.AppendUint64(b, ledgerUint(expected, "last_checkpoint_id"))
	case "carryover":
		b = appendField(b, str(expected, "period_id"))
		b = appendField(b, str(expected, "account_code"))
		b = binary.BigEndian.AppendUint64(b, uint64(units(expected, "units")))
		b = appendField(b, str(expected, "reason"))
	default:
		stop("unknown ledger approval kind")
	}
	digest := approval.Digest(b)
	require(bytes.Equal(b, raw(str(request, "request_bytes"))), "ledger approval request bytes differ from expected fields")
	require(str(request, "request_digest") == hex.EncodeToString(digest[:]), "ledger approval digest mismatch")
	return digest[:]
}

type ledgerProposal struct {
	ID     string
	Digest []byte
}

func (d *driver) recordLedgerProposal(actor, kind string, count int64, reply, expected object) ledgerProposal {
	r := obj(reply["approval_request"])
	require(num(r, "required_approvals") == count && r["status"] == "pending", "unexpected ledger approval policy or state")
	expected["requested_by"] = d.required("user/" + actor)
	expected["approval_request_id"] = str(r, "id")
	expected["requested_at"], expected["expires_at"] = r["requested_at"], r["expires_at"]
	require(matchesProposal(obj(reply["material"]), expected), "decoded ledger material differs from expected fields")
	p := ledgerProposal{str(r, "id"), ledgerChallenge(kind, r, expected)}
	d.put(d.scope+"/proposal/"+actor, p)
	d.evidence("verified_material", expected)
	d.evidence("request_digest", r["request_digest"])
	d.evidence("required_approvals", count)
	return p
}

func (d *driver) ledgerProposal(actor string) ledgerProposal {
	var p ledgerProposal
	require(d.read(d.scope+"/proposal/"+actor, &p) && p.ID != "" && len(p.Digest) == sha256.Size, "missing verified ledger proposal")
	return p
}

func (p ledgerProposal) path(base string) string { return base + "/approvals/" + p.ID + "/assertions" }

func (p ledgerProposal) approve(b *browser, base, label string) object {
	return b.write(label+"/"+p.ID+"/"+b.name, p.path(base), func() object {
		return object{"assertion": b.d.assert(b.name, p.Digest)}
	})
}

func (d *driver) checkLedgerApproval(p ledgerProposal, reply object, count int64, status string) {
	r := obj(reply["approval_request"])
	require(r["id"] == p.ID && r["request_digest"] == hex.EncodeToString(p.Digest) && r["status"] == status && num(reply, "approvals") == count, "unexpected ledger approval result")
	d.evidence("approval", object{"id": p.ID, "status": status, "approvals": count})
}

func (d *driver) expectLedgerRefusal(label, path, message string, write func(), codes ...int) {
	f, refused := portalRefusal(path, write, codes...)
	require(refused, "ledger accepted "+label)
	require(message == "" || f.message == message, "unexpected refusal for "+label+": "+f.message)
	d.evidence(label, object{"http_status": f.httpStatus, "business_code": f.businessCode, "message": f.message})
}

func ledgerList(view object, field string) []any {
	list, ok := view[field].([]any)
	require(ok, "missing ledger list "+field)
	return list
}

func listedLedgerRequest(rows []any, p ledgerProposal) object {
	for _, item := range rows {
		row := obj(item)
		r := obj(row["approval_request"])
		if r["id"] == p.ID {
			require(r["request_digest"] == hex.EncodeToString(p.Digest), "listed ledger request digest mismatch")
			return row
		}
	}
	stop("ledger request missing from list")
	return nil
}
