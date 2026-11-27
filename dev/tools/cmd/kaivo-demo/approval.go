package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	rec "github.com/Kaivodev/protobuf/gen/go/aipay/reconciliation/v1"
	"github.com/Kaivodev/servicekit/approval"
	pr "google.golang.org/protobuf/reflect/protoreflect"
)

// Walk the published field numbers. Portal projection represents bytes as raw base64url,
// amounts as decimal strings and enum values without their protobuf prefix.
func materialBytes(b []byte, desc pr.MessageDescriptor, m object) []byte {
	fields := desc.Fields()
	if m["credentials_sha256"] != nil {
		require(fields.ByName("credentials_sha256") != nil, "credentials_sha256 requires protobuf v0.18.0; rebuild with --workspace")
	}
	byNumber := make([]pr.FieldDescriptor, fields.Len())
	for i := range byNumber {
		byNumber[i] = fields.Get(i)
	}
	sort.Slice(byNumber, func(i, j int) bool { return byNumber[i].Number() < byNumber[j].Number() })
	for _, f := range byNumber {
		k := string(f.Name())
		v := m[k]
		if desc.FullName() == "aipay.common.v1.Money" && k == "units" {
			v = m["amount_minor"]
		}
		if desc.FullName() == "aipay.common.v1.TradeQuoteSnapshot" {
			if k == "fiat_currency" {
				v = obj(m["fiat_amount"])["currency"]
			}
			if money, ok := v.(map[string]any); ok && f.Kind() == pr.Int64Kind {
				v = money["amount_minor"]
			}
		}
		if k == "min_amount_fiat" || k == "max_amount_fiat" || k == "daily_limit_fiat" {
			v = m[k+"_minor"]
		}
		if one := f.ContainingOneof(); one != nil && !one.IsSynthetic() {
			if v == nil {
				continue
			}
			b = binary.BigEndian.AppendUint32(b, uint32(f.Number()))
		} else if f.HasOptionalKeyword() {
			if v == nil && (k == "expected_plugin_control_version" || k == "credentials_sha256" ||
				f.FullName() == "aipay.payment.v1.ChannelAccountConfiguration.payment_instruction_ttl_seconds") {
				continue
			}
			if v == nil {
				// These owner encodings include an explicit absent-presence byte.
				require(desc.ParentFile().Package() == "aipay.reconciliation.v1" ||
					desc.Name() == "SellerRefundReviewMaterial" || desc.Name() == "SellerRefundFailureMaterial", "missing approval field "+k)
				b = append(b, 0)
				continue
			}
			b = append(b, 1)
		}
		if f.IsList() {
			list, _ := v.([]any)
			if k == "callback_source_cidrs" && len(list) == 0 {
				continue
			}
			b = binary.BigEndian.AppendUint32(b, uint32(len(list)))
			for _, item := range list {
				b = materialValue(b, f, item)
			}
		} else {
			b = materialValue(b, f, v)
		}
	}
	return b
}
func materialValue(b []byte, f pr.FieldDescriptor, v any) []byte {
	switch f.Kind() {
	case pr.MessageKind:
		if f.Message().FullName() == "google.protobuf.Timestamp" {
			t, e := time.Parse(time.RFC3339Nano, fmt.Sprint(v))
			check(e)
			require(t.Nanosecond()%1000 == 0, "approval time precision")
			return binary.BigEndian.AppendUint64(b, uint64(t.UnixNano()))
		}
		return materialBytes(b, f.Message(), obj(v))
	case pr.StringKind:
		s, _ := v.(string)
		return appendField(b, s)
	case pr.BytesKind:
		s, _ := v.(string)
		return appendField(b, string(raw(s)))
	case pr.BoolKind:
		if v == true {
			return append(b, 1)
		}
		return append(b, 0)
	case pr.EnumKind:
		values := f.Enum().Values()
		for i := 1; i < values.Len(); i++ {
			q := values.Get(i)
			if strings.HasSuffix(string(q.Name()), "_"+strings.ToUpper(fmt.Sprint(v))) {
				return binary.BigEndian.AppendUint32(b, uint32(q.Number()))
			}
		}
		stop("invalid approval enum %s", f.Name())
	case pr.Int64Kind, pr.Int32Kind:
		n, e := strconv.ParseInt(fmt.Sprint(v), 10, 64)
		check(e)
		if f.Kind() == pr.Int32Kind {
			return binary.BigEndian.AppendUint32(b, uint32(n))
		}
		return binary.BigEndian.AppendUint64(b, uint64(n))
	case pr.Uint32Kind, pr.Uint64Kind:
		n, e := strconv.ParseUint(fmt.Sprint(v), 10, 64)
		check(e)
		if f.Kind() == pr.Uint32Kind {
			return binary.BigEndian.AppendUint32(b, uint32(n))
		}
		return binary.BigEndian.AppendUint64(b, n)
	}
	stop("unsupported approval field %s", f.Name())
	return nil
}
func challenge(owner, requesterID string, res object) []byte {
	r, m := obj(res["approval_request"]), obj(res["material"])
	require(str(r, "requested_by") == requesterID, "unexpected proposer")
	require(num(r, "required_approvals") == 2 && str(r, "id") == str(m, "approval_request_id") && str(m, "requested_by") == str(r, "requested_by") && str(r, "kind") == str(m, "kind") && m[str(m, "kind")] != nil, "approval header mismatch")
	require(r["requested_at"] == m["requested_at"] && r["expires_at"] == m["expires_at"], "approval timestamp mismatch")
	desc := (&pay.PaymentApprovalMaterial{}).ProtoReflect().Descriptor()
	if owner == "reconciliation" {
		desc = (&rec.ReconciliationApprovalMaterial{}).ProtoReflect().Descriptor()
	} else {
		require(owner == "payment", "unknown owner")
	}
	b := materialBytes(appendField(nil, "aipay."+owner+".admin.v1"), desc, m)
	dig := approval.Digest(b)
	require(bytes.Equal(b, raw(str(r, "request_bytes"))) && bytes.Equal(dig[:], raw(str(r, "request_digest"))), "canonical approval bytes/digest mismatch")
	return dig[:]
}
func matchesProposal(material, sent object) bool {
	for k, value := range sent {
		if sub, ok := value.(map[string]any); ok {
			m, ok := material[k].(map[string]any)
			if !ok || !matchesProposal(m, sub) {
				return false
			}
		} else if !reflect.DeepEqual(material[k], value) && !sameInstant(material[k], value) {
			return false
		}
	}
	return true
}

// Owners echo timestamps at microsecond precision ("...:22.000000Z") even when
// the request used whole seconds ("...:22Z"). Compare such values as instants.
func sameInstant(a, b any) bool {
	x, ok1 := a.(string)
	y, ok2 := b.(string)
	if !ok1 || !ok2 {
		return false
	}
	t1, e1 := time.Parse(time.RFC3339Nano, x)
	t2, e2 := time.Parse(time.RFC3339Nano, y)
	return e1 == nil && e2 == nil && t1.Equal(t2)
}
func (proposer *browser) approve(label, owner, path, assertPath string, body object) object {
	d := proposer.d
	// Existing unqualified checkpoints belong to operations. A different
	// submitter needs its own idempotency key, body and assertion checkpoints.
	if proposer.name != "operations" {
		label = proposer.name + "/" + label
	}
	d.login(proposer.name)
	requesterID := d.required("user/" + proposer.name)
	r := proposer.write(label, path, func() object { return body })
	d.evidence("requested_by", requesterID)
	d.evidence("proposer", proposer.name)
	material := obj(r["material"])
	operation := obj(material[str(material, "kind")])
	var sent object
	if d.privateChannelApproval(path) {
		sent = normalized(body)
	} else {
		d.read("write/"+d.scope+"/"+label+"/body", &sent)
	}
	if sent != nil {
		switch {
		case sent["change"] != nil:
			require(matchesProposal(operation, obj(sent["change"])), "owner proposal differs from submitted change")
		case sent["draft_id"] != nil:
			draft := obj(operation["draft"])
			require(draft["draft_id"] == sent["draft_id"] && draft["revision"] == sent["expected_revision"] && operation["expected_control_version"] == sent["expected_control_version"], "owner proposal differs from pricing draft")
		default:
			require(matchesProposal(operation, sent), "owner proposal differs from submitted request")
		}
	}
	if pkg, ok := body["package_sha256"]; ok {
		require(obj(obj(r["material"])["plugin_version"])["package_sha256"] == pkg, "published digest differs from local package")
	}
	return d.approveExisting(label, owner, requesterID, assertPath, r)
}

// The owner may already have accepted a signature before a previous run stopped.
func (d *driver) approveExisting(label, owner, requesterID, assertPath string, r object) object {
	digest := challenge(owner, requesterID, r)
	aid := str(obj(r["approval_request"]), "id")
	credentials := map[string]string{}
	// Existing manual reviews may include a registered reviewer from a different
	// session. Reconciliation independently verifies both signatures at issuance.
	if obj(r["material"])["kind"] == "seller_refund" {
		for _, item := range approvalRecords(r) {
			record := obj(item)
			credentials[str(record, "approver_id")] = str(obj(record["assertion"]), "credential_id")
		}
	}
	for _, person := range approvers {
		credentials[d.key("person/"+person)] = b64.EncodeToString(d.credential(person).ID)
	}
	for _, person := range approvers {
		if len(approvalRecords(r)) == 2 || signedBy(r, d.key("person/"+person)) {
			continue
		}
		d.login(person)
		r = d.browser(person).write(label+"/"+person, assertPath+"/approvals/"+aid+"/assertions", func() object { return object{"assertion": d.assert(person, digest)} })
		require(bytes.Equal(challenge(owner, requesterID, r), digest), "approval changed between people")
	}
	records, ok := r["approvals"].([]any)
	require(ok && len(records) == 2, "expected two approval records")
	verified := map[string]bool{}
	for _, v := range records {
		record := obj(v)
		person := str(record, "approver_id")
		if credential, ok := credentials[person]; ok && obj(record["assertion"])["credential_id"] == credential && record["request_id"] == aid {
			verified[person] = true
		}
	}
	require(len(verified) == 2, "owner approval identities do not match registered people")
	status := str(obj(r["approval_request"]), "status")
	require(status == "approved" || status == "executed", "owner did not execute two approvals")
	if obj(r["material"])["kind"] == "forced_close" {
		require(status == "approved", "payment did not approve the forced close")
		d.evidence("approval_status", status)
		d.evidence("approvers", []string{d.key("person/" + approvers[0]), d.key("person/" + approvers[1])})
	}
	d.evidence("approval_id", aid)
	d.evidence("request_digest", b64.EncodeToString(digest))
	return obj(r["material"])
}

// Check fresh HTTP responses before a write result can be checkpointed.
func checkRenderedApprovals(r object) {
	for _, item := range approvalRecords(r) {
		a := obj(obj(item)["assertion"])
		str(a, "credential_id")
		require(len(a) == 1, "rendered approval assertion must contain only credential_id")
	}
}

func approvalRecords(r object) []any {
	records, _ := r["approvals"].([]any)
	return records
}

func signedBy(r object, person string) bool {
	for _, v := range approvalRecords(r) {
		if obj(v)["approver_id"] == person {
			return true
		}
	}
	return false
}
