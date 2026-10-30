// Package approval verifies FIDO2 approvals (hardware security keys or synced
// passkeys) of funds-affecting requests.
// The executing service computes request_digest over its canonical request
// bytes; an approver signs it through WebAuthn with challenge = request_digest.
// Validity depends only on the executor's own approver key registry.
package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	approvalv1 "github.com/aipay-dev/protobuf/gen/go/aipay/approval/v1"
)

// DomainTag precedes the canonical request bytes, without a length prefix.
const DomainTag = "AIPAY-APPROVAL-V1"

// Digest returns request_digest = SHA-256("AIPAY-APPROVAL-V1" || request).
func Digest(canonicalRequest []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainTag))
	h.Write(canonicalRequest)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// Key is one entry of the approver key registry, written only by a key
// ceremony.
type Key struct {
	ID           string
	ApproverID   string
	IAMUserID    string
	CredentialID []byte
	// PublicKey is a COSE_Key: EC2, P-256, ES256.
	PublicKey []byte
	RPID      string
	Revoked   bool
	// SignCount is the largest counter recorded for this key so far.
	SignCount uint32
}

// Request is the pending approval request as stored by the executor.
type Request struct {
	Digest      [32]byte
	RequestedBy string
	ExpiresAt   time.Time
	// Approvers lists approver IDs that already approved this request.
	Approvers []string
}

// Result carries the counter to record with the approval; store it as the
// key's new largest counter in the same transaction (0 for synced passkeys).
type Result struct{ SignCount uint32 }

// Rejection names the failed check with a stable reason for logs and alerts.
type Rejection struct{ Reason string }

func (r *Rejection) Error() string { return "approval rejected: " + r.Reason }

func reject(reason string) (Result, error) { return Result{}, &Rejection{Reason: reason} }

type Verifier struct {
	rpID    string
	rpHash  [32]byte
	origins map[string]bool
	now     func() time.Time
}

// NewVerifier accepts assertions for rpID from the exact HTTPS origins listed.
func NewVerifier(rpID string, origins []string, now func() time.Time) (*Verifier, error) {
	if rpID == "" || len(origins) == 0 {
		return nil, errors.New("approval verifier requires an RP ID and allowed origins")
	}
	allowed := map[string]bool{}
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, errors.New("approval origins must be https://host[:port]")
		}
		allowed[origin] = true
	}
	if now == nil {
		now = time.Now
	}
	return &Verifier{rpID: rpID, rpHash: sha256.Sum256([]byte(rpID)), origins: allowed, now: now}, nil
}

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
	flagExtensions   = 0x80
)

// Verify checks one approver's assertion for request. The caller still
// enforces the number of approvals and records the approval and counter.
// assertion is the browser's AuthenticatorAssertionResponse, passed through
// unchanged as aipay.approval.v1.WebAuthnAssertion.
func (v *Verifier) Verify(request Request, key Key, assertion *approvalv1.WebAuthnAssertion) (Result, error) {
	switch {
	case !v.now().Before(request.ExpiresAt):
		return reject("request_expired")
	case key.Revoked:
		return reject("key_revoked")
	case key.RPID != v.rpID:
		return reject("key_rp_id")
	case !bytes.Equal(key.CredentialID, assertion.GetCredentialId()) || len(assertion.GetCredentialId()) == 0:
		return reject("credential_mismatch")
	case key.IAMUserID == "" || key.IAMUserID == request.RequestedBy:
		return reject("self_approval")
	case key.ApproverID == "" || slices.Contains(request.Approvers, key.ApproverID):
		return reject("duplicate_approver")
	}
	var client struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(assertion.GetClientDataJson(), &client); err != nil {
		return reject("client_data_malformed")
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(client.Challenge)
	switch {
	case client.Type != "webauthn.get":
		return reject("client_data_type")
	case err != nil || !bytes.Equal(challenge, request.Digest[:]):
		return reject("challenge_mismatch")
	case !v.origins[client.Origin] || client.CrossOrigin:
		return reject("origin_mismatch")
	}
	data := assertion.GetAuthenticatorData()
	if len(data) < 37 {
		return reject("authenticator_data_malformed")
	}
	flags := data[32]
	switch {
	case !bytes.Equal(data[:32], v.rpHash[:]):
		return reject("rp_id_mismatch")
	case flags&flagUserPresent == 0:
		return reject("user_not_present")
	case flags&flagUserVerified == 0:
		return reject("user_not_verified")
	case flags&flagAttested != 0, flags&flagExtensions == 0 && len(data) != 37:
		return reject("authenticator_data_malformed")
	}
	counter := binary.BigEndian.Uint32(data[33:37])
	if !counterAdvances(counter, key.SignCount) {
		return reject("sign_count_not_increased")
	}
	public, err := parseCOSEKey(key.PublicKey)
	if err != nil {
		return reject("key_malformed")
	}
	clientHash := sha256.Sum256(assertion.GetClientDataJson())
	signed := sha256.Sum256(append(bytes.Clone(data), clientHash[:]...))
	if !ecdsa.VerifyASN1(public, signed[:], assertion.GetSignature()) {
		return reject("signature_invalid")
	}
	return Result{SignCount: counter}, nil
}

// counterAdvances accepts a synced passkey that reports 0 while the recorded
// counter is also 0 (decision A80); once a key has reported a non-zero counter
// it must strictly increase, so a return to 0 is a regression.
func counterAdvances(counter, recorded uint32) bool {
	return counter > recorded || (counter == 0 && recorded == 0)
}

// parseCOSEKey reads exactly {1: 2, 3: -7, -1: 1, -2: x, -3: y} in any order
// (RFC 9053 EC2 key, ES256, P-256) from definite-length CBOR.
func parseCOSEKey(raw []byte) (*ecdsa.PublicKey, error) {
	invalid := errors.New("invalid COSE EC2 P-256 key")
	major, count, rest, ok := cborHead(raw)
	if !ok || major != 5 || count != 5 {
		return nil, invalid
	}
	seen := map[int64]bool{}
	var x, y []byte
	for i := 0; i < 5; i++ {
		var label int64
		if label, rest, ok = cborInt(rest); !ok || seen[label] {
			return nil, invalid
		}
		seen[label] = true
		switch label {
		case 1, 3, -1:
			var value int64
			if value, rest, ok = cborInt(rest); !ok || value != map[int64]int64{1: 2, 3: -7, -1: 1}[label] {
				return nil, invalid
			}
		case -2, -3:
			var kind, length uint64
			if kind, length, rest, ok = cborHead(rest); !ok || kind != 2 || length != 32 || uint64(len(rest)) < length {
				return nil, invalid
			}
			if label == -2 {
				x = rest[:32]
			} else {
				y = rest[:32]
			}
			rest = rest[32:]
		default:
			return nil, invalid
		}
	}
	if len(rest) != 0 || x == nil || y == nil {
		return nil, invalid
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
}

// cborHead decodes a definite-length head: major type and argument.
func cborHead(b []byte) (major, value uint64, rest []byte, ok bool) {
	if len(b) == 0 {
		return 0, 0, nil, false
	}
	major, info, b := uint64(b[0]>>5), b[0]&0x1f, b[1:]
	switch {
	case info < 24:
		return major, uint64(info), b, true
	case info == 24 && len(b) >= 1:
		return major, uint64(b[0]), b[1:], true
	case info == 25 && len(b) >= 2:
		return major, uint64(binary.BigEndian.Uint16(b)), b[2:], true
	case info == 26 && len(b) >= 4:
		return major, uint64(binary.BigEndian.Uint32(b)), b[4:], true
	}
	return 0, 0, nil, false
}

func cborInt(b []byte) (int64, []byte, bool) {
	major, value, rest, ok := cborHead(b)
	if !ok || value > 1<<31 {
		return 0, nil, false
	}
	switch major {
	case 0:
		return int64(value), rest, true
	case 1:
		return -1 - int64(value), rest, true
	}
	return 0, nil, false
}
