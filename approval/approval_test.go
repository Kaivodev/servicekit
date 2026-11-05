package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	approvalv1 "github.com/Kaivodev/protobuf/gen/go/aipay/approval/v1"
	"github.com/Kaivodev/protobuf/testvectors"
	"google.golang.org/protobuf/proto"
)

type vectorAssertion struct {
	Name            string `json:"name"`
	StoredSignCount uint32 `json:"stored_sign_count"`
	Assertion       struct {
		CredentialID      string `json:"credential_id"`
		AuthenticatorData string `json:"authenticator_data"`
		ClientDataJSON    string `json:"client_data_json"`
		Signature         string `json:"signature"`
	} `json:"assertion"`
}

type vectors struct {
	RPID          string `json:"rp_id"`
	Origin        string `json:"origin"`
	RequestBytes  string `json:"request_bytes"`
	RequestDigest string `json:"request_digest"`
	Credential    struct {
		CredentialID  string `json:"credential_id"`
		COSEPublicKey string `json:"cose_public_key"`
	} `json:"credential"`
	Valid   []vectorAssertion `json:"valid"`
	Invalid []vectorAssertion `json:"invalid"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	var v vectors
	if err := json.Unmarshal(testvectors.ApprovalV1(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v vectors) assertion(t *testing.T, a vectorAssertion) *approvalv1.WebAuthnAssertion {
	return &approvalv1.WebAuthnAssertion{CredentialId: unhex(t, a.Assertion.CredentialID), AuthenticatorData: unhex(t, a.Assertion.AuthenticatorData),
		ClientDataJson: unhex(t, a.Assertion.ClientDataJSON), Signature: unhex(t, a.Assertion.Signature)}
}

var now = time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)

func expectReason(t *testing.T, err error, reason string) {
	t.Helper()
	var rejection *Rejection
	if !errors.As(err, &rejection) || rejection.Reason != reason {
		t.Fatalf("got %v, want %s", err, reason)
	}
}

func TestContractVectors(t *testing.T) {
	v := loadVectors(t)
	digest := Digest(unhex(t, v.RequestBytes))
	if hex.EncodeToString(digest[:]) != v.RequestDigest {
		t.Fatal("request digest differs from the contract vector")
	}
	verifier, err := NewVerifier(v.RPID, []string{v.Origin}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Digest: digest, RequestedBy: "requester", ExpiresAt: now.Add(time.Hour)}
	key := func(stored uint32) Key {
		return Key{ID: "key-1", ApproverID: "approver-1", IAMUserID: "approver-user", CredentialID: unhex(t, v.Credential.CredentialID),
			PublicKey: unhex(t, v.Credential.COSEPublicKey), RPID: v.RPID, SignCount: stored}
	}
	if len(v.Valid) < 3 {
		t.Fatal("expected counter, synced passkey and first-counter vectors")
	}
	for _, valid := range v.Valid {
		assertion := v.assertion(t, valid)
		result, err := verifier.Verify(request, key(valid.StoredSignCount), assertion)
		if err != nil || result.SignCount != binary.BigEndian.Uint32(assertion.AuthenticatorData[33:37]) {
			t.Fatalf("%s: result=%+v err=%v", valid.Name, result, err)
		}
	}
	want := map[string]string{
		"counter_not_increased": "sign_count_not_increased", "counter_regressed": "sign_count_not_increased", "counter_reset_to_zero": "sign_count_not_increased",
		"user_not_verified": "user_not_verified", "user_not_present": "user_not_present", "wrong_challenge": "challenge_mismatch",
		"wrong_origin": "origin_mismatch", "wrong_rp_id": "rp_id_mismatch", "registration_type": "client_data_type", "cross_origin": "origin_mismatch",
	}
	for _, invalid := range v.Invalid {
		_, err := verifier.Verify(request, key(invalid.StoredSignCount), v.assertion(t, invalid))
		expectReason(t, err, want[invalid.Name])
	}
}

func TestRequestAndRegistryChecks(t *testing.T) {
	v := loadVectors(t)
	verifier, _ := NewVerifier(v.RPID, []string{v.Origin}, func() time.Time { return now })
	valid := v.assertion(t, v.Valid[0])
	digest := Digest(unhex(t, v.RequestBytes))
	base := func() (Request, Key) {
		return Request{Digest: digest, RequestedBy: "requester", ExpiresAt: now.Add(time.Hour)},
			Key{ApproverID: "approver-1", IAMUserID: "approver-user", CredentialID: valid.GetCredentialId(), PublicKey: unhex(t, v.Credential.COSEPublicKey), RPID: v.RPID, SignCount: 41}
	}
	cases := map[string]func(*Request, *Key, *approvalv1.WebAuthnAssertion){
		"request_expired":     func(r *Request, _ *Key, _ *approvalv1.WebAuthnAssertion) { r.ExpiresAt = now },
		"self_approval":       func(r *Request, k *Key, _ *approvalv1.WebAuthnAssertion) { r.RequestedBy = k.IAMUserID },
		"duplicate_approver":  func(r *Request, k *Key, _ *approvalv1.WebAuthnAssertion) { r.Approvers = []string{k.ApproverID} },
		"key_revoked":         func(_ *Request, k *Key, _ *approvalv1.WebAuthnAssertion) { k.Revoked = true },
		"key_rp_id":           func(_ *Request, k *Key, _ *approvalv1.WebAuthnAssertion) { k.RPID = "aipay.example" },
		"credential_mismatch": func(_ *Request, _ *Key, a *approvalv1.WebAuthnAssertion) { a.CredentialId = []byte("other") },
		"challenge_mismatch": func(r *Request, _ *Key, _ *approvalv1.WebAuthnAssertion) {
			r.Digest = Digest([]byte("another request"))
		},
		"signature_invalid": func(_ *Request, _ *Key, a *approvalv1.WebAuthnAssertion) {
			a.Signature = append([]byte{}, a.Signature[:len(a.Signature)-1]...)
		},
		"key_malformed": func(_ *Request, k *Key, _ *approvalv1.WebAuthnAssertion) { k.PublicKey = k.PublicKey[:20] },
		"authenticator_data_malformed": func(_ *Request, _ *Key, a *approvalv1.WebAuthnAssertion) {
			a.AuthenticatorData = append(append([]byte{}, a.AuthenticatorData...), 0xa0)
		},
	}
	for reason, edit := range cases {
		t.Run(reason, func(t *testing.T) {
			request, key := base()
			assertion := proto.Clone(valid).(*approvalv1.WebAuthnAssertion)
			edit(&request, &key, assertion)
			_, err := verifier.Verify(request, key, assertion)
			expectReason(t, err, reason)
		})
	}
	request, key := base()
	key.PublicKey = otherKey(t)
	_, err := verifier.Verify(request, key, valid)
	expectReason(t, err, "signature_invalid")
	if _, err = NewVerifier(v.RPID, []string{"http://admin.aipay.example"}, nil); err == nil {
		t.Fatal("plain HTTP origin accepted")
	}
}

func otherKey(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	cose := append([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}, raw[1:33]...)
	return append(append(cose, 0x22, 0x58, 0x20), raw[33:]...)
}

type softwareKey struct {
	key  *ecdsa.PrivateKey
	cose []byte
}

func newSoftwareKey(t *testing.T) softwareKey {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	cose := append([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}, raw[1:33]...)
	return softwareKey{key: key, cose: append(append(cose, 0x22, 0x58, 0x20), raw[33:]...)}
}

func (k softwareKey) assert(t *testing.T, digest [32]byte, counter uint32) *approvalv1.WebAuthnAssertion {
	t.Helper()
	rp := sha256.Sum256([]byte("admin.aipay.example"))
	data := binary.BigEndian.AppendUint32(append(rp[:], 0x05), counter)
	client := []byte(`{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `","origin":"https://admin.aipay.example"}`)
	clientHash := sha256.Sum256(client)
	signed := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, k.key, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	return &approvalv1.WebAuthnAssertion{CredentialId: []byte("cred"), AuthenticatorData: data, ClientDataJson: client, Signature: signature}
}

// approve runs one approval per counter, recording the returned counter as an
// executor would, and returns the first rejection.
func approve(t *testing.T, key softwareKey, counters ...uint32) (int, error) {
	t.Helper()
	verifier, _ := NewVerifier("admin.aipay.example", []string{"https://admin.aipay.example"}, func() time.Time { return now })
	registry := Key{ApproverID: "approver", IAMUserID: "approver-user", CredentialID: []byte("cred"), PublicKey: key.cose, RPID: "admin.aipay.example"}
	for i, counter := range counters {
		digest := Digest([]byte(fmt.Sprintf("request %d", i)))
		result, err := verifier.Verify(Request{Digest: digest, RequestedBy: "requester", ExpiresAt: now.Add(time.Hour)}, registry, key.assert(t, digest, counter))
		if err != nil {
			return i, err
		}
		registry.SignCount = result.SignCount
	}
	return len(counters), nil
}

func TestSignCounterRules(t *testing.T) {
	key := newSoftwareKey(t)
	// A synced passkey reports 0 on every use.
	if n, err := approve(t, key, 0, 0, 0, 0); err != nil {
		t.Fatalf("synced passkey rejected at use %d: %v", n+1, err)
	}
	// A counter may start after a recorded 0 and must then strictly increase.
	if n, err := approve(t, key, 0, 1, 2, 7); err != nil {
		t.Fatalf("increasing counter rejected at use %d: %v", n+1, err)
	}
	for name, counters := range map[string][]uint32{
		"regressed":     {5, 6, 4},
		"repeated":      {5, 5},
		"reset to zero": {3, 0},
		"zero after 1":  {0, 1, 0},
	} {
		n, err := approve(t, key, counters...)
		if n != len(counters)-1 {
			t.Fatalf("%s: rejected at use %d instead of the last", name, n+1)
		}
		expectReason(t, err, "sign_count_not_increased")
	}
}

// A software authenticator exercises extension data and COSE label order.
func TestExtensionDataAndKeyEncoding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	// Labels in a different order: -3, -2, 3, 1, -1.
	cose := append([]byte{0xa5, 0x22, 0x58, 0x20}, raw[33:]...)
	cose = append(append(cose, 0x21, 0x58, 0x20), raw[1:33]...)
	cose = append(cose, 0x03, 0x26, 0x01, 0x02, 0x20, 0x01)
	digest := Digest([]byte("request"))
	rp := sha256.Sum256([]byte("admin.aipay.example"))
	sign := func(flags byte, tail []byte) *approvalv1.WebAuthnAssertion {
		data := binary.BigEndian.AppendUint32(append(rp[:], flags), 7)
		data = append(data, tail...)
		client := []byte(`{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `","origin":"https://admin.aipay.example"}`)
		clientHash := sha256.Sum256(client)
		signed := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
		signature, _ := ecdsa.SignASN1(rand.Reader, key, signed[:])
		return &approvalv1.WebAuthnAssertion{CredentialId: []byte("cred"), AuthenticatorData: data, ClientDataJson: client, Signature: signature}
	}
	verifier, _ := NewVerifier("admin.aipay.example", []string{"https://admin.aipay.example"}, func() time.Time { return now })
	request := Request{Digest: digest, RequestedBy: "requester", ExpiresAt: now.Add(time.Minute)}
	registry := Key{ApproverID: "a", IAMUserID: "u", CredentialID: []byte("cred"), PublicKey: cose, RPID: "admin.aipay.example", SignCount: 6}
	if _, err := verifier.Verify(request, registry, sign(0x85, []byte{0xa0})); err != nil {
		t.Fatal("extension data rejected:", err)
	}
	_, err := verifier.Verify(request, registry, sign(0x45, nil))
	expectReason(t, err, "authenticator_data_malformed")
	duplicate := append([]byte{}, cose...)
	duplicate[len(duplicate)-2] = 0x03 // second alg label instead of crv
	registry.PublicKey = duplicate
	_, err = verifier.Verify(request, registry, sign(0x05, nil))
	expectReason(t, err, "key_malformed")
}
