package authz

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	eventsv1 "github.com/Kaivodev/protobuf/gen/go/aipay/events/v1"
	iamv1 "github.com/Kaivodev/protobuf/gen/go/aipay/iam/v1"
	"github.com/Kaivodev/servicekit/authz/authztest"
	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/signing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	notRequired = authztest.NotRequired
	required    = authztest.Required
	mfaRecent   = authztest.MFARecent
	singleUse   = authztest.SingleUse
)

type ruleSpec = authztest.Rule

type testSchema struct{}

func newSchema(*testing.T) testSchema { return testSchema{} }

func (testSchema) options(rules ...ruleSpec) *descriptorpb.MethodOptions {
	return authztest.Options(rules...)
}

func (testSchema) service(t *testing.T, name string, methods map[string]*descriptorpb.MethodOptions) protoreflect.ServiceDescriptor {
	t.Helper()
	service, err := authztest.Service("aipay.test.v1."+name, methods)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

var now = time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)

func devSigner(t *testing.T, id string) signing.Signer {
	t.Helper()
	signer, err := signing.Open(context.Background(), signing.Config{Environment: config.Development, Backend: signing.BackendMemory, KeyID: id}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func validClaims() Claims {
	fingerprint := sha256.Sum256([]byte("POST /api/withdrawals"))
	return Claims{Issuer: "iam", Subject: "0199f000-0000-7000-8000-00000000c0de", PrincipalType: PrincipalUser,
		ActingScope: Scope{Type: ScopeAccount, AccountID: "0199f000-0000-7000-8000-0000000000a1", AccountType: AccountPersonal},
		Audience:    Audience{"payment", "settlement"}, Permission: "settlement.withdrawal.create",
		RequestFingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]), AMR: []string{"pwd", "hwk", AMRMultiFactor},
		AuthTime: now.Add(-2 * time.Minute).Unix(), IssuedAt: now.Add(-10 * time.Second).Unix(), ExpiresAt: now.Add(50 * time.Second).Unix(),
		ID: "jti-0123456789abcdef"}
}

type memoryReplay struct {
	mu   sync.Mutex
	used map[string]bool
	fail error
}

func (m *memoryReplay) Consume(_ context.Context, use Use) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if m.used[use.ID] {
		return ErrReplayed
	}
	m.used[use.ID] = true
	return nil
}

type peerKey struct{}

func withPeer(ctx context.Context, peer string) context.Context {
	return context.WithValue(ctx, peerKey{}, peer)
}
func testPeer(ctx context.Context) (string, error) {
	if peer, ok := ctx.Value(peerKey{}).(string); ok {
		return peer, nil
	}
	return "", errors.New("no peer")
}

type fixture struct {
	authorizer *Authorizer
	iam        signing.Signer
	replay     *memoryReplay
	log        *bytes.Buffer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	schema := newSchema(t)
	withdraw := []string{"settlement.withdrawal.create"}
	service := schema.service(t, "WithdrawalService", map[string]*descriptorpb.MethodOptions{
		"Ping":     schema.options(ruleSpec{Callers: []string{"ledger", "reconciliation"}, Requirement: notRequired}),
		"Read":     schema.options(ruleSpec{Callers: []string{"backend"}, Requirement: required, Permissions: []string{"settlement.withdrawal.read", "settlement.record.read"}}, ruleSpec{Callers: []string{"ledger"}, Requirement: notRequired}),
		"Recent":   schema.options(ruleSpec{Callers: []string{"backend"}, Requirement: mfaRecent, Permissions: withdraw, MaxAgeSeconds: 300}),
		"Withdraw": schema.options(ruleSpec{Callers: []string{"backend"}, Requirement: singleUse, Permissions: withdraw, MaxAgeSeconds: 300}),
	})
	policies, err := LoadPolicies(service)
	if err != nil {
		t.Fatal(err)
	}
	iam := devSigner(t, "iam-2026-10")
	keys, _ := signing.NewPublicKeys(map[string]*ecdsa.PublicKey{"iam-2026-10": iam.PublicKey()})
	verifier, err := NewAssertionVerifier(VerifierConfig{Issuer: "iam", Audience: "settlement", Keys: keys, Leeway: 5 * time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	replay := &memoryReplay{used: map[string]bool{}}
	var log bytes.Buffer
	authorizer, err := New(Options{Service: "settlement", Policies: policies, Peer: testPeer, Assertions: verifier, Replay: replay,
		Log: slog.New(slog.NewJSONHandler(&log, nil)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{authorizer: authorizer, iam: iam, replay: replay, log: &log}
}

func (f fixture) token(t *testing.T, edit func(*Claims)) string {
	t.Helper()
	claims := validClaims()
	if edit != nil {
		edit(&claims)
	}
	token, err := SignAssertion(context.Background(), f.iam, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// call runs the unary interceptor and returns the Call the handler saw.
func (f fixture) call(method, peer string, tokens ...string) (Call, metadata.MD, error) {
	ctx := withPeer(context.Background(), peer)
	md := metadata.MD{}
	for _, token := range tokens {
		md.Append(MetadataKey, token)
	}
	md.Append("x-request-id", "kept")
	ctx = metadata.NewIncomingContext(ctx, md)
	var seen Call
	var seenMD metadata.MD
	_, err := f.authorizer.Unary()(ctx, &emptypb.Empty{}, &grpc.UnaryServerInfo{FullMethod: "/aipay.test.v1.WithdrawalService/" + method}, func(ctx context.Context, _ any) (any, error) {
		seen, _ = FromContext(ctx)
		seenMD, _ = metadata.FromIncomingContext(ctx)
		return &emptypb.Empty{}, nil
	})
	return seen, seenMD, err
}

func expect(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestCallersAndUndeclaredMethods(t *testing.T) {
	f := newFixture(t)
	call, _, err := f.call("Ping", "ledger")
	if err != nil || call.Caller() != "ledger" || call.Requirement() != NotRequired {
		t.Fatalf("call=%+v err=%v", call, err)
	}
	if _, ok := call.Assertion(); ok {
		t.Fatal("service call carried an assertion")
	}
	_, _, err = f.call("Ping", "backend")
	expect(t, err, codes.PermissionDenied)
	_, _, err = f.call("Ping", "ledger", f.token(t, nil))
	expect(t, err, codes.PermissionDenied)
	_, _, err = f.call("Undeclared", "ledger")
	expect(t, err, codes.PermissionDenied)
	_, err = f.authorizer.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/aipay.test.v1.WithdrawalService/Ping"}, nil)
	expect(t, err, codes.Unauthenticated)
	// The same method admits ledger as a service call and backend only with an assertion.
	if _, _, err = f.call("Read", "ledger"); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.call("Read", "backend")
	expect(t, err, codes.Unauthenticated)
	if !strings.Contains(f.log.String(), `"reason":"policy_missing"`) || !strings.Contains(f.log.String(), `"reason":"caller_not_allowed"`) {
		t.Fatalf("denials were not logged with reasons: %s", f.log)
	}
}

func TestHealthIsExempt(t *testing.T) {
	f := newFixture(t)
	ctx := withPeer(context.Background(), "probe")
	_, err := f.authorizer.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}, func(context.Context, any) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	unary, _ := DenyUndeclared()
	if _, err = unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}, func(context.Context, any) (any, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	_, err = unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/aipay.test.v1.WithdrawalService/Ping"}, nil)
	expect(t, err, codes.PermissionDenied)
}

func TestAssertionClaims(t *testing.T) {
	f := newFixture(t)
	call, md, err := f.call("Read", "backend", f.token(t, func(c *Claims) { c.Permission = "settlement.record.read" }))
	if err != nil {
		t.Fatal(err)
	}
	assertion, ok := call.Assertion()
	if !ok || assertion.Subject() != validClaims().Subject || assertion.ActingScope() != validClaims().ActingScope || len(assertion.RequestFingerprint()) != 32 {
		t.Fatalf("unexpected assertion %+v", assertion)
	}
	if len(md.Get(MetadataKey)) != 0 || len(md.Get("x-request-id")) != 1 {
		t.Fatal("raw assertion reached the handler or other metadata was lost")
	}
	assertion.AMR()[0] = "changed"
	if assertion.AMR()[0] != "pwd" {
		t.Fatal("assertion is mutable through its accessors")
	}
	other := devSigner(t, "iam-2026-10")
	forged, _ := SignAssertion(context.Background(), other, validClaims())
	unknown := devSigner(t, "iam-old")
	unregistered, _ := SignAssertion(context.Background(), unknown, validClaims())
	good := f.token(t, nil)
	parts := strings.Split(good, ".")
	reencode := func(header string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + parts[1] + "." + parts[2]
	}
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var widened map[string]any
	_ = json.Unmarshal(claimsJSON, &widened)
	widened["permission"] = "settlement.withdrawal.read"
	tampered, _ := json.Marshal(widened)
	cases := map[string]struct {
		method string
		token  string
		code   codes.Code
	}{
		"wrong audience": {"Read", f.token(t, func(c *Claims) { c.Audience = Audience{"payment"}; c.Permission = "settlement.withdrawal.read" }), codes.Unauthenticated},
		"permission":     {"Read", good, codes.PermissionDenied},
		"wrong issuer":   {"Read", f.token(t, func(c *Claims) { c.Issuer = "backend"; c.Permission = "settlement.withdrawal.read" }), codes.Unauthenticated},
		"expired": {"Read", f.token(t, func(c *Claims) {
			c.IssuedAt, c.ExpiresAt = now.Add(-2*time.Minute).Unix(), now.Add(-time.Minute).Unix()
		}), codes.Unauthenticated},
		"issued in the future": {"Read", f.token(t, func(c *Claims) {
			c.IssuedAt, c.ExpiresAt = now.Add(time.Minute).Unix(), now.Add(time.Minute+30*time.Second).Unix()
		}), codes.Unauthenticated},
		"other key":        {"Recent", forged, codes.Unauthenticated},
		"unregistered key": {"Recent", unregistered, codes.Unauthenticated},
		"tampered claims":  {"Read", parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2], codes.Unauthenticated},
		"alg none":         {"Recent", reencode(`{"alg":"none","kid":"iam-2026-10","typ":"aipay-assertion+jwt"}`), codes.Unauthenticated},
		"embedded key":     {"Recent", reencode(`{"alg":"ES256","kid":"iam-2026-10","typ":"aipay-assertion+jwt","jku":"https://attacker.test"}`), codes.Unauthenticated},
		"wrong type":       {"Recent", reencode(`{"alg":"ES256","kid":"iam-2026-10","typ":"JWT"}`), codes.Unauthenticated},
		"duplicate header": {"Recent", reencode(`{"alg":"ES256","kid":"iam-2026-10","typ":"aipay-assertion+jwt","alg":"ES256"}`), codes.Unauthenticated},
		"truncated":        {"Recent", parts[0] + "." + parts[1], codes.Unauthenticated},
		"garbage":          {"Recent", "not-a-token", codes.Unauthenticated},
		"no mfa":           {"Recent", f.token(t, func(c *Claims) { c.AMR = []string{"pwd", "otp"} }), codes.PermissionDenied},
		"stale auth":       {"Recent", f.token(t, func(c *Claims) { c.AuthTime = now.Add(-6 * time.Minute).Unix() }), codes.PermissionDenied},
		"no auth_time":     {"Recent", f.token(t, func(c *Claims) { c.AuthTime = 0 }), codes.PermissionDenied},
		"merchant signature": {"Recent", f.token(t, func(c *Claims) {
			c.PrincipalType, c.AMR = PrincipalMerchantApplication, []string{"epay_v2_sign"}
			c.ActingScope = Scope{Type: ScopeApplication, AccountID: "a1", AccountType: AccountPersonal, BusinessID: "b1", ApplicationID: "app1"}
		}), codes.PermissionDenied},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := f.call(tc.method, "backend", tc.token)
			expect(t, err, tc.code)
		})
	}
	_, _, err = f.call("Recent", "backend", good, good)
	expect(t, err, codes.Unauthenticated)
	if _, _, err = f.call("Recent", "backend", good); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.log.String(), parts[2]) || strings.Contains(f.log.String(), parts[1]) {
		t.Fatal("assertion material was logged")
	}
}

func TestLongLifetimeAndMalformedClaimsCannotBeIssued(t *testing.T) {
	f := newFixture(t)
	for name, edit := range map[string]func(*Claims){
		"lifetime":    func(c *Claims) { c.ExpiresAt = c.IssuedAt + 61 },
		"scope":       func(c *Claims) { c.ActingScope = Scope{Type: ScopePlatform, BusinessID: "x"} },
		"fingerprint": func(c *Claims) { c.RequestFingerprint = "short" },
		"jti":         func(c *Claims) { c.ID = "short" },
		"wildcard":    func(c *Claims) { c.Permission = "settlement.*" },
	} {
		claims := validClaims()
		edit(&claims)
		if _, err := SignAssertion(context.Background(), f.iam, claims); err == nil {
			t.Fatalf("%s: malformed claims signed", name)
		}
	}
	// A verifier also refuses a long-lived assertion signed by a non-conforming issuer.
	claims := validClaims()
	claims.ExpiresAt = claims.IssuedAt + 3600
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"iam-2026-10","typ":"aipay-assertion+jwt"}`))
	body, _ := json.Marshal(claims)
	input := header + "." + base64.RawURLEncoding.EncodeToString(body)
	der, _ := f.iam.Sign(context.Background(), []byte(input))
	jws := input + "." + base64.RawURLEncoding.EncodeToString(derToRaw(t, der))
	_, _, err := f.call("Recent", "backend", jws)
	expect(t, err, codes.Unauthenticated)
}

func derToRaw(t *testing.T, der []byte) []byte {
	t.Helper()
	// Reuse SignAssertion's conversion through a signer that returns der.
	token, err := SignAssertion(context.Background(), fixedSigner{der: der}, validClaims())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(token[strings.LastIndex(token, ".")+1:])
	return raw
}

type fixedSigner struct{ der []byte }

func (fixedSigner) KeyID() string                                  { return "iam-2026-10" }
func (fixedSigner) PublicKey() *ecdsa.PublicKey                    { return nil }
func (s fixedSigner) Sign(context.Context, []byte) ([]byte, error) { return s.der, nil }

func TestSingleUse(t *testing.T) {
	f := newFixture(t)
	token := f.token(t, nil)
	if _, _, err := f.call("Withdraw", "backend", token); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.call("Withdraw", "backend", token)
	expect(t, err, codes.Unauthenticated)
	if !strings.Contains(f.log.String(), `"reason":"assertion_replayed"`) {
		t.Fatal("replay was not logged")
	}
	_, _, err = f.call("Withdraw", "backend", f.token(t, func(c *Claims) { c.AMR = []string{"pwd"}; c.ID = "jti-fedcba9876543210" }))
	expect(t, err, codes.PermissionDenied)
	if f.replay.used["jti-fedcba9876543210"] {
		t.Fatal("an assertion failing MFA was consumed")
	}
	f.replay.fail = errors.New("database down")
	_, _, err = f.call("Withdraw", "backend", f.token(t, func(c *Claims) { c.ID = "jti-1111111111111111" }))
	expect(t, err, codes.Unavailable)
}

func TestStreamInterceptor(t *testing.T) {
	f := newFixture(t)
	ctx := metadata.NewIncomingContext(withPeer(context.Background(), "backend"), metadata.Pairs(MetadataKey, f.token(t, nil)))
	var seen Call
	err := f.authorizer.Stream()(nil, &fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/aipay.test.v1.WithdrawalService/Recent"}, func(_ any, stream grpc.ServerStream) error {
		seen, _ = FromContext(stream.Context())
		return nil
	})
	if err != nil || seen.Method() != "/aipay.test.v1.WithdrawalService/Recent" {
		t.Fatalf("seen=%+v err=%v", seen, err)
	}
	err = f.authorizer.Stream()(nil, &fakeStream{ctx: withPeer(context.Background(), "backend")}, &grpc.StreamServerInfo{FullMethod: "/aipay.test.v1.Other/Watch"}, nil)
	expect(t, err, codes.PermissionDenied)
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeStream) Context() context.Context { return s.ctx }

func TestLoadPoliciesFailsClosed(t *testing.T) {
	schema := newSchema(t)
	ok := schema.options(ruleSpec{Callers: []string{"ledger"}, Requirement: notRequired})
	cases := map[string]*descriptorpb.MethodOptions{
		"undeclared":        nil,
		"no rules":          schema.options(),
		"unspecified":       schema.options(ruleSpec{Callers: []string{"ledger"}}),
		"unknown enum":      schema.options(ruleSpec{Callers: []string{"ledger"}, Requirement: 9}),
		"duplicate caller":  schema.options(ruleSpec{Callers: []string{"ledger"}, Requirement: notRequired}, ruleSpec{Callers: []string{"ledger"}, Requirement: required, Permissions: []string{"a.b"}}),
		"no permission":     schema.options(ruleSpec{Callers: []string{"backend"}, Requirement: required}),
		"mfa without age":   schema.options(ruleSpec{Callers: []string{"backend"}, Requirement: mfaRecent, Permissions: []string{"a.b"}}),
		"service with perm": schema.options(ruleSpec{Callers: []string{"ledger"}, Requirement: notRequired, Permissions: []string{"a.b"}}),
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			service := schema.service(t, "S", map[string]*descriptorpb.MethodOptions{"Fine": ok, "Bad": options})
			if _, err := LoadPolicies(service); err == nil {
				t.Fatal("invalid policy loaded")
			}
		})
	}
	// A future contract field this version cannot enforce must not be ignored.
	rule := extendedRule(t, schema)
	service := schema.service(t, "S", map[string]*descriptorpb.MethodOptions{"Fine": rule})
	if _, err := LoadPolicies(service); err == nil {
		t.Fatal("unknown policy field ignored")
	}
	policies, err := LoadPolicies(schema.service(t, "S", map[string]*descriptorpb.MethodOptions{"Fine": ok}))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := policies.Lookup("/aipay.test.v1.S/Fine"); !found {
		t.Fatal("policy not keyed by full method")
	}
	// New refuses rules it cannot enforce.
	single := schema.service(t, "S", map[string]*descriptorpb.MethodOptions{"W": schema.options(ruleSpec{Callers: []string{"backend"}, Requirement: singleUse, Permissions: []string{"a.b"}, MaxAgeSeconds: 60})})
	policies, _ = LoadPolicies(single)
	if _, err = New(Options{Service: "settlement", Policies: policies, Peer: testPeer, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err == nil {
		t.Fatal("authorizer without assertion verifier accepted")
	}
}

// extendedRule appends an unknown field (number 15) to a rule, as a newer
// contract version adding a constraint would.
func extendedRule(t *testing.T, schema testSchema) *descriptorpb.MethodOptions {
	t.Helper()
	policy := authztest.Policy(ruleSpec{Callers: []string{"ledger"}, Requirement: notRequired})
	policy.GetRules()[0].ProtoReflect().SetUnknown(protoreflect.RawFields{0x7a, 0x01, 0x78}) // field 15, bytes "x"
	return authztest.WithPolicy(policy)
}

// The published contracts load as declared: every IAM and event stream method
// has a policy the interceptor understands.
func TestGeneratedContractPolicies(t *testing.T) {
	policies, err := LoadPolicies(
		iamv1.File_aipay_iam_v1_authorization_proto.Services().ByName("AuthorizationService"),
		eventsv1.File_aipay_events_v1_event_stream_proto.Services().ByName("EventStreamService"))
	if err != nil {
		t.Fatal(err)
	}
	authorize, ok := policies.Lookup("/aipay.iam.v1.AuthorizationService/Authorize")
	if rule, admitted := authorize.Rule("backend"); !ok || !admitted || rule.Requirement != NotRequired {
		t.Fatalf("Authorize policy %+v", authorize)
	}
	list, ok := policies.Lookup("/aipay.events.v1.EventStreamService/ListEvents")
	if _, admitted := list.Rule("payment"); !ok || admitted {
		t.Fatal("ListEvents admits a non-receiver")
	}
	for _, receiver := range []string{"ledger", "reconciliation", "settlement"} {
		if _, admitted := list.Rule(receiver); !admitted {
			t.Fatalf("ListEvents does not admit %s", receiver)
		}
	}
}

func TestActingScopeShapes(t *testing.T) {
	const account, org, business, app = "account-1", "org-1", "business-1", "app-1"
	personal := func(s Scope) Scope { s.AccountID, s.AccountType = account, AccountPersonal; return s }
	organization := func(s Scope) Scope { s.AccountID, s.AccountType, s.OrgID = account, AccountOrganization, org; return s }
	valid := map[string]Scope{
		"platform":                    {Type: ScopePlatform},
		"platform bound to account":   personal(Scope{Type: ScopePlatform}),
		"personal account":            personal(Scope{Type: ScopeAccount}),
		"organization account":        organization(Scope{Type: ScopeAccount}),
		"organization without org_id": {Type: ScopeAccount, AccountID: account, AccountType: AccountOrganization},
		"business":                    personal(Scope{Type: ScopeBusiness, BusinessID: business}),
		"application":                 organization(Scope{Type: ScopeApplication, BusinessID: business, ApplicationID: app}),
	}
	for name, scope := range valid {
		if !scope.valid() {
			t.Errorf("%s rejected: %+v", name, scope)
		}
	}
	invalid := map[string]Scope{
		"unknown type":                 {Type: "organization", AccountID: account, AccountType: AccountOrganization},
		"no type":                      personal(Scope{}),
		"account without id":           {Type: ScopeAccount, AccountType: AccountPersonal},
		"account without type":         {Type: ScopeAccount, AccountID: account},
		"unknown account type":         {Type: ScopeAccount, AccountID: account, AccountType: "team"},
		"personal with org":            {Type: ScopeAccount, AccountID: account, AccountType: AccountPersonal, OrgID: org},
		"account with business":        personal(Scope{Type: ScopeAccount, BusinessID: business}),
		"business without id":          personal(Scope{Type: ScopeBusiness}),
		"business without account":     {Type: ScopeBusiness, BusinessID: business},
		"business with application":    personal(Scope{Type: ScopeBusiness, BusinessID: business, ApplicationID: app}),
		"application without id":       personal(Scope{Type: ScopeApplication, BusinessID: business}),
		"application without business": personal(Scope{Type: ScopeApplication, ApplicationID: app}),
		"platform with business":       {Type: ScopePlatform, BusinessID: business},
		"platform with org only":       {Type: ScopePlatform, OrgID: org},
		"platform personal with org":   {Type: ScopePlatform, AccountID: account, AccountType: AccountPersonal, OrgID: org},
	}
	for name, scope := range invalid {
		if scope.valid() {
			t.Errorf("%s accepted: %+v", name, scope)
		}
	}
}

// signRaw signs arbitrary claim JSON as IAM would, bypassing SignAssertion's
// own validation, to prove the verifier rejects what a faulty issuer emits.
func signRaw(t *testing.T, signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}, claims string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"iam-2026-10","typ":"aipay-assertion+jwt"}`))
	input := header + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	der, err := signer.Sign(context.Background(), []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(derToRaw(t, der))
}

func TestActingScopeVerification(t *testing.T) {
	f := newFixture(t)
	encode := func(scope string, edit func(map[string]any)) string {
		claims := validClaims()
		body, _ := json.Marshal(claims)
		var fields map[string]any
		_ = json.Unmarshal(body, &fields)
		var parsed any
		_ = json.Unmarshal([]byte(scope), &parsed)
		fields["acting_scope"] = parsed
		if edit != nil {
			edit(fields)
		}
		out, _ := json.Marshal(fields)
		return string(out)
	}
	if _, _, err := f.call("Recent", "backend", signRaw(t, f.iam, encode(`{"type":"account","account_id":"a1","account_type":"personal"}`, nil))); err != nil {
		t.Fatal("valid raw assertion rejected:", err)
	}
	for name, claims := range map[string]string{
		"superseded organization scope": encode(`{"type":"organization","organization_id":"o1"}`, nil),
		"superseded member":             encode(`{"type":"account","account_id":"a1","account_type":"organization","organization_id":"o1"}`, nil),
		"personal account with org":     encode(`{"type":"account","account_id":"a1","account_type":"personal","org_id":"o1"}`, nil),
		"business without business_id":  encode(`{"type":"business","account_id":"a1","account_type":"personal"}`, nil),
		"unknown scope type":            encode(`{"type":"tenant","account_id":"a1","account_type":"personal"}`, nil),
		"missing acting_scope":          encode(`null`, func(m map[string]any) { delete(m, "acting_scope") }),
		"merchant application at business scope": encode(`{"type":"business","account_id":"a1","account_type":"personal","business_id":"b1"}`, func(m map[string]any) {
			m["principal_type"] = PrincipalMerchantApplication
		}),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := f.call("Recent", "backend", signRaw(t, f.iam, claims))
			expect(t, err, codes.Unauthenticated)
		})
	}
	if _, err := SignAssertion(context.Background(), f.iam, func() Claims {
		c := validClaims()
		c.ActingScope = Scope{Type: ScopeAccount, AccountID: "a1", AccountType: AccountPersonal, OrgID: "o1"}
		return c
	}()); err == nil {
		t.Fatal("issued a personal-account assertion with an organization")
	}
}

func TestCallScopeAccess(t *testing.T) {
	f := newFixture(t)
	business := Scope{Type: ScopeBusiness, AccountID: "account-1", AccountType: AccountOrganization, OrgID: "org-1", BusinessID: "business-1"}
	call, _, err := f.call("Read", "backend", f.token(t, func(c *Claims) { c.ActingScope = business; c.Permission = "settlement.record.read" }))
	if err != nil {
		t.Fatal(err)
	}
	account, ok := call.Account()
	if !ok || account != (Account{ID: "account-1", Type: AccountOrganization, OrgID: "org-1"}) {
		t.Fatalf("account=%+v ok=%v", account, ok)
	}
	if _, err = call.RequireScope(ScopeAccount); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("business scope passed an account-wide requirement: %v", err)
	}
	if scope, err := call.RequireScope(ScopeAccount, ScopeBusiness); err != nil || scope.BusinessID != "business-1" {
		t.Fatalf("scope=%+v err=%v", scope, err)
	}
	service, _, err := f.call("Read", "ledger")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := service.Account(); ok {
		t.Fatal("service call reported an account")
	}
	if _, err = service.RequireScope(ScopePlatform, ScopeAccount, ScopeBusiness, ScopeApplication); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("service call passed a scope requirement: %v", err)
	}
}
