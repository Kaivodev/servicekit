package authz_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/servicekit/authz"
	"github.com/aipay-dev/servicekit/authz/authztest"
	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/devcert"
	"github.com/aipay-dev/servicekit/mtls"
	"github.com/aipay-dev/servicekit/rpc"
	"github.com/aipay-dev/servicekit/signing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

type usedIDs struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (u *usedIDs) Consume(_ context.Context, use authz.Use) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.seen[use.ID] {
		return authz.ErrReplayed
	}
	u.seen[use.ID] = true
	return nil
}

// register serves every method of service with a handler that reports the
// verified funds account back through a header. CreateWithdrawal acts on
// account-wide funds, so like a real handler it requires the account scope.
func register(service string, methods ...string) rpc.Register {
	return func(registrar grpc.ServiceRegistrar) {
		desc := &grpc.ServiceDesc{ServiceName: service, HandlerType: (*any)(nil)}
		for _, method := range methods {
			full := "/" + service + "/" + method
			desc.Methods = append(desc.Methods, grpc.MethodDesc{MethodName: method, Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(emptypb.Empty)
				if err := decode(request); err != nil {
					return nil, err
				}
				return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: srv, FullMethod: full}, func(ctx context.Context, _ any) (any, error) {
					call, ok := authz.FromContext(ctx)
					if !ok {
						return nil, status.Error(codes.Internal, "no authorization context")
					}
					if method == "CreateWithdrawal" {
						if _, err := call.RequireScope(authz.ScopeAccount); err != nil {
							return nil, err
						}
					}
					if account, ok := call.Account(); ok {
						_ = grpc.SetHeader(ctx, metadata.Pairs("x-test-account", account.ID))
					}
					return &emptypb.Empty{}, nil
				})
			}})
		}
		registrar.RegisterService(desc, struct{}{})
	}
}

func TestAuthorizationOverMutualTLS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := devcert.Generate(dir, "aipay.test", []string{"settlement", "backend", "ledger", "payment"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	material := map[string]*mtls.Material{}
	for _, name := range []string{"settlement", "backend", "ledger", "payment"} {
		m, err := mtls.Load(config.TLS{CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(dir, name, "tls.crt"), KeyFile: filepath.Join(dir, name, "tls.key"), TrustDomain: "aipay.test"}, name)
		if err != nil {
			t.Fatal(err)
		}
		material[name] = m
	}
	const name = "aipay.settlement.v1.WithdrawalService"
	service, err := authztest.Service(name, map[string]*descriptorpb.MethodOptions{
		"CreateWithdrawal": authztest.Options(authztest.Rule{Callers: []string{"backend"}, Requirement: authztest.SingleUse, Permissions: []string{"settlement.withdrawal.create"}, MaxAgeSeconds: 300}),
		"GetWithdrawal":    authztest.Options(authztest.Rule{Callers: []string{"backend"}, Requirement: authztest.Required, Permissions: []string{"settlement.withdrawal.read", "settlement.record.read"}}, authztest.Rule{Callers: []string{"ledger"}, Requirement: authztest.NotRequired}),
		"Undeclared":       nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authz.LoadPolicies(service); err == nil {
		t.Fatal("a service with an undeclared method loaded")
	}
	declared, err := authztest.Service(name, map[string]*descriptorpb.MethodOptions{
		"CreateWithdrawal": authztest.Options(authztest.Rule{Callers: []string{"backend"}, Requirement: authztest.SingleUse, Permissions: []string{"settlement.withdrawal.create"}, MaxAgeSeconds: 300}),
		"GetWithdrawal":    authztest.Options(authztest.Rule{Callers: []string{"backend"}, Requirement: authztest.Required, Permissions: []string{"settlement.withdrawal.read", "settlement.record.read"}}, authztest.Rule{Callers: []string{"ledger"}, Requirement: authztest.NotRequired}),
	})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := authz.LoadPolicies(declared)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := signing.Open(context.Background(), signing.Config{Environment: config.Development, Backend: signing.BackendMemory, KeyID: "iam-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := signing.MarshalJWKS(map[string]*ecdsa.PublicKey{"iam-1": iam.PublicKey()})
	keys, err := signing.ParseJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authz.NewAssertionVerifier(authz.VerifierConfig{Issuer: "iam", Audience: "settlement", Keys: keys, Leeway: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authz.New(authz.Options{Service: "settlement", Policies: policies, Peer: material["settlement"].Peer, Assertions: verifier,
		Replay: &usedIDs{seen: map[string]bool{}}, Log: logging.New(io.Discard, slog.LevelInfo)})
	if err != nil {
		t.Fatal(err)
	}
	options := rpc.ServerOptions{RPC: config.RPC{Address: "127.0.0.1:0", ServerName: "settlement", AllowedPeers: []string{"backend", "ledger", "payment"}, CallTimeout: time.Second, MaxMessageBytes: 4096, MaxConcurrentStreams: 16},
		HealthTimeout: 50 * time.Millisecond, HealthInterval: 10 * time.Millisecond, ShutdownTimeout: time.Second, Authorizer: authorizer}
	server, err := rpc.NewServer(options, material["settlement"], logging.New(io.Discard, slog.LevelInfo), logging.New(io.Discard, slog.LevelInfo), nil, register(name, "CreateWithdrawal", "GetWithdrawal", "Undeclared"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	defer func() { cancel(); <-done }()
	dial := func(caller string) *grpc.ClientConn {
		connectCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		conn, err := rpc.Connect(connectCtx, material[caller], rpc.ClientOptions{Address: server.Address(), ServerName: "settlement", ExpectedService: "settlement", CallTimeout: time.Second, MaxMessageBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	backend, ledger, payment := dial("backend"), dial("ledger"), dial("payment")
	deadline := time.Now().Add(2 * time.Second)
	for !server.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("server not ready")
		}
		time.Sleep(time.Millisecond)
	}
	fingerprint := sha256.Sum256([]byte("request"))
	issued := 0
	issue := func(edit func(*authz.Claims)) string {
		now := time.Now()
		issued++
		claims := authz.Claims{Issuer: "iam", Subject: "user-1", PrincipalType: authz.PrincipalUser,
			ActingScope: authz.Scope{Type: authz.ScopeAccount, AccountID: "account-1", AccountType: authz.AccountOrganization, OrgID: "org-1"}, Audience: authz.Audience{"settlement"},
			Permission: "settlement.withdrawal.create", RequestFingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]), AMR: []string{"pwd", "hwk", "mfa"},
			AuthTime: now.Add(-time.Minute).Unix(), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), ID: fmt.Sprintf("assertion-%08d", issued)}
		if edit != nil {
			edit(&claims)
		}
		token, err := authz.SignAssertion(context.Background(), iam, claims)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	invoke := func(conn *grpc.ClientConn, method, token string) (string, error) {
		callCtx := context.Background()
		if token != "" {
			callCtx = metadata.AppendToOutgoingContext(callCtx, authz.MetadataKey, token)
		}
		var header metadata.MD
		err := conn.Invoke(callCtx, "/"+name+"/"+method, &emptypb.Empty{}, &emptypb.Empty{}, grpc.Header(&header))
		account := header.Get("x-test-account")
		if len(account) == 0 {
			return "", err
		}
		return account[0], err
	}
	expect := func(label string, err error, code codes.Code) {
		t.Helper()
		if status.Code(err) != code {
			t.Fatalf("%s: got %v, want %s", label, err, code)
		}
	}
	token := issue(nil)
	account, err := invoke(backend, "CreateWithdrawal", token)
	if err != nil || account != "account-1" {
		t.Fatalf("account=%q err=%v", account, err)
	}
	// A business role of the same account cannot reach account-wide funds.
	businessScope := authz.Scope{Type: authz.ScopeBusiness, AccountID: "account-1", AccountType: authz.AccountOrganization, BusinessID: "business-1"}
	_, err = invoke(backend, "CreateWithdrawal", issue(func(c *authz.Claims) { c.ActingScope = businessScope }))
	expect("business scope on account funds", err, codes.PermissionDenied)
	account, err = invoke(backend, "GetWithdrawal", issue(func(c *authz.Claims) { c.ActingScope = businessScope; c.Permission = "settlement.record.read" }))
	if err != nil || account != "account-1" {
		t.Fatalf("business-scoped read: account=%q err=%v", account, err)
	}
	_, err = invoke(backend, "CreateWithdrawal", token)
	expect("replayed assertion", err, codes.Unauthenticated)
	_, err = invoke(backend, "CreateWithdrawal", issue(func(c *authz.Claims) { c.Audience = authz.Audience{"payment"} }))
	expect("wrong audience", err, codes.Unauthenticated)
	_, err = invoke(backend, "CreateWithdrawal", issue(func(c *authz.Claims) { c.Permission = "settlement.withdrawal.read" }))
	expect("wrong permission", err, codes.PermissionDenied)
	_, err = invoke(backend, "CreateWithdrawal", issue(func(c *authz.Claims) { c.AMR = []string{"pwd"} }))
	expect("missing MFA", err, codes.PermissionDenied)
	_, err = invoke(backend, "CreateWithdrawal", issue(func(c *authz.Claims) { c.AuthTime = time.Now().Add(-10 * time.Minute).Unix() }))
	expect("stale authentication", err, codes.PermissionDenied)
	_, err = invoke(backend, "CreateWithdrawal", "")
	expect("no assertion", err, codes.Unauthenticated)
	_, err = invoke(payment, "CreateWithdrawal", issue(nil))
	expect("caller outside policy", err, codes.PermissionDenied)
	if _, err = invoke(ledger, "GetWithdrawal", ""); err != nil {
		t.Fatal("service call:", err)
	}
	_, err = invoke(ledger, "GetWithdrawal", issue(func(c *authz.Claims) { c.Permission = "settlement.withdrawal.read" }))
	expect("assertion on a service call", err, codes.PermissionDenied)
	if _, err = invoke(backend, "GetWithdrawal", issue(func(c *authz.Claims) { c.Permission = "settlement.record.read" })); err != nil {
		t.Fatal(err)
	}
	_, err = invoke(ledger, "Undeclared", "")
	expect("undeclared method", err, codes.PermissionDenied)
}
