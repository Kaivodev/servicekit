package authz

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Kaivodev/servicekit/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// healthPrefix is servicekit's own readiness service. Its callers are limited
// by the mTLS peer allowlist and it carries no business data.
const healthPrefix = "/grpc.health.v1.Health/"

// ErrReplayed is returned by a ReplayGuard for an already consumed jti.
var ErrReplayed = errors.New("identity assertion was already used")

// Use identifies one consumption of a single-use assertion.
type Use struct {
	ID        string
	Method    string
	Subject   string
	ExpiresAt time.Time
}

// ReplayGuard records single-use assertion IDs durably, e.g. in the service's
// <p>_used_assertions table, and returns ErrReplayed for a reused ID.
type ReplayGuard interface {
	Consume(ctx context.Context, use Use) error
}

type Options struct {
	// Service is the local service name; assertions must name it in aud.
	Service  string
	Policies Policies
	// Peer returns the verified mTLS service identity, e.g. mtls.Material.Peer.
	Peer func(context.Context) (string, error)
	// Assertions is required when any rule needs an assertion.
	Assertions *AssertionVerifier
	// Replay is required when any rule is SingleUse.
	Replay ReplayGuard
	// Log receives one warning per denial with a stable reason, never tokens.
	Log *slog.Logger
	Now func() time.Time
}

type Authorizer struct{ options Options }

func New(options Options) (*Authorizer, error) {
	if !config.ValidService(options.Service) || options.Peer == nil || options.Log == nil || options.Policies.byMethod == nil {
		return nil, errors.New("authorizer requires a service, policies, peer verifier and logger")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	var problem error
	options.Policies.each(func(policy Policy) {
		for _, rule := range policy.Rules {
			switch {
			case rule.Requirement >= Required && options.Assertions == nil:
				problem = errors.New(policy.Method + " requires identity assertions but no verifier is configured")
			case rule.Requirement >= Required && options.Assertions.cfg.Audience != options.Service:
				problem = errors.New("assertion verifier audience differs from the service")
			case rule.Requirement == SingleUse && options.Replay == nil:
				problem = errors.New(policy.Method + " requires single-use assertions but no replay guard is configured")
			}
		}
	})
	if problem != nil {
		return nil, problem
	}
	return &Authorizer{options: options}, nil
}

type contextKey struct{}

// Call is the verified, read-only authorization result for one RPC.
type Call struct {
	method      string
	caller      string
	requirement Requirement
	assertion   *Assertion
}

func (c Call) Method() string           { return c.method }
func (c Call) Caller() string           { return c.caller }
func (c Call) Requirement() Requirement { return c.requirement }

// Assertion returns the verified IAM assertion; absent for service calls.
// Business subject, organization and merchant application come from here,
// never from request fields.
func (c Call) Assertion() (*Assertion, bool) { return c.assertion, c.assertion != nil }

// Scope returns the verified acting scope; absent for service calls.
func (c Call) Scope() (Scope, bool) {
	if c.assertion == nil {
		return Scope{}, false
	}
	return c.assertion.ActingScope(), true
}

// Account returns the trusted funds account of the call: the account of an
// account, business or application scope, or the one target account IAM
// bound a platform call to. Use it to filter account resources; methods that
// act on account-wide funds must also RequireScope(ScopeAccount).
func (c Call) Account() (Account, bool) {
	scope, ok := c.Scope()
	if !ok {
		return Account{}, false
	}
	return scope.Account()
}

// RequireScope returns the acting scope when its type is one of types and a
// PermissionDenied error otherwise, including for service calls. Balances,
// address books and withdrawals require ScopeAccount, so a business or
// application role never reaches account-wide funds through a shared account.
func (c Call) RequireScope(types ...string) (Scope, error) {
	scope, ok := c.Scope()
	if ok {
		for _, allowed := range types {
			if scope.Type == allowed {
				return scope, nil
			}
		}
	}
	return Scope{}, status.Error(codes.PermissionDenied, "Acting scope is not accepted by this method")
}

// FromContext returns the Call stored by the interceptor.
func FromContext(ctx context.Context) (Call, bool) {
	call, ok := ctx.Value(contextKey{}).(Call)
	return call, ok
}

type rejection struct {
	code    codes.Code
	reason  string
	message string
}

var (
	errService     = rejection{codes.Unauthenticated, "peer_unverified", "Service authentication required"}
	errNoPolicy    = rejection{codes.PermissionDenied, "policy_missing", "Caller is not authorized for this method"}
	errCaller      = rejection{codes.PermissionDenied, "caller_not_allowed", "Caller is not authorized for this method"}
	errUnexpected  = rejection{codes.PermissionDenied, "assertion_unexpected", "Identity assertion is not accepted by this method"}
	errMissing     = rejection{codes.Unauthenticated, "assertion_missing", "Identity assertion required"}
	errPermission  = rejection{codes.PermissionDenied, "permission_not_accepted", "Permission is not accepted by this method"}
	errMFA         = rejection{codes.PermissionDenied, "mfa_required", "Multi-factor authentication required"}
	errRecentAuth  = rejection{codes.PermissionDenied, "recent_auth_required", "Recent authentication required"}
	errReplayed    = rejection{codes.Unauthenticated, "assertion_replayed", "Invalid identity assertion"}
	errReplayStore = rejection{codes.Unavailable, "replay_guard_unavailable", "Authorization is temporarily unavailable"}
)

const invalidMessage = "Invalid identity assertion"

// withoutAssertion keeps handlers from logging or forwarding the raw token.
func withoutAssertion(md metadata.MD) metadata.MD {
	md = md.Copy()
	md.Delete(MetadataKey)
	return md
}

// authorize returns the context handed to the handler: it carries the Call and
// no longer carries the raw assertion metadata.
func (a *Authorizer) authorize(ctx context.Context, method string) (context.Context, error) {
	caller, err := a.options.Peer(ctx)
	if err != nil {
		return nil, a.reject(ctx, method, "", errService)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get(MetadataKey)
	if strings.HasPrefix(method, healthPrefix) {
		if len(values) != 0 {
			return nil, a.reject(ctx, method, caller, errUnexpected)
		}
		return context.WithValue(ctx, contextKey{}, Call{method: method, caller: caller, requirement: NotRequired}), nil
	}
	policy, ok := a.options.Policies.byMethod[method]
	if !ok {
		return nil, a.reject(ctx, method, caller, errNoPolicy)
	}
	rule, ok := policy.Rule(caller)
	if !ok {
		return nil, a.reject(ctx, method, caller, errCaller)
	}
	call := Call{method: method, caller: caller, requirement: rule.Requirement}
	if rule.Requirement == NotRequired {
		if len(values) != 0 {
			return nil, a.reject(ctx, method, caller, errUnexpected)
		}
		return context.WithValue(ctx, contextKey{}, call), nil
	}
	if len(values) != 1 {
		return nil, a.reject(ctx, method, caller, errMissing)
	}
	assertion, err := a.options.Assertions.Verify(values[0])
	if err != nil {
		reason := "assertion_invalid"
		var denial *Denial
		if errors.As(err, &denial) {
			reason = denial.Reason
		}
		return nil, a.reject(ctx, method, caller, rejection{codes.Unauthenticated, reason, invalidMessage})
	}
	if !slices.Contains(rule.Permissions, assertion.Permission()) {
		return nil, a.reject(ctx, method, caller, errPermission)
	}
	if rule.Requirement >= MFARecent {
		if !assertion.MFA() {
			return nil, a.reject(ctx, method, caller, errMFA)
		}
		authTime, now := assertion.AuthTime(), a.options.Now()
		if authTime.IsZero() || now.Sub(authTime) > rule.RecentAuthMaxAge || authTime.After(now.Add(a.options.Assertions.cfg.Leeway)) {
			return nil, a.reject(ctx, method, caller, errRecentAuth)
		}
	}
	if rule.Requirement == SingleUse {
		err = a.options.Replay.Consume(ctx, Use{ID: assertion.ID(), Method: method, Subject: assertion.Subject(), ExpiresAt: assertion.ExpiresAt()})
		if errors.Is(err, ErrReplayed) {
			return nil, a.reject(ctx, method, caller, errReplayed)
		}
		if err != nil {
			return nil, a.reject(ctx, method, caller, errReplayStore)
		}
	}
	call.assertion = assertion
	ctx = metadata.NewIncomingContext(ctx, withoutAssertion(md))
	return context.WithValue(ctx, contextKey{}, call), nil
}

func (a *Authorizer) reject(ctx context.Context, method, caller string, r rejection) error {
	a.options.Log.WarnContext(ctx, "rpc authorization denied", "method", method, "peer_service", caller, "reason", r.reason, "code", r.code.String())
	return status.Error(r.code, r.message)
}

func (a *Authorizer) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		authorized, err := a.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(authorized, req)
	}
}

type authorizedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authorizedStream) Context() context.Context { return s.ctx }

func (a *Authorizer) Stream() grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authorized, err := a.authorize(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(server, &authorizedStream{ServerStream: stream, ctx: authorized})
	}
}

// DenyUndeclared is the fallback when a server has no Authorizer: only the
// health service is reachable, every other method is PermissionDenied.
func DenyUndeclared() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	denied := status.Error(codes.PermissionDenied, "Caller is not authorized for this method")
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if !strings.HasPrefix(info.FullMethod, healthPrefix) {
				return nil, denied
			}
			return handler(ctx, req)
		}, func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if !strings.HasPrefix(info.FullMethod, healthPrefix) {
				return denied
			}
			return handler(server, stream)
		}
}
