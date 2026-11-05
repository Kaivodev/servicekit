// Package authz enforces per-method authorization policies on the server: the
// (aipay.authz.v1.policy) option of each RPC names the allowed callers and the
// IAM identity assertion each caller must present. Methods without a policy
// and callers matching no rule are denied. Verified results reach handlers as
// a read-only Call in the context; handlers may narrow them, never widen them.
package authz

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	authzv1 "github.com/Kaivodev/protobuf/gen/go/aipay/authz/v1"
	"github.com/Kaivodev/servicekit/config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// MaxRecentAuth bounds a rule's recent authentication window.
const MaxRecentAuth = time.Hour

// Requirement is the identity assertion a caller must present. Each level
// includes every check of the levels before it.
type Requirement int

const (
	// NotRequired admits a service call on the verified mTLS identity alone and
	// rejects requests that carry an assertion anyway.
	NotRequired Requirement = iota + 1
	// Required needs a valid assertion with one of the rule's permissions.
	Required
	// MFARecent additionally needs "mfa" in amr and a recent auth_time.
	MFARecent
	// SingleUse additionally consumes the assertion's jti.
	SingleUse
)

func (r Requirement) String() string {
	switch r {
	case NotRequired:
		return "not_required"
	case Required:
		return "required"
	case MFARecent:
		return "mfa_recent"
	case SingleUse:
		return "single_use"
	}
	return "invalid"
}

type Rule struct {
	Callers          []string
	Requirement      Requirement
	Permissions      []string
	RecentAuthMaxAge time.Duration
}

// Policy is the parsed option of one method, keyed by its gRPC full method
// name ("/package.Service/Method").
type Policy struct {
	Method string
	Rules  []Rule
}

// Policies is immutable after LoadPolicies.
type Policies struct{ byMethod map[string]Policy }

var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

var requirements = map[authzv1.AssertionRequirement]Requirement{
	authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_NOT_REQUIRED: NotRequired,
	authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_REQUIRED:     Required,
	authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_MFA_RECENT:   MFARecent,
	authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_SINGLE_USE:   SingleUse,
}

// LoadPolicies reads the (aipay.authz.v1.policy) option of every method of
// services, typically taken from the generated SDK, e.g.
// eventsv1.File_aipay_events_v1_event_stream_proto.Services().ByName(...).
// Any method without a valid policy is an error, so a server never starts
// with an undeclared method.
func LoadPolicies(services ...protoreflect.ServiceDescriptor) (Policies, error) {
	if len(services) == 0 {
		return Policies{}, errors.New("authorization policies require at least one service")
	}
	result := Policies{byMethod: map[string]Policy{}}
	for _, service := range services {
		methods := service.Methods()
		for i := 0; i < methods.Len(); i++ {
			method := methods.Get(i)
			name := fmt.Sprintf("/%s/%s", service.FullName(), method.Name())
			if _, exists := result.byMethod[name]; exists {
				return Policies{}, fmt.Errorf("%s: service listed twice", name)
			}
			policy, err := parsePolicy(method)
			if err != nil {
				return Policies{}, fmt.Errorf("%s: %w", name, err)
			}
			policy.Method = name
			result.byMethod[name] = policy
		}
	}
	return result, nil
}

// Lookup returns a copy of the policy of fullMethod.
func (p Policies) Lookup(fullMethod string) (Policy, bool) {
	policy, ok := p.byMethod[fullMethod]
	if !ok {
		return Policy{}, false
	}
	rules := make([]Rule, len(policy.Rules))
	for i, rule := range policy.Rules {
		rules[i] = Rule{Callers: append([]string(nil), rule.Callers...), Requirement: rule.Requirement, Permissions: append([]string(nil), rule.Permissions...), RecentAuthMaxAge: rule.RecentAuthMaxAge}
	}
	return Policy{Method: policy.Method, Rules: rules}, true
}

func (p Policies) each(visit func(Policy)) {
	for _, policy := range p.byMethod {
		visit(policy)
	}
}

// Rule returns the rule admitting caller, if any.
func (p Policy) Rule(caller string) (Rule, bool) {
	for _, rule := range p.Rules {
		for _, allowed := range rule.Callers {
			if allowed == caller {
				return rule, true
			}
		}
	}
	return Rule{}, false
}

// Fields this version enforces. A newer SDK may add policy fields; a policy
// that populates one fails to load rather than being enforced partially.
var (
	policyFields = map[protoreflect.Name]bool{"rules": true}
	ruleFields   = map[protoreflect.Name]bool{"callers": true, "assertion": true, "permissions": true, "recent_auth_max_age_seconds": true}
)

func onlyKnownFields(m protoreflect.Message, known map[protoreflect.Name]bool) error {
	var unknown error
	m.Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if !known[field.Name()] {
			unknown = fmt.Errorf("policy field %s is not enforced by this servicekit version", field.Name())
			return false
		}
		return true
	})
	if unknown == nil && len(m.GetUnknown()) != 0 {
		unknown = errors.New("policy carries unknown fields")
	}
	return unknown
}

func parsePolicy(method protoreflect.MethodDescriptor) (Policy, error) {
	options := method.Options()
	if options == nil || !proto.HasExtension(options, authzv1.E_Policy) {
		return Policy{}, errors.New("no (aipay.authz.v1.policy) declared")
	}
	message, ok := proto.GetExtension(options, authzv1.E_Policy).(*authzv1.MethodPolicy)
	if !ok || message == nil {
		return Policy{}, errors.New("unreadable policy option")
	}
	if err := onlyKnownFields(message.ProtoReflect(), policyFields); err != nil {
		return Policy{}, err
	}
	if len(message.GetRules()) == 0 {
		return Policy{}, errors.New("policy has no caller rules")
	}
	var policy Policy
	seen := map[string]bool{}
	for i, declared := range message.GetRules() {
		rule, err := parseRule(declared, seen)
		if err != nil {
			return Policy{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
		policy.Rules = append(policy.Rules, rule)
	}
	return policy, nil
}

func parseRule(declared *authzv1.CallerRule, seen map[string]bool) (Rule, error) {
	if err := onlyKnownFields(declared.ProtoReflect(), ruleFields); err != nil {
		return Rule{}, err
	}
	requirement, ok := requirements[declared.GetAssertion()]
	if !ok {
		return Rule{}, errors.New("assertion requirement must be declared")
	}
	rule := Rule{Callers: append([]string(nil), declared.GetCallers()...), Requirement: requirement,
		Permissions: append([]string(nil), declared.GetPermissions()...), RecentAuthMaxAge: time.Duration(declared.GetRecentAuthMaxAgeSeconds()) * time.Second}
	if len(rule.Callers) == 0 {
		return Rule{}, errors.New("no callers")
	}
	for _, caller := range rule.Callers {
		if !config.ValidService(caller) || seen[caller] {
			return Rule{}, errors.New("callers must be unique service names")
		}
		seen[caller] = true
	}
	unique := map[string]bool{}
	for _, permission := range rule.Permissions {
		if !permissionPattern.MatchString(permission) || unique[permission] {
			return Rule{}, errors.New("permissions must be unique catalog keys")
		}
		unique[permission] = true
	}
	switch {
	case requirement == NotRequired && (len(rule.Permissions) != 0 || rule.RecentAuthMaxAge != 0):
		return Rule{}, errors.New("a service call takes no permissions or recent authentication window")
	case requirement >= Required && len(rule.Permissions) == 0:
		return Rule{}, errors.New("an assertion requirement needs acceptable permissions")
	case requirement == Required && rule.RecentAuthMaxAge != 0:
		return Rule{}, errors.New("a recent authentication window needs MFA_RECENT or SINGLE_USE")
	case requirement >= MFARecent && (rule.RecentAuthMaxAge <= 0 || rule.RecentAuthMaxAge > MaxRecentAuth):
		return Rule{}, errors.New("recent authentication window must be between 1 and 3600 seconds")
	}
	return rule, nil
}
