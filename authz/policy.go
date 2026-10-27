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

	"github.com/aipay-dev/servicekit/config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// PolicyExtension is the full name of the method option defined in
// github.com/aipay-dev/protobuf (aipay/authz/v1/policy.proto).
const PolicyExtension = "aipay.authz.v1.policy"

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

// enum numbers of aipay.authz.v1.AssertionRequirement
var requirements = map[protoreflect.EnumNumber]Requirement{1: NotRequired, 2: Required, 3: MFARecent, 4: SingleUse}

// LoadPolicies reads the policy option of every method of services. extension
// must be the generated aipay.authz.v1 E_Policy type; passing it explicitly
// keeps registration visible in the composition root. Any method without a
// valid policy is an error, so a server never starts with an undeclared method.
func LoadPolicies(extension protoreflect.ExtensionType, services ...protoreflect.ServiceDescriptor) (Policies, error) {
	if extension == nil || extension.TypeDescriptor().FullName() != PolicyExtension || extension.TypeDescriptor().Message() == nil {
		return Policies{}, errors.New("authorization policies require the " + PolicyExtension + " extension type")
	}
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
			policy, err := parsePolicy(extension, method)
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

var (
	policyFields = map[protoreflect.Name]bool{"rules": true}
	ruleFields   = map[protoreflect.Name]bool{"callers": true, "assertion": true, "permissions": true, "recent_auth_max_age_seconds": true}
)

// onlyKnownFields fails closed when a newer contract populates a field this
// version cannot enforce.
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

func field(m protoreflect.Message, name protoreflect.Name, kind protoreflect.Kind, list bool) (protoreflect.FieldDescriptor, error) {
	fd := m.Descriptor().Fields().ByName(name)
	if fd == nil || fd.Kind() != kind || fd.IsList() != list {
		return nil, fmt.Errorf("policy schema lacks %s", name)
	}
	return fd, nil
}

func stringList(m protoreflect.Message, name protoreflect.Name) ([]string, error) {
	fd, err := field(m, name, protoreflect.StringKind, true)
	if err != nil {
		return nil, err
	}
	list := m.Get(fd).List()
	values := make([]string, list.Len())
	for i := range values {
		values[i] = list.Get(i).String()
	}
	return values, nil
}

func parsePolicy(extension protoreflect.ExtensionType, method protoreflect.MethodDescriptor) (Policy, error) {
	options := method.Options()
	if options == nil || !proto.HasExtension(options, extension) {
		return Policy{}, errors.New("no " + PolicyExtension + " declared")
	}
	value, ok := proto.GetExtension(options, extension).(proto.Message)
	if !ok {
		return Policy{}, errors.New("unreadable policy option")
	}
	message := value.ProtoReflect()
	if err := onlyKnownFields(message, policyFields); err != nil {
		return Policy{}, err
	}
	rulesField, err := field(message, "rules", protoreflect.MessageKind, true)
	if err != nil {
		return Policy{}, err
	}
	list := message.Get(rulesField).List()
	if list.Len() == 0 {
		return Policy{}, errors.New("policy has no caller rules")
	}
	var policy Policy
	seen := map[string]bool{}
	for i := 0; i < list.Len(); i++ {
		rule, err := parseRule(list.Get(i).Message(), seen)
		if err != nil {
			return Policy{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
		policy.Rules = append(policy.Rules, rule)
	}
	return policy, nil
}

func parseRule(m protoreflect.Message, seen map[string]bool) (Rule, error) {
	if err := onlyKnownFields(m, ruleFields); err != nil {
		return Rule{}, err
	}
	var rule Rule
	var err error
	if rule.Callers, err = stringList(m, "callers"); err != nil {
		return Rule{}, err
	}
	if rule.Permissions, err = stringList(m, "permissions"); err != nil {
		return Rule{}, err
	}
	assertion, err := field(m, "assertion", protoreflect.EnumKind, false)
	if err != nil {
		return Rule{}, err
	}
	maxAge, err := field(m, "recent_auth_max_age_seconds", protoreflect.Uint32Kind, false)
	if err != nil {
		return Rule{}, err
	}
	requirement, ok := requirements[m.Get(assertion).Enum()]
	if !ok {
		return Rule{}, errors.New("assertion requirement must be declared")
	}
	rule.Requirement = requirement
	rule.RecentAuthMaxAge = time.Duration(m.Get(maxAge).Uint()) * time.Second
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
