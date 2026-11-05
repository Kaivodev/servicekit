// Package authztest builds test-only gRPC services whose methods carry
// (aipay.authz.v1.policy) options from the generated SDK, for servicekit's own
// tests. Services declare policies in github.com/Kaivodev/protobuf instead.
package authztest

import (
	"errors"
	"strings"

	authzv1 "github.com/Kaivodev/protobuf/gen/go/aipay/authz/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	NotRequired = authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_NOT_REQUIRED
	Required    = authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_REQUIRED
	MFARecent   = authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_MFA_RECENT
	SingleUse   = authzv1.AssertionRequirement_ASSERTION_REQUIREMENT_SINGLE_USE
)

type Rule struct {
	Callers       []string
	Requirement   authzv1.AssertionRequirement
	Permissions   []string
	MaxAgeSeconds uint32
}

// Policy returns the generated policy message for rules.
func Policy(rules ...Rule) *authzv1.MethodPolicy {
	policy := &authzv1.MethodPolicy{}
	for _, rule := range rules {
		policy.Rules = append(policy.Rules, &authzv1.CallerRule{Callers: rule.Callers, Assertion: rule.Requirement, Permissions: rule.Permissions, RecentAuthMaxAgeSeconds: rule.MaxAgeSeconds})
	}
	return policy
}

// Options returns method options carrying a policy with rules.
func Options(rules ...Rule) *descriptorpb.MethodOptions {
	return WithPolicy(Policy(rules...))
}

// WithPolicy returns method options carrying policy.
func WithPolicy(policy *authzv1.MethodPolicy) *descriptorpb.MethodOptions {
	options := &descriptorpb.MethodOptions{}
	proto.SetExtension(options, authzv1.E_Policy, policy)
	return options
}

// Service builds the service fullName ("package.Service") whose methods take
// and return google.protobuf.Empty. A nil option leaves a method undeclared.
func Service(fullName string, methods map[string]*descriptorpb.MethodOptions) (protoreflect.ServiceDescriptor, error) {
	dot := strings.LastIndex(fullName, ".")
	if dot <= 0 {
		return nil, errors.New("service name must be package-qualified")
	}
	service := &descriptorpb.ServiceDescriptorProto{Name: proto.String(fullName[dot+1:])}
	for method, options := range methods {
		service.Method = append(service.Method, &descriptorpb.MethodDescriptorProto{Name: proto.String(method),
			InputType: proto.String(".google.protobuf.Empty"), OutputType: proto.String(".google.protobuf.Empty"), Options: options})
	}
	built, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String(strings.ReplaceAll(fullName, ".", "/") + ".proto"), Package: proto.String(fullName[:dot]), Syntax: proto.String("proto3"),
		Dependency: []string{"google/protobuf/empty.proto", "aipay/authz/v1/policy.proto"}, Service: []*descriptorpb.ServiceDescriptorProto{service},
	}, protoregistry.GlobalFiles)
	if err != nil {
		return nil, err
	}
	return built.Services().Get(0), nil
}
