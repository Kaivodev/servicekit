// Package authztest builds (aipay.authz.v1.policy) descriptors at runtime for
// servicekit's own tests and test-only RPCs. Services use the generated
// protobuf SDK instead; this package mirrors its names and field numbers.
package authztest

import (
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// AssertionRequirement values of aipay.authz.v1.AssertionRequirement.
const (
	NotRequired int32 = 1
	Required    int32 = 2
	MFARecent   int32 = 3
	SingleUse   int32 = 4
)

type Rule struct {
	Callers       []string
	Requirement   int32
	Permissions   []string
	MaxAgeSeconds uint32
}

type Schema struct {
	// Extension stands in for the generated authzv1.E_Policy.
	Extension protoreflect.ExtensionType
	file      protoreflect.FileDescriptor
	policy    protoreflect.MessageDescriptor
	rule      protoreflect.MessageDescriptor
}

func policyFile() *descriptorpb.FileDescriptorProto {
	repeated, optional := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(), descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	field := func(name, json string, number int32, label *descriptorpb.FieldDescriptorProto_Label, kind descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), JsonName: proto.String(json), Number: proto.Int32(number), Label: label, Type: kind.Enum()}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	enum := &descriptorpb.EnumDescriptorProto{Name: proto.String("AssertionRequirement")}
	for i, name := range []string{"UNSPECIFIED", "NOT_REQUIRED", "REQUIRED", "MFA_RECENT", "SINGLE_USE"} {
		enum.Value = append(enum.Value, &descriptorpb.EnumValueDescriptorProto{Name: proto.String("ASSERTION_REQUIREMENT_" + name), Number: proto.Int32(int32(i))})
	}
	extension := field("policy", "policy", 51000, optional, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".aipay.authz.v1.MethodPolicy")
	extension.Extendee = proto.String(".google.protobuf.MethodOptions")
	return &descriptorpb.FileDescriptorProto{
		Name: proto.String("aipay/authz/v1/policy.proto"), Package: proto.String("aipay.authz.v1"), Syntax: proto.String("proto3"),
		Dependency: []string{"google/protobuf/descriptor.proto"}, EnumType: []*descriptorpb.EnumDescriptorProto{enum},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("MethodPolicy"), Field: []*descriptorpb.FieldDescriptorProto{
				field("rules", "rules", 1, repeated, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".aipay.authz.v1.CallerRule"),
			}},
			{Name: proto.String("CallerRule"), Field: []*descriptorpb.FieldDescriptorProto{
				field("callers", "callers", 1, repeated, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
				field("assertion", "assertion", 2, optional, descriptorpb.FieldDescriptorProto_TYPE_ENUM, ".aipay.authz.v1.AssertionRequirement"),
				field("permissions", "permissions", 3, repeated, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
				field("recent_auth_max_age_seconds", "recentAuthMaxAgeSeconds", 4, optional, descriptorpb.FieldDescriptorProto_TYPE_UINT32, ""),
			}},
		},
		Extension: []*descriptorpb.FieldDescriptorProto{extension},
	}
}

func NewSchema() (*Schema, error) {
	files := new(protoregistry.Files)
	if err := files.RegisterFile(descriptorpb.File_google_protobuf_descriptor_proto); err != nil {
		return nil, err
	}
	file, err := protodesc.NewFile(policyFile(), files)
	if err != nil {
		return nil, err
	}
	return &Schema{Extension: dynamicpb.NewExtensionType(file.Extensions().ByName("policy")), file: file,
		policy: file.Messages().ByName("MethodPolicy"), rule: file.Messages().ByName("CallerRule")}, nil
}

// Policy returns the extension value for rules, as a mutable message.
func (s *Schema) Policy(rules ...Rule) protoreflect.Message {
	policy := dynamicpb.NewMessage(s.policy)
	list := policy.Mutable(s.policy.Fields().ByName("rules")).List()
	fields := s.rule.Fields()
	for _, spec := range rules {
		rule := dynamicpb.NewMessage(s.rule)
		callers := rule.Mutable(fields.ByName("callers")).List()
		for _, caller := range spec.Callers {
			callers.Append(protoreflect.ValueOfString(caller))
		}
		permissions := rule.Mutable(fields.ByName("permissions")).List()
		for _, permission := range spec.Permissions {
			permissions.Append(protoreflect.ValueOfString(permission))
		}
		rule.Set(fields.ByName("assertion"), protoreflect.ValueOfEnum(protoreflect.EnumNumber(spec.Requirement)))
		if spec.MaxAgeSeconds != 0 {
			rule.Set(fields.ByName("recent_auth_max_age_seconds"), protoreflect.ValueOfUint32(spec.MaxAgeSeconds))
		}
		list.Append(protoreflect.ValueOfMessage(rule))
	}
	return policy
}

// Options returns method options carrying a policy with rules.
func (s *Schema) Options(rules ...Rule) *descriptorpb.MethodOptions {
	options := &descriptorpb.MethodOptions{}
	proto.SetExtension(options, s.Extension, s.Policy(rules...).Interface())
	return options
}

// Service builds the service fullName ("package.Service") whose methods take
// and return google.protobuf.Empty. A nil option leaves a method undeclared.
func (s *Schema) Service(fullName string, methods map[string]*descriptorpb.MethodOptions) (protoreflect.ServiceDescriptor, error) {
	dot := strings.LastIndex(fullName, ".")
	if dot <= 0 {
		return nil, errors.New("service name must be package-qualified")
	}
	service := &descriptorpb.ServiceDescriptorProto{Name: proto.String(fullName[dot+1:])}
	for method, options := range methods {
		service.Method = append(service.Method, &descriptorpb.MethodDescriptorProto{Name: proto.String(method),
			InputType: proto.String(".google.protobuf.Empty"), OutputType: proto.String(".google.protobuf.Empty"), Options: options})
	}
	files := new(protoregistry.Files)
	empty, err := protoregistry.GlobalFiles.FindFileByPath("google/protobuf/empty.proto")
	if err != nil {
		return nil, err
	}
	for _, file := range []protoreflect.FileDescriptor{descriptorpb.File_google_protobuf_descriptor_proto, empty, s.file} {
		if err := files.RegisterFile(file); err != nil {
			return nil, err
		}
	}
	built, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String(strings.ReplaceAll(fullName, ".", "/") + ".proto"), Package: proto.String(fullName[:dot]), Syntax: proto.String("proto3"),
		Dependency: []string{"google/protobuf/empty.proto", "aipay/authz/v1/policy.proto"}, Service: []*descriptorpb.ServiceDescriptorProto{service},
	}, files)
	if err != nil {
		return nil, err
	}
	return built.Services().Get(0), nil
}
