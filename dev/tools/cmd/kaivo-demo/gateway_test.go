package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	rec "github.com/Kaivodev/protobuf/gen/go/aipay/reconciliation/v1"
	pr "google.golang.org/protobuf/reflect/protoreflect"
)

func TestGatewayCredentialDigest(t *testing.T) {
	b := credentialBytes(map[string]string{"b": "line\n", "a": "x<&"})
	digest := sha256.Sum256(b)
	if fmt.Sprintf("%x", digest) != "6d6eca2089f7a889f89ee6845013474b55b8c3977fe608635ac5195b3edcd164" {
		t.Fatal("credential contract vector mismatch")
	}
	response := object{"credentials_sha256": b64.EncodeToString(digest[:])}
	verifiedCredentialDigest(response, b)
	expectFailure(t, func() { verifiedCredentialDigest(response, append(b, '\n')) })
}

func TestGatewayUpload(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, filepath.Join(root, "servicekit"), "setup")
	check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=127.0.0.1:9107\n")))
	code := "sim_form_md5"
	head := strings.Repeat("a", 40)
	manifest := []byte(`{"abi_version":3,"build":{"source_commit":"` + head + `"},"code":"sim_form_md5","note":"<&\u000a` + "\u2028" + `","type":"payment"}`)
	wasm := []byte("test component bytes")
	sum := sha256.Sum256(bytes.Join([][]byte{manifest, wasm}, nil))
	pkg := filepath.Join(root, code)
	check(atomic(filepath.Join(pkg, "manifest.json"), manifest))
	check(atomic(filepath.Join(pkg, "plugin.wasm"), wasm))
	check(atomic(filepath.Join(pkg, "fixtures", "query.json"), []byte("{}")))
	d.put("package/"+code, pkg)
	d.put("hash/"+code, fmt.Sprintf("%x", sum))
	m := d.upload(code)
	if !bytes.Equal(raw(str(m, "manifest_json")), manifest) || !bytes.Equal(raw(str(m, "package_sha256")), sum[:]) {
		t.Fatal("upload must preserve the v3 bytes")
	}
	for _, invalid := range [][]byte{
		bytes.Replace(manifest, []byte(head), []byte("uncommitted"), 1),
		bytes.Replace(manifest, []byte(`"abi_version":3`), []byte(`"abi_version":2`), 1),
		append(bytes.Clone(manifest), '\n'),
	} {
		expectFailure(t, func() { gatewayPackage(code, invalid, wasm, "") })
	}
	gatewayPackage(code, bytes.Replace(manifest, []byte(head), []byte(strings.Repeat("b", 64)), 1), wasm, "")
	expectFailure(t, func() { gatewayPackage(code, manifest, wasm, strings.Repeat("c", 40)) })
	check(atomic(filepath.Join(pkg, "plugin.wasm"), append(wasm, 0)))
	expectFailure(t, func() { d.upload(code) })
}

func TestGatewayApprovalDigestPresence(t *testing.T) {
	for _, desc := range []pr.MessageDescriptor{
		(&pay.ChannelAccountConfiguration{}).ProtoReflect().Descriptor(),
		(&rec.VerificationAccountConfiguration{}).ProtoReflect().Descriptor(),
	} {
		t.Run(string(desc.Name()), func(t *testing.T) {
			m := object{"enabled": false, "priority": 0, "weight": 0, "min_amount_fiat_minor": "1",
				"max_amount_fiat_minor": "2", "daily_limit_fiat_minor": "3", "callback_source_cidrs": []any{"127.0.0.1/32"}}
			legacy := materialBytes(nil, desc, m)
			digest := bytes.Repeat([]byte{42}, 32)
			m["credentials_sha256"] = b64.EncodeToString(digest)
			if desc.Fields().ByName("credentials_sha256") == nil {
				expectFailure(t, func() { materialBytes(nil, desc, m) })
				return
			}
			want := append(legacy, 1, 0, 0, 0, 32)
			if !bytes.Equal(materialBytes(nil, desc, m), append(want, digest...)) {
				t.Fatal("credentials_sha256 must follow the complete historical encoding")
			}
		})
	}
}
