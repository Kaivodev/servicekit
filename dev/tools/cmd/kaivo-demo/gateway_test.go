package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			withCredentials := append(want, digest...)
			if !bytes.Equal(materialBytes(nil, desc, m), withCredentials) {
				t.Fatal("credentials_sha256 must follow the complete historical encoding")
			}
			if desc.Name() == "ChannelAccountConfiguration" {
				m["payment_instruction_ttl_seconds"] = 300
				if !bytes.Equal(materialBytes(nil, desc, m), append(withCredentials, 1, 0, 0, 1, 44)) {
					t.Fatal("instruction TTL must follow the credential digest as a present uint32")
				}
			}
		})
	}
}

func TestEPayPackages(t *testing.T) {
	const head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, p := range []struct{ code, world, version, older string }{
		{"epay_v1", "payment", "0.3.0", "0.2.99"},
		{"epay_v1_verify", "verification", "0.2.0", "0.1.99"},
	} {
		t.Run(p.code, func(t *testing.T) {
			m := object{"type": p.world, "abi_version": 3, "code": p.code, "build": object{"source_commit": head},
				"config": object{"unpaid_timeout_seconds": object{"required": true, "type": "string"}}}
			validate := func() { gatewayPackage(p.code, encoded(m), []byte{1}, head) }
			for _, version := range []string{p.version, "0.10.0", "1.0.0"} {
				m["version"] = version
				validate()
			}
			for _, version := range []string{p.older, "1.0.0-alpha", p.version + "+build.1", "invalid", "0.4"} {
				m["version"] = version
				expectFailure(t, validate)
			}
			m["version"] = p.version
			m["type"] = "other"
			expectFailure(t, validate)
			m["type"] = p.world
			delete(m, "config")
			expectFailure(t, validate)
		})
	}
	if pluginWorld("another_verify") != "verification" || pluginWorld("verify_payment") != "payment" {
		t.Fatal("world must follow the _verify suffix")
	}
}

func TestVersionAtLeast(t *testing.T) {
	const minimum = "2.10.9"
	for _, v := range []string{minimum, "2.10.10", "2.11.0", "10.0.0", "18446744073709551616.0.0"} {
		if !versionAtLeast(v, minimum) {
			t.Errorf("rejected %q", v)
		}
	}
	for _, v := range []string{"1.99.99", "2.9.99", "2.10.8", "02.11.0", "3.01.0", "3.0.00",
		"", "3.0", "3.0.0.0", "3.0.", "v3.0.0", "+3.0.0", "3.0.0\n", "3.０.0", "3.0.0-rc.1", "3.0.0+build"} {
		if versionAtLeast(v, minimum) {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestGatewayPrebuiltPackages(t *testing.T) {
	root := t.TempDir()
	packages := filepath.Join(root, "packages")
	t.Setenv("KAIVO_DEMO_PLUGIN_PACKAGES", packages)
	check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=127.0.0.1:9107\n")))
	codes := []string{"sim_form_md5", "sim_form_md5_verify", "epay_v1", "epay_v1_verify"}
	for _, code := range codes {
		path := filepath.Join(packages, code)
		m := object{"abi_version": 3, "build": object{"source_commit": strings.Repeat("b", 40)}, "code": code,
			"version": "0.3.0", "type": pluginWorld(code), "config": object{"unpaid_timeout_seconds": object{"type": "string", "required": true}}}
		check(atomic(filepath.Join(path, "manifest.json"), encoded(m)))
		check(atomic(filepath.Join(path, "plugin.wasm"), []byte("test component")))
		check(atomic(filepath.Join(path, "fixtures", "query.json"), []byte("{}")))
	}
	d := newDriver(root, filepath.Join(root, "servicekit"), "setup")
	d.packages()
	for _, code := range codes {
		if d.required("package/"+code) != filepath.Join(packages, code) || len(d.required("hash/"+code)) != 64 {
			t.Fatalf("missing package or digest for %s", code)
		}
	}
	check(os.Remove(filepath.Join(packages, "epay_v1_verify", "manifest.json")))
	expectFailure(t, d.packages)
}

func TestDemoOrderRouting(t *testing.T) {
	for _, group := range []struct {
		names, amount, channel, sim string
	}{
		{"main duplicates dispute seller-offline bot-notices statement archived-work cancel k-query-transient k-ledger-cancel-event dispute-return", "2.00", "epay_v1", "epay-demo"},
		{"refund-insufficient refund-before-release refund-after-release dispute-refund-before-release dispute-refund-after-release manual-refund manual-refund-failure late-payment dispute-return-paid", "1.00", "sim_form_md5", "md5-demo"},
	} {
		for _, name := range strings.Fields(group.names) {
			if scenarios[name] == nil {
				t.Fatalf("unregistered scenario %s", name)
			}
			for _, gateway := range []bool{true, false} {
				channel, sim := group.channel, group.sim
				if !gateway {
					channel, sim = "sim_form_md5", "md5-demo"
				}
				amount, code := scenarioOrder(name, gateway)
				if amount != group.amount || code != channel || simulatorAccount(code) != sim {
					t.Errorf("%s (gateway=%v): got %s %s", name, gateway, amount, code)
				}
			}
		}
	}
	expectFailure(t, func() { simulatorAccount("unrecognized") })
}

func TestEPayTimeout(t *testing.T) {
	for ttl, want := range map[string]int64{"": 4200, "10m": 4200, "1s": 3601, "1.000001s": 3602, "2h30m": 12600, "24h": 90000} {
		if got := unpaidTimeoutSeconds(ttl); got != want {
			t.Errorf("ttl %q: got %d, want %d", ttl, got, want)
		}
	}
	for _, v := range []string{"600", "500ms", "1.0000001s", "24h1s"} {
		expectFailure(t, func() { unpaidTimeoutSeconds(v) })
	}
}

func TestChannelSetupAndWitness(t *testing.T) {
	const address = "http://127.0.0.1:9080"
	md5 := channelSetup(md5Channel, true, address, "")
	epay := channelSetup(epayChannel, true, address, "4200")
	if md5.minAmount != "1" || md5.maxAmount != "100" || epay.minAmount != "101" || epay.maxAmount != "10000000" ||
		channelSetup(md5Channel, false, address, "").maxAmount != "10000000" {
		t.Fatal("incorrect routing limits")
	}
	if epay.queryConfig["gateway"] != address || epay.queryConfig["pid"] != "1001" || epay.queryConfig["unpaid_timeout_seconds"] != "4200" ||
		len(epay.queryConfig) != 3 || epay.tradeConfig["product_name"] == nil || len(epay.tradeConfig) != 4 ||
		epay.tradeFile != epay.queryFile || md5.tradeFile == md5.queryFile {
		t.Fatal("incorrect EPay or form-md5 configuration")
	}
	if md5.tradeKey != "shared" || md5.queryKey != "query_key" || epay.tradeKey != "merchant_key" || epay.queryKey != "merchant_key" {
		t.Fatal("credential fields must match the four plugin manifests")
	}
	sim := []byte(`{"accounts":[{"id":"md5-demo","shared_secret":"trade","query_shared_secret":"query"},{"id":"epay-demo","shared_secret":"epay"}]}`)
	if epay.witnessSource(epayChannel, map[string]string{"merchant_key": "epay"}, sim) != "upstream-sim/epay-demo/shared_secret" ||
		md5.witnessSource(md5Channel, map[string]string{"query_key": "query"}, sim) != "upstream-sim/md5-demo/query_shared_secret" {
		t.Fatal("incorrect witness source")
	}
	expectFailure(t, func() { epay.witnessSource(epayChannel, map[string]string{"merchant_key": "trade"}, sim) })
	expectFailure(t, func() { epay.witnessSource(epayChannel, map[string]string{"shared": "epay"}, sim) })
	expectFailure(t, func() {
		md5.witnessSource(md5Channel, map[string]string{"query_key": "trade"}, bytes.ReplaceAll(sim, []byte(`"query"`), []byte(`"trade"`)))
	})
}

func TestResumeMD5ChannelSetup(t *testing.T) {
	for _, limit := range []string{"10000000", "100"} {
		t.Run(limit, func(t *testing.T) {
			root := t.TempDir()
			d := newDriver(root, "", "setup")
			reviews := filepath.Join(root, "reviews.json")
			check(atomic(reviews, encoded([]object{{"seller_account_id": "seller", "review_sha256": strings.Repeat("01", 32)}})))
			check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=127.0.0.1:9107\nAIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE="+reviews+"\n")))
			for _, step := range []string{"双批发布 sim_form_md5", "双批发布 sim_form_md5_verify", "交易凭据", "支付方式",
				"卖方通道绑定", "定价 channel", "定价 merchant", "风控", "支付插件绑定", "通道启用", "独立只读凭据见证", "核验账户与启用"} {
				d.put("step/setup/"+step, result{Name: step, Status: "ok"})
			}
			d.put("uuid/channel", "original")
			d.put("seller-account", "seller")
			d.put("trade-ref", "existing-ref")
			d.put("trade-digest", "existing-digest")
			d.put("user/operations", "operator")
			d.put("session-until/operations", time.Now().Add(time.Hour))
			op := d.browser("operations")
			op.cookies["__Host-kaivo_platform_session"] = "test-session"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + strings.TrimPrefix(r.URL.Path, op.prefix) {
				case "GET /channel-accounts/original":
					fmt.Fprintf(w, `{"code":200,"data":{"configuration":{"channel_code":"sim_form_md5","enabled":true,"max_amount_fiat_minor":%q},"control_version":17}}`, limit)
				case "GET /auth/csrf":
					fmt.Fprint(w, `{"code":200,"data":{"token":"csrf"}}`)
				case "POST /channel-accounts/requests":
					// Stop at the real approval boundary after inspecting the outgoing change.
					var body object
					dec := json.NewDecoder(r.Body)
					dec.UseNumber()
					if err := dec.Decode(&body); err != nil {
						t.Error(err)
						return
					}
					change := obj(body["change"])
					c := obj(change["configuration"])
					if num(change, "expected_control_version") != 17 || c["channel_account_id"] != "original" ||
						c["enabled"] != true || c["max_amount_fiat_minor"] != "100" || c["min_amount_fiat_minor"] != "1" ||
						c["credentials_ref"] != "existing-ref" || c["credentials_sha256"] != "existing-digest" {
						t.Error("unexpected form-md5 limit proposal")
					}
					fmt.Fprint(w, `{"code":409,"msg":"test approval boundary"}`)
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
			}))
			defer srv.Close()
			op.addr = strings.TrimPrefix(srv.URL, "http://")
			want := "test approval boundary"
			if limit == "100" {
				// With no EPay package staged, reaching its publication proves md5 was skipped.
				want = "missing setup result package/epay_v1"
			}
			if reason := failureText(d.channels); !strings.Contains(reason, want) {
				t.Errorf("channels stopped at %q, want %q", reason, want)
			}
		})
	}
}

func TestResumeEPayChannelSetup(t *testing.T) {
	credential := credentialBytes(map[string]string{"merchant_key": strings.Repeat("k", 32)})
	sum := sha256.Sum256(credential)
	digest := b64.EncodeToString(sum[:])
	for _, tc := range []struct {
		name, ref, digest string
		version           int64
		enabled, repair   bool
	}{
		{"old binding", "old-ref", "old-digest", 1, false, true},
		{"stale reference", "old-ref", digest, 5, true, true},
		{"stale digest", "new-ref", "old-digest", 3, false, true},
		{"matching credentials", "new-ref", digest, 2, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			d := newDriver(root, "", "setup")
			reviews := filepath.Join(root, "reviews.json")
			check(atomic(reviews, encoded([]object{{"seller_account_id": "seller", "review_sha256": strings.Repeat("01", 32)}})))
			check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE="+reviews+"\n")))
			check(atomic(filepath.Join(root, "handoff/epay.json"), credential))
			for _, step := range []string{"双批发布 epay_v1", "双批发布 epay_v1_verify", "交易凭据/epay_v1",
				"卖方通道绑定/epay_v1", "通道定价/epay_v1", "风控/epay_v1"} {
				d.put("step/setup/"+step, result{Name: step, Status: "ok"})
			}
			d.put("trade-ref/epay_v1", "old-ref")
			d.put("trade-digest/epay_v1", "old-digest")
			d.put("write/setup/seal-trade/epay_v1/result", object{"credentials_ref": "old-ref", "credentials_sha256": "old-digest"})
			d.put("write/setup/enable-plugin/epay_v1/body", object{"expected_control_version": 1})
			d.put("uuid/channel/epay_v1", "original")
			d.put("plugin/epay_v1", "plugin")
			d.put("seller-account", "seller")
			d.put("user/operations", "operator")
			d.put("session-until/operations", time.Now().Add(time.Hour))
			op := d.browser("operations")
			op.cookies["__Host-kaivo_platform_session"] = "test-session"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body object
				if r.Method == http.MethodPost {
					dec := json.NewDecoder(r.Body)
					dec.UseNumber()
					if err := dec.Decode(&body); err != nil {
						t.Error(err)
						return
					}
				}
				switch r.Method + " " + strings.TrimPrefix(r.URL.Path, op.prefix) {
				case "GET /auth/csrf":
					fmt.Fprint(w, `{"code":200,"data":{"token":"csrf"}}`)
				case "POST /channel-accounts/credentials":
					if body["channel_account_id"] != "original" || body["channel_code"] != epayChannel || body["credentials_json"] != b64.EncodeToString(credential) {
						t.Error("incorrect trade credential seal request")
					}
					fmt.Fprintf(w, `{"code":200,"data":{"credentials_ref":"new-ref","credentials_sha256":%q}}`, digest)
				case "GET /channel-accounts/original":
					fmt.Fprintf(w, `{"code":200,"data":{"configuration":{"channel_code":"epay_v1","enabled":%t,"credentials_ref":%q,"credentials_sha256":%q},"control_version":%d}}`,
						tc.enabled, tc.ref, tc.digest, tc.version)
				case "GET /plugins":
					fmt.Fprint(w, `{"code":200,"data":{"items":[{"plugin_version_id":"plugin","control_version":1}]}}`)
				case "POST /channel-accounts/requests", "POST /plugin-enables/requests":
					repair := strings.HasSuffix(r.URL.Path, "/channel-accounts/requests")
					if repair {
						body = obj(body["change"])
						c := obj(body["configuration"])
						if c["enabled"] != tc.enabled || c["credentials_ref"] != "new-ref" || c["credentials_sha256"] != digest {
							t.Error("incorrect credential repair proposal")
						}
					}
					if repair != tc.repair || num(body, "expected_control_version") != tc.version {
						t.Error("unexpected approval request or channel version")
					}
					fmt.Fprint(w, `{"code":409,"msg":"test approval boundary"}`)
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
			}))
			defer srv.Close()
			op.addr = strings.TrimPrefix(srv.URL, "http://")
			reason := failureText(func() { d.setupChannel(epayChannel, true) })
			if !strings.Contains(reason, "test approval boundary") || d.required("trade-ref/epay_v1") != "new-ref" ||
				d.required("trade-digest/epay_v1") != digest {
				t.Fatalf("EPay setup did not resume with the resealed credential: %s", reason)
			}
		})
	}
}
