package main

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayModeFromDeployedSettings(t *testing.T) {
	const payment = "AIPAY_UPSTREAM_GATEWAY_ADDRESS"
	const reconciliation = "AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS"
	for _, native := range []bool{true, false} {
		for _, trade := range []string{"", "trade:9107"} {
			for _, verify := range []string{"", "verification:9108"} {
				t.Run(fmt.Sprintf("native=%t/trade=%t/verify=%t", native, trade != "", verify != ""), func(t *testing.T) {
					root := t.TempDir()
					d := newDriver(root, "", "setup")
					if native {
						check(atomic(filepath.Join(root, "env/payment.env"), []byte(payment+"="+trade)))
						check(atomic(filepath.Join(root, "env/reconciliation.env"), []byte(reconciliation+"="+verify)))
					} else {
						k := fakeKube(t)
						for _, s := range []struct{ ns, service, key, addr string }{
							{"business", "payment", payment, trade}, {"reconciliation", "reconciliation", reconciliation, verify},
						} {
							data := map[string]string{}
							if s.addr != "" {
								data[s.key] = s.addr
							}
							check(atomic(filepath.Join(k.dir, k.namespaces[s.ns]+"_"+s.service+"-config.json"), encoded(object{"data": data})))
						}
						d.demoEnvironment = k
					}
					var got bool
					msg := failureText(func() { got = d.gatewayMode() })
					if !native && (trade == "") != (verify == "") {
						if !strings.Contains(msg, payment) || !strings.Contains(msg, reconciliation) {
							t.Fatal("mixed overlay must identify both ConfigMap settings")
						}
					} else if msg != "" || got != (trade != "") {
						t.Fatal("incorrect gateway mode")
					}
				})
			}
		}
	}
}

func TestPartialGatewayOverlayStopsBeforeSetup(t *testing.T) {
	k := fakeKube(t)
	t.Setenv("AIPAY_DEMO_TARGET", "k8s")
	check(atomic(filepath.Join(k.dir, "kaivo-business_payment-config.json"),
		encoded(object{"data": object{"AIPAY_UPSTREAM_GATEWAY_ADDRESS": "trade:9107"}})))
	err := executeContext(t.Context(), []string{t.TempDir(), ".", "setup", "iam"})
	if err == nil || !strings.Contains(err.Error(), "reconciliation-config") {
		t.Fatal("setup must diagnose a partial gateway overlay")
	}
	calls := string(file(filepath.Join(k.dir, "calls")))
	if strings.Count(calls, "\n") != 2 || strings.Count(calls, `"get", "configmap"`) != 2 {
		t.Fatal("setup must check both ConfigMaps before starting forwards or owner commands")
	}
}

func TestKubeGatewayPackages(t *testing.T) {
	k := fakeKube(t)
	k.namespaces["sim"] = "custom-sim"
	const host = "upstream-sim.custom-sim.svc.cluster.local"
	root := t.TempDir()
	packages := filepath.Join(root, "prebuilt")
	t.Setenv("KAIVO_DEMO_PLUGIN_PACKAGES", packages)
	k.configs["payment"] = map[string]string{"AIPAY_UPSTREAM_GATEWAY_ADDRESS": "trade:9107"}
	k.configs["reconciliation"] = map[string]string{"AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS": "verify:9108"}
	d := newDriver(root, filepath.Join(root, "servicekit"), "setup")
	d.demoEnvironment = k
	codes := []string{md5Channel, md5Channel + "_verify", epayChannel, epayChannel + "_verify"}
	for _, code := range codes {
		version, old := "0.3.1", "0.3.0"
		if code == epayChannel+"_verify" {
			version, old = "0.2.1", "0.2.0"
		}
		m := object{"code": code, "abi_version": 3, "build": object{"source_commit": strings.Repeat("a", 40)}, "type": pluginWorld(code),
			"version": old, "domains": []string{host}, "config": object{"unpaid_timeout_seconds": object{"type": "string", "required": true}}}
		wasm := []byte("test component")
		validate := func() { d.checkGatewayPackage(code, encoded(m), wasm, "") }
		if msg := failureText(validate); !strings.Contains(msg, code) || !strings.Contains(msg, version) {
			t.Fatal("old version must identify the plugin and minimum")
		}
		m["version"] = version
		for _, domains := range [][]string{nil, {"127.0.0.1"}, {"*." + host}, {host + ":9080"}, {"upstream-sim.kaivo-sim.svc.cluster.local"}} {
			m["domains"] = domains
			if msg := failureText(validate); !strings.Contains(msg, code) || !strings.Contains(msg, host) {
				t.Fatal("domain mismatch must identify the plugin and configured simulator host")
			}
		}
		m["domains"] = []string{"127.0.0.1", host}
		path := filepath.Join(packages, code)
		check(atomic(filepath.Join(path, "manifest.json"), encoded(m)))
		check(atomic(filepath.Join(path, "plugin.wasm"), wasm))
		check(atomic(filepath.Join(path, "fixtures/query.json"), []byte("{}")))
	}
	d.packages()
	for _, code := range codes {
		if d.required("package/"+code) != filepath.Join(packages, code) || d.upload(code)["manifest_json"] == nil {
			t.Fatal("missing Kubernetes gateway upload")
		}
	}
	k.namespaces["sim"] = "other-sim"
	if msg := failureText(func() { d.upload(epayChannel) }); !strings.Contains(msg, "upstream-sim.other-sim.svc.cluster.local") {
		t.Fatal("upload must recheck the current simulator domain")
	}
}

func TestKubeChannelInputs(t *testing.T) {
	k := fakeKube(t)
	const host = "http://upstream-sim.kaivo-sim.svc.cluster.local:9080"
	sim := encoded(object{"accounts": []object{
		{"id": "md5-demo", "style": "form-md5", "shared_secret": "trade", "query_shared_secret": "query"},
		{"id": "epay-demo", "style": "epay-v1", "pid": 1001, "shared_secret": "merchant"},
	}})
	check(atomic(filepath.Join(k.dir, "kaivo-sim_upstream-sim-private.json"), encoded(object{"data": object{"config.json": base64.StdEncoding.EncodeToString(sim)}})))
	check(atomic(filepath.Join(k.dir, "kaivo-reconciliation_reconciliation-handoff.json"), encoded(object{"data": object{
		"query.json": base64.StdEncoding.EncodeToString(encoded(object{"query_key": "query"})),
		"epay.json":  base64.StdEncoding.EncodeToString(encoded(object{"merchant_key": "merchant"})),
	}})))
	d := newDriver(k.dir, "", "setup")
	d.demoEnvironment = k
	for _, code := range []string{epayChannel, md5Channel} {
		spec := channelSetup(code, true, k.addresses().gateway, "4200")
		if spec.tradeConfig["gateway"] != host || spec.queryConfig["gateway"] != host {
			t.Fatal("trade and verification require the in-cluster simulator")
		}
		want := "trade"
		if code == epayChannel {
			want = "merchant"
		}
		trade := d.channelCredentials(code, spec.tradeFile, spec.tradeKey)
		verify := d.channelCredentials(code, spec.queryFile, spec.queryKey)
		if len(trade) != 1 || trade[spec.tradeKey] != want || len(verify) != 1 || spec.witnessSource(code, verify, sim) == "" {
			t.Fatal("incorrect Kubernetes channel credential handoff")
		}
	}
}

func TestKubeSimulatorPort(t *testing.T) {
	for _, tc := range []struct{ base, port, want string }{
		{"", "", "9080"}, {"9080", "19080", "19080"}, {"18080", "1", "1"}, {"18080", "65535", "65535"},
		{"18080", "18079", "18079"}, {"18080", "18088", "18088"}, {"18080", "18080", ""}, {"18080", "18087", ""},
		{"9073", "", ""}, {"", "0", ""}, {"", "65536", ""}, {"", "invalid", ""}, {"65529", "9000", ""},
	} {
		t.Run(tc.base+"/"+tc.port, func(t *testing.T) {
			t.Setenv("AIPAY_DEMO_PORT_BASE", tc.base)
			t.Setenv("AIPAY_DEMO_SIM_PORT", tc.port)
			msg := failureText(func() {
				k := newKubeEnvironment(t.Context(), t.TempDir())
				if tc.want != "" && k.addresses().sim != "http://127.0.0.1:"+tc.want {
					t.Fatal("wrong local simulator endpoint")
				}
			})
			if (msg == "") != (tc.want != "") {
				t.Fatal("incorrect port validation")
			}
		})
	}
}
