package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeKube(t *testing.T) *kubeEnvironment {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AIPAY_DEMO_CONFIGMAP_SYNC", "1ms")
	t.Setenv("DEMO_TEST_ROOT", dir)
	t.Setenv("KUBECTL", "python3 -B testdata/fake_kubectl.py wrapper")
	return newKubeEnvironment(t.Context(), dir, func(line string) { t.Log(line) })
}
func failureText(f func()) (msg string) {
	defer func() {
		if v := recover(); v != nil {
			msg = v.(failure).reason
		}
	}()
	f()
	return
}

func TestKubeFactsAndRedaction(t *testing.T) {
	k := fakeKube(t)
	k.namespaces["business"] = "custom-business"
	dsn := "postgresql://iam:secret-sentinel@business-pg-rw:5432/aipay_iam?sslmode=require"
	t.Setenv("DEMO_TEST_VALUE", dsn)
	c := k.database("iam")
	if c.Host != "127.0.0.1" || int(c.Port) != k.base+5 || c.User != "iam" || c.Password != "secret-sentinel" || c.RuntimeParams["default_transaction_read_only"] != "on" || c.TLSConfig == nil {
		t.Fatal("lost owner credentials, TLS or read-only session")
	}
	if string(k.field("custom-business", "configmap", "test", "key")) != "fresh" {
		t.Fatal("configmap data")
	}
	msg := failureText(func() { k.kubectl(nil, "custom-business", "not-a-verb") })
	args := string(file(filepath.Join(k.dir, "calls")))
	if !strings.Contains(args, "custom-business") || strings.Contains(args, "sentinel") || msg == "" || strings.Contains(msg, "sentinel") {
		t.Fatal("kubectl argv or diagnostics")
	}
	t.Setenv("DEMO_TEST_VALUE", "%secret-sentinel")
	msg = failureText(func() { k.database("payment") })
	if msg == "" || strings.Contains(msg, "sentinel") {
		t.Fatal("DSN parse error exposed input")
	}
}
func TestKubeOwnerLifecycle(t *testing.T) {
	k := fakeKube(t)
	var original object
	decode(file("testdata/deployment.json"), &original)
	spec0 := obj(obj(obj(original["spec"])["template"])["spec"])
	c0 := obj(spec0["containers"].([]any)[0])
	manifest := filepath.Join(k.dir, "declarations", "bootstrap.json")
	declaration := []byte("{\n \"witness\": \"demo\"\n}\n")
	check(atomic(manifest, declaration))
	owner := func() []byte {
		return k.owner("iam", "AIPAY_IAM_BOOTSTRAP_DATABASE_URL", "bootstrap", "--manifest", manifest)
	}
	if string(owner()) != "private-pod-log-sentinel\n" {
		t.Fatal("owner result")
	}
	var pod object
	decode(file(filepath.Join(k.dir, "pod")), &pod)
	spec := obj(pod["spec"])
	meta := obj(pod["metadata"])
	c := obj(spec["containers"].([]any)[0])
	if obj(meta["labels"])["app.kubernetes.io/name"] != "iam-admin" || spec["serviceAccountName"] != "iam-migrate" || spec["serviceAccount"] != nil || spec["restartPolicy"] != "Never" || obj(meta["annotations"])["kaivo.dev/declaration"] != string(declaration) {
		t.Fatal("owner Pod identity or declaration")
	}
	for _, field := range []string{"securityContext", "imagePullSecrets", "initContainers", "automountServiceAccountToken"} {
		if !reflect.DeepEqual(spec[field], spec0[field]) {
			t.Fatal(field)
		}
	}
	for _, field := range []string{"image", "imagePullPolicy", "securityContext", "envFrom"} {
		if !reflect.DeepEqual(c[field], c0[field]) {
			t.Fatal(field)
		}
	}
	if c["startupProbe"] != nil || c["livenessProbe"] != nil || c["readinessProbe"] != nil || len(spec["volumes"].([]any)) != 2 || len(c["volumeMounts"].([]any)) != 2 || c["args"].([]any)[2] != "/run/kaivo/declaration/input.json" {
		t.Fatal("owner execution or mounts")
	}
	mapped := 0
	for _, v := range c["env"].([]any) {
		e := obj(v)
		if e["name"] == "AIPAY_DATABASE_URL" || e["name"] == "AIPAY_IAM_BOOTSTRAP_DATABASE_URL" {
			ref := obj(obj(e["valueFrom"])["secretKeyRef"])
			if ref["name"] != "pg-iam" || ref["key"] != "uri" || e["value"] != nil {
				t.Fatal("owner URI reference")
			}
			mapped++
		}
	}
	if mapped != 2 {
		t.Fatal("missing database environment override")
	}
	t.Setenv("POD_PHASE", "Failed")
	msg := failureText(func() { owner() })
	calls := string(file(filepath.Join(k.dir, "calls")))
	if msg == "" || strings.Contains(msg, "sentinel") || strings.Count(calls, `"delete"`) != 2 || strings.Count(calls, `"logs"`) != 2 || strings.Contains(calls, manifest) {
		t.Fatal("failed owner cleanup or private data in argv")
	}
}

func TestKubeMarketPipe(t *testing.T) {
	k := fakeKube(t)
	k.seed = filepath.Join(k.dir, "seed")
	err := os.WriteFile(k.seed, []byte("#!/bin/sh\n[ \"$1\" = market ] || exit 2\nprintf '%s\\n' '---' 'market stream'\nexit \"${FAIL_SEED:-0}\"\n"), 0700)
	if err != nil {
		t.Fatal(err)
	}
	k.syncDelay = 15 * time.Millisecond
	start := time.Now()
	k.refreshMarket()
	calls := string(file(filepath.Join(k.dir, "calls")))
	if time.Since(start) < k.syncDelay || strings.Contains(calls, `"exec"`) {
		t.Fatal("market projection wait")
	}
	for _, env := range []string{"FAIL_SEED", "FAIL_APPLY"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "1")
			if failureText(k.applyMarket) == "" {
				t.Fatal("pipeline hid a failed stage")
			}
		})
	}
}

func TestKubeForwards(t *testing.T) {
	for _, fail := range []string{"", "service/ledger-pg-rw"} {
		t.Run("failed="+fail, func(t *testing.T) {
			k := fakeKube(t)
			t.Setenv("FAIL_FORWARD", fail)
			// Reserve a test range for the eight base ports and the simulator.
			for {
				k.base = 20000 + rand.IntN(20000)
				if k.base <= 65527 {
					var held []net.Listener
					for i := 0; i < 9; i++ {
						l, e := net.Listen("tcp4", k.local(i))
						if e != nil {
							break
						}
						held = append(held, l)
					}
					for _, l := range held {
						l.Close()
					}
					if len(held) == 9 {
						k.simPort = k.base + 8
						break
					}
				}
			}
			defer k.closeForwards()
			msg := failureText(k.startForwards)
			if (msg != "") != (fail != "") {
				t.Fatal(msg)
			}
			if fail == "" && len(k.forwards) != 7 {
				t.Fatal("missing port-forward")
			}
			if !strings.Contains(string(file(filepath.Join(k.dir, "calls"))), fmt.Sprintf(`"service/upstream-sim", "%d:9080"`, k.simPort)) {
				t.Fatal("incorrect upstream-sim port mapping")
			}
			k.closeForwards()
			for _, port := range []string{k.local(0), k.local(3), k.local(7), k.local(8)} {
				if c, e := net.DialTimeout("tcp", port, time.Second); e == nil {
					c.Close()
					t.Fatal("listener survived", port)
				}
			}
		})
	}
}
func TestKubeMailpit(t *testing.T) {
	k := fakeKube(t)
	token := b64.EncodeToString(make([]byte, 32))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/messages":
			id := "unrelated"
			if r.URL.Query().Get("start") == "1" {
				id = "expected"
			}
			fmt.Fprintf(w, `{"total":2,"messages":[{"ID":"%s","To":[{"Address":"admin1@demo.aipay.test"}]}]}`, id)
		case "/api/v1/message/unrelated":
			fmt.Fprint(w, `{"Text":"another email"}`)
		case "/api/v1/message/expected":
			json.NewEncoder(w).Encode(object{"Text": string(encoded(iamMail{"admin1@demo.aipay.test", "重置密码", "令牌：" + token}))})
		default:
			t.Error("unexpected Mailpit path")
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	k.base = port - 3
	d := newDriver(t.TempDir(), "", "setup")
	d.demoEnvironment = k
	if d.mail(d.email("admin1"), "重置密码") != token {
		t.Fatal("IAM mail token")
	}
}
func TestKubeRejectsNativeScenarios(t *testing.T) {
	t.Setenv("AIPAY_DEMO_TARGET", "k8s")
	t.Setenv("KUBECTL", "missing-kubectl")
	for _, s := range []string{"duplicates", "ledger-reader", "ledger-matches"} {
		dir := t.TempDir()
		out := filepath.Join(dir, "report.md")
		e := executeContext(context.Background(), []string{dir, ".", "run", s, "-o", out})
		if e == nil || !strings.Contains(e.Error(), "仅本机栈") || !bytes.Contains(file(out), []byte("仅本机栈")) {
			t.Fatal(s, e)
		}
	}
}

func TestKubeCashier(t *testing.T) {
	k := fakeKube(t)
	d := newDriver(t.TempDir(), "", "main")
	d.demoEnvironment = k
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	k.simPort = l.Addr().(*net.TCPAddr).Port
	calls := make(chan string, 2)
	srv := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls <- r.Method; w.WriteHeader(200) })}
	go srv.Serve(l)
	defer srv.Close()
	d.cashier("http://127.0.0.1:9080/cashier/fixture", true)
	if <-calls != "GET" || <-calls != "POST" {
		t.Fatal("cashier request order")
	}
	if failureText(func() { d.cashier("http://localhost:9080/cashier/private", false) }) != "unexpected cashier link" {
		t.Fatal("unexpected cashier host accepted")
	}
}

func TestKubeFixtureCredentialHandoff(t *testing.T) {
	k := fakeKube(t)
	t.Setenv("DEMO_TEST_VALUE", "bot-secret-sentinel")
	check(atomic(filepath.Join(k.dir, "merchant-key.json"), encoded(object{"PID": "123", "Key": "merchant-secret-sentinel"})))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cfg fixtureConfig
		if r.URL.Path != "/config" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer bot-secret-sentinel" || json.NewDecoder(r.Body).Decode(&cfg) != nil || cfg.Token != "" || !bytes.Contains(cfg.V1, []byte("merchant-secret-sentinel")) {
			t.Error("invalid fixture handoff")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	k.base = port - 4
	k.syncMerchantKeys()
	calls := string(file(filepath.Join(k.dir, "calls")))
	if strings.Contains(calls, "sentinel") || strings.Contains(calls, `"exec"`) {
		t.Fatal("credential handoff arguments")
	}
	entries, e := os.ReadDir(k.dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, item := range entries {
		if item.Name() != "merchant-key.json" && strings.Contains(string(file(filepath.Join(k.dir, item.Name()))), "sentinel") {
			t.Fatal("private fixture handoff persisted")
		}
	}
}

func TestKubeOwnerSharesPVCNode(t *testing.T) {
	var deployment object
	decode(file("testdata/deployment.json"), &deployment)
	spec := obj(obj(obj(deployment["spec"])["template"])["spec"])
	spec["volumes"] = append(spec["volumes"].([]any), object{"name": "data", "persistentVolumeClaim": object{"claimName": "evidence"}})
	pod := ownerPod(deployment, "business", "iam-admin-test", "iam", sellersDatabase, t.TempDir(), []string{"sellers", "list"})
	affinity := obj(obj(obj(pod["spec"])["affinity"])["podAffinity"])
	terms := affinity["requiredDuringSchedulingIgnoredDuringExecution"].([]any)
	term := obj(terms[0])
	if term["topologyKey"] != "kubernetes.io/hostname" || obj(obj(term["labelSelector"])["matchLabels"])["app.kubernetes.io/name"] != "iam" {
		t.Fatal("owner may be scheduled away from the mounted PVC")
	}
}

func TestKubeOwnerKeepsWorkloadIdentity(t *testing.T) {
	var deployment object
	decode(file("testdata/deployment.json"), &deployment)
	spec := obj(obj(obj(deployment["spec"])["template"])["spec"])
	gcp := object{"serviceAccountToken": object{"audience": "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/cluster", "expirationSeconds": 3600, "path": "token"}}
	rpc := object{"serviceAccountToken": object{"audience": "kaivo:ledger", "expirationSeconds": 600, "path": "ledger"}}
	spec["volumes"] = append(spec["volumes"].([]any),
		object{"name": "gcp-token", "projected": object{"sources": []any{gcp}}},
		object{"name": "peer-tokens", "projected": object{"sources": []any{rpc}}})
	pod := ownerPod(deployment, "business", "iam-admin-test", "iam", sellersDatabase, t.TempDir(), []string{"sellers", "list"})
	podSpec := obj(pod["spec"])
	if podSpec["serviceAccountName"] != "iam" {
		t.Fatal("owner with a GCP token must use the service's own ServiceAccount")
	}
	for _, v := range podSpec["volumes"].([]any) {
		volume := obj(v)
		switch volume["name"] {
		case "gcp-token":
			if sources := obj(volume["projected"])["sources"].([]any); len(sources) != 1 {
				t.Fatal("owner lost the GCP workload identity token")
			}
		case "peer-tokens":
			if volume["projected"] != nil || volume["emptyDir"] == nil {
				t.Fatal("owner kept a service RPC token")
			}
		}
	}
	plain := ownerPod(func() object { var d object; decode(file("testdata/deployment.json"), &d); return d }(), "business", "iam-admin-test", "iam", sellersDatabase, t.TempDir(), []string{"sellers", "list"})
	if obj(plain["spec"])["serviceAccountName"] != "iam-migrate" {
		t.Fatal("owner without a GCP token must keep the migrate ServiceAccount")
	}
}
