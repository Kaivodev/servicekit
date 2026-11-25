package main

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestKubeDepositDatasetAndOwners(t *testing.T) {
	k := fakeKube(t)
	k.namespaces["sim"] = "sim-custom"
	repo, e := filepath.Abs("../../../..")
	check(e)
	seller := id()
	// The bootstrap seed has already started devchain with its empty genesis.
	seed := object{"metadata": object{"resourceVersion": "1"}, "data": object{"chain.json": "bootstrap"}}
	check(atomic(filepath.Join(k.dir, "sim-custom_deposit-dataset.json"), encoded(seed)))
	k.prepareDeposits(repo, seller)
	get := func(ns, name string) map[string]string { return k.data(ns, "configmap", name) }
	data := get("sim-custom", datasetName)
	recon := get("kaivo-reconciliation", "reconciliation-deposits")
	var scenario, chain, bindings object
	decode([]byte(data["scenario.json"]), &scenario)
	decode([]byte(data["chain.json"]), &chain)
	decode([]byte(data["bindings.json"]), &bindings)
	if len(data) != 4 || scenario["account_id"] != seller || num(chain, "chain_id") != 31337 || obj(bindings["bindings"].([]any)[0])["address_id"] != scenario["address_id"] || recon["bindings.json"] != data["bindings.json"] || recon["AIPAY_RECON_SCREENING_MODE"] != "development_allow" || recon["AIPAY_RECON_DEPOSITS"] != "on" || recon["AIPAY_RECON_EVM_RPC_URL"] != "http://devchain.sim-custom.svc.cluster.local:8545" || recon["AIPAY_RECON_BINDINGS_FILE"] != depositDir+"/bindings.json" || strings.Contains(data["reconciliation.env"], k.dir) {
		t.Fatal("inconsistent projected dataset")
	}
	calls := string(file(filepath.Join(k.dir, "calls")))
	for _, d := range []struct{ ns, name string }{{"sim-custom", "devchain"}, {"sim-custom", "devcollection"}, {"kaivo-reconciliation", "reconciliation"}} {
		restart := `"-n", "` + d.ns + `", "rollout", "restart", "deployment/` + d.name + `"`
		status := strings.Replace(restart, `"restart"`, `"status"`, 1)
		ri, si := strings.Index(calls, restart), strings.Index(calls, status)
		if ri < 0 || si <= ri {
			t.Fatal("missing ordered rollout", d.name)
		}
		calls = calls[si+len(status):]
	}
	k.prepareDeposits("unused-on-resume", seller)
	if !maps.Equal(data, get("sim-custom", datasetName)) || failureText(func() { k.prepareDeposits(repo, id()) }) == "" {
		t.Fatal("lost original dataset")
	}
	t.Setenv("FAIL_ROLLOUT", "deployment/devchain")
	if failureText(func() { k.prepareDeposits(repo, seller) }) == "" {
		t.Fatal("ignored failed rollout")
	}
	for _, tc := range []struct {
		svc, db, label, secret string
		args                   []string
	}{
		{"ledger", "AIPAY_LEDGER_WALLETS_DATABASE_URL", "ledger-admin", "pg-ledger", []string{"wallets", "register", "file"}},
		{"devcollection", "AIPAY_DATABASE_URL", "collection-admin", "pg-collection-dev", []string{"receipt", "add", "normal"}},
	} {
		k.owner(tc.svc, tc.db, tc.args...)
		var pod object
		decode(file(filepath.Join(k.dir, "pod")), &pod)
		meta, spec := obj(pod["metadata"]), obj(pod["spec"])
		c := obj(spec["containers"].([]any)[0])
		if obj(meta["labels"])["app.kubernetes.io/name"] != tc.label || c["name"] != tc.svc || string(encoded(c["args"])) != string(encoded(tc.args)) || tc.svc == "devcollection" && (spec["serviceAccountName"] != "collection" || meta["namespace"] != "sim-custom") {
			t.Fatal("wrong owner Pod", tc.svc)
		}
		refs := 0
		for _, ev := range c["env"].([]any) {
			v := obj(ev)
			if v["name"] == tc.db {
				ref := obj(obj(v["valueFrom"])["secretKeyRef"])
				if ref["name"] != tc.secret || ref["key"] != "uri" {
					t.Fatal("wrong owner secret")
				}
				refs++
			}
		}
		if refs != 1 {
			t.Fatal("duplicate or missing owner URI")
		}
	}
	if strings.Contains(string(file(filepath.Join(k.dir, "calls"))), `"exec"`) {
		t.Fatal("unexpected exec")
	}
}
func TestKubeSellerReviewMerge(t *testing.T) {
	k := fakeKube(t)
	seller, owner := id(), id()
	row := object{"seller_account_id": id(), "review_sha256": strings.Repeat("ab", 32), "reviewed_by": "existing", "valid_until": time.Now().Add(time.Hour)}
	other := string(encoded([]object{row}))
	t.Setenv("REVIEW_CONFLICT", other)
	cm := object{"metadata": object{"resourceVersion": "1"}, "data": object{reviewsKey: "[]", "rate.json": "untouched"}}
	path := filepath.Join(k.dir, "kaivo-business_payment-inputs.json")
	check(atomic(path, encoded(cm)))
	k.sellerReview(seller, owner, "seller@example.test")
	data := k.data("kaivo-business", "configmap", "payment-inputs")
	var rows []object
	decode([]byte(data[reviewsKey]), &rows)
	var before []object
	decode([]byte(other), &before)
	if data["rate.json"] != "untouched" || len(rows) != 2 || !reflect.DeepEqual(rows[0], before[0]) || rows[1]["seller_account_id"] != seller || len(str(rows[1], "review_sha256")) != 64 || rows[1]["reviewed_by"] != "kaivo-demo-development" {
		t.Fatal("review merge")
	}
	until, e := time.Parse(time.RFC3339, str(rows[1], "valid_until"))
	if e != nil || !until.After(time.Now()) {
		t.Fatal("invalid review validity")
	}
	applied := file(path)
	k.sellerReview(seller, owner, "seller@example.test")
	if string(applied) != string(file(path)) {
		t.Fatal("retry rewrote valid review")
	}
	t.Setenv("TEST_STAGE_ENV", "production")
	clear(k.configs)
	if failureText(func() { k.sellerReview(seller, owner, "seller@example.test") }) == "" || !json.Valid(file(path)) {
		t.Fatal("missing development guard")
	}
}
