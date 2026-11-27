package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/servicekit/signing"
)

var testTime = time.Date(2026, 11, 19, 12, 30, 10, 765000123, time.UTC)

// Keep the consumer contract independent of the producer's inventory.
var contract = map[objectID]string{
	{"kaivo-business", "Secret", "backend-private"}:                "bot-token epay.der portal-cookie-key telegram-webhook-secret",
	{"kaivo-business", "Secret", "iam-private"}:                    "data-key epay.der sealer.key signing.pem",
	{"kaivo-business", "Secret", "payment-private"}:                "epay.der plugins.json signing.pem",
	{"kaivo-ledger", "Secret", "ledger-private"}:                   "report.pem signing.pem",
	{"kaivo-reconciliation", "Secret", "reconciliation-private"}:   "sealer.key signing.pem",
	{"kaivo-reconciliation", "Secret", "reconciliation-handoff"}:   "epay.json query.json",
	{"kaivo-sim", "ConfigMap", "deposit-dataset"}:                  "chain.json",
	{"kaivo-sim", "Secret", "collection-private"}:                  "collection.jwks signing.pem",
	{"kaivo-sim", "Secret", "demo-fixtures-private"}:               "bot-token",
	{"kaivo-sim", "Secret", "upstream-sim-private"}:                "config.json",
	{"kaivo-business", "ConfigMap", "backend-inputs"}:              "bot-api-base-url",
	{"kaivo-business", "ConfigMap", "iam-inputs"}:                  "routes.json signer-valid-from",
	{"kaivo-business", "ConfigMap", "payment-inputs"}:              "rate.json seller-reviews.json",
	{"kaivo-business", "ConfigMap", "notifier-inputs"}:             "allowed-hosts egress-proxy",
	{"kaivo-ledger", "ConfigMap", "ledger-inputs"}:                 "usd-rates.json",
	{"kaivo-reconciliation", "ConfigMap", "reconciliation-inputs"}: "coverage.json market.json",
	{"kaivo-business", "ConfigMap", "kaivo-signing-public"}:        publicFiles,
	{"kaivo-ledger", "ConfigMap", "kaivo-signing-public"}:          publicFiles,
	{"kaivo-reconciliation", "ConfigMap", "kaivo-signing-public"}:  publicFiles,
}

const publicFiles = "collection.jwks iam.jwks ledger-report-public.pem ledger.jwks payment.jwks platform-public.pem reconciliation.jwks"

type cluster map[objectID]manifest

func setupKubectl(t *testing.T) {
	t.Helper()
	t.Setenv("KAIVO_STAGING_KMS_DIR", "")
	t.Setenv("KUBECTL", "sh  testdata/kubectl.sh shell kaivo-k3s sudo k3s kubectl")
	t.Setenv("SEED_TEST_CALLS", filepath.Join(t.TempDir(), "calls"))
	t.Setenv("SEED_TEST_FAILURE", "")
	t.Setenv("SEED_TEST_COLLISION", "")
}

func serve(t *testing.T, c cluster, market bool) {
	t.Helper()
	mode := "seed"
	if market {
		mode = "market"
	}
	t.Setenv("SEED_TEST_MODE", mode)
	for ns, env := range map[string]string{business: "SEED_TEST_BUSINESS", ledger: "SEED_TEST_LEDGER", recon: "SEED_TEST_RECON", sim: "SEED_TEST_SIM"} {
		items := []manifest{}
		for id, item := range c {
			if id.namespace == ns && (!market || slices.Contains(marketObjects, id)) {
				items = append(items, item)
			}
		}
		t.Setenv(env, jsonFile(map[string]any{"items": items}))
	}
}

func generate(t *testing.T, c cluster, now time.Time, args ...string) cluster {
	t.Helper()
	serve(t, c, len(args) > 0)
	var out, diag bytes.Buffer
	if cli(args, &out, &diag, now) != 0 || diag.Len() != 0 {
		t.Fatalf("generation failed: %s", diag.String())
	}
	data := out.String()
	if !strings.HasPrefix(data, "---\n") {
		t.Fatal("missing YAML document marker")
	}
	got := cluster{}
	for doc := range strings.SplitSeq(strings.TrimPrefix(data, "---\n"), "---\n") {
		var obj manifest
		dec := json.NewDecoder(strings.NewReader(doc))
		dec.DisallowUnknownFields()
		if !json.Valid([]byte(doc)) || dec.Decode(&obj) != nil {
			t.Fatal("unexpected stdout or manifest field")
		}
		id := objectID{obj.Metadata.Namespace, obj.Kind, obj.Metadata.Name}
		if _, ok := got[id]; ok {
			t.Fatal("duplicate manifest")
		}
		if obj.APIVersion != "v1" || !maps.Equal(obj.Metadata.Labels, fields{managedBy: manager}) {
			t.Fatal("incorrect metadata")
		}
		got[id] = obj
	}
	return got
}

func checkInventory(t *testing.T, c cluster, want map[objectID]string) {
	t.Helper()
	if len(c) != len(want) {
		t.Fatalf("got %d objects, want %d", len(c), len(want))
	}
	for id, keys := range want {
		got := slices.Sorted(maps.Keys(c[id].Data))
		if strings.Join(got, " ") != keys {
			t.Fatalf("incorrect keys for %s/%s", id.namespace, id.name)
		}
	}
}

func raw(t *testing.T, c cluster, id objectID, key string) string {
	t.Helper()
	value := c[id].Data[key]
	if id.kind != secret {
		return value
	}
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("invalid base64 for %s/%s", id.name, key)
	}
	return string(b)
}

func decoded[T any](t *testing.T, raw string) T {
	t.Helper()
	var v T
	if json.Unmarshal([]byte(raw), &v) != nil {
		t.Fatal("invalid JSON file")
	}
	return v
}

func privateKey(t *testing.T, data []byte) any {
	t.Helper()
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		t.Fatal("invalid PKCS#8")
	}
	return key
}

func checkKeys(t *testing.T, c cluster) {
	t.Helper()
	for _, spec := range []struct {
		id      objectID
		service string
	}{
		{collectionPrivate, "collection"}, {iamPrivate, "iam"}, {paymentPrivate, "payment"}, {ledgerPrivate, "ledger"}, {reconPrivate, "reconciliation"},
	} {
		block, _ := pem.Decode([]byte(raw(t, c, spec.id, "signing.pem")))
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Fatal("invalid signing PEM")
		}
		key := privateKey(t, block.Bytes).(*ecdsa.PrivateKey)
		for _, id := range registries {
			keys, err := signing.ParseJWKS([]byte(c[id].Data[spec.service+".jwks"]))
			pub, found := keys.Lookup(spec.service + "-dev")
			if err != nil || keys.Len() != 1 || !found || key.Curve != elliptic.P256() || !pub.Equal(&key.PublicKey) {
				t.Fatal("signing key mismatch")
			}
		}
	}
	der := raw(t, c, backendPrivate, "epay.der")
	key := privateKey(t, []byte(der)).(*rsa.PrivateKey)
	if key.N.BitLen() < 2048 || der != raw(t, c, iamPrivate, "epay.der") || der != raw(t, c, paymentPrivate, "epay.der") {
		t.Fatal("EPay key mismatch")
	}
	report := privateKey(t, pemDER(raw(t, c, ledgerPrivate, "report.pem"), "PRIVATE KEY")).(*ecdsa.PrivateKey)
	if report.Curve != elliptic.P256() || report.Equal(privateKey(t, pemDER(raw(t, c, ledgerPrivate, "signing.pem"), "PRIVATE KEY"))) {
		t.Fatal("invalid report key")
	}
	for _, id := range registries {
		rsaPub, err := x509.ParsePKIXPublicKey(pemDER(c[id].Data["platform-public.pem"], "PUBLIC KEY"))
		if err != nil || !key.PublicKey.Equal(rsaPub) {
			t.Fatal("EPay public key mismatch")
		}
		pub, err := x509.ParsePKIXPublicKey(pemDER(c[id].Data["ledger-report-public.pem"], "PUBLIC KEY"))
		if err != nil || !report.PublicKey.Equal(pub) {
			t.Fatal("report public key mismatch")
		}
	}
	iamSeal, reconSeal := raw(t, c, iamPrivate, "sealer.key"), raw(t, c, reconPrivate, "sealer.key")
	if len(iamSeal) != 32 || len(reconSeal) != 32 || iamSeal == reconSeal || !encoded32(base64.StdEncoding, raw(t, c, iamPrivate, "data-key")) {
		t.Fatal("invalid sealers/data key")
	}
	bot := raw(t, c, backendPrivate, "bot-token")
	if raw(t, c, fixturePrivate, "bot-token") != bot || !strings.HasPrefix(bot, "10001:") || !encoded32(base64.RawURLEncoding, strings.TrimPrefix(bot, "10001:")) ||
		!encoded32(base64.RawURLEncoding, raw(t, c, backendPrivate, "portal-cookie-key")) || !encoded32(base64.RawURLEncoding, raw(t, c, backendPrivate, "telegram-webhook-secret")) {
		t.Fatal("invalid backend development credentials")
	}
	checkPair(t, c)
}

func checkPair(t *testing.T, c cluster) {
	t.Helper()
	cfg := decoded[simConfig](t, raw(t, c, simPrivate, "config.json"))
	if cfg.Environment != "test" || cfg.Listen != "0.0.0.0:9080" || cfg.BaseURL != "http://127.0.0.1:9080" || len(cfg.Accounts) != 2 || !encoded32(base64.RawURLEncoding, cfg.Control) {
		t.Fatal("invalid simulator config")
	}
	a := cfg.Accounts[0]
	p := decoded[pluginConfig](t, raw(t, c, paymentPrivate, "plugins.json"))
	tx, err := base64.StdEncoding.DecodeString(p.Credentials["sim-md5-v1"].Secrets["shared"])
	query := decoded[fields](t, raw(t, c, handoff, "query.json"))["query_key"]
	if err != nil || a.ID != "md5-demo" || a.Style != "form-md5" || string(tx) != a.Shared || a.Query != query || a.Query == a.Shared || !encoded32(base64.StdEncoding, p.EvidenceKey) {
		t.Fatal("simulator credential mismatch")
	}
	for _, s := range []string{query, a.Shared} {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatal("invalid simulator secret format")
		}
	}
	// The simulator rejects a query_shared_secret field on EPay (even empty).
	wire := decoded[struct{ Accounts []map[string]any }](t, raw(t, c, simPrivate, "config.json"))
	epay := cfg.Accounts[1]
	key := decoded[fields](t, raw(t, c, handoff, "epay.json"))
	if epay.ID != "epay-demo" || epay.Style != "epay-v1" || epay.PID != 1001 || !validMerchantKey(epay.Shared) ||
		len(key) != 1 || key["merchant_key"] != epay.Shared || len(wire.Accounts[1]) != 4 {
		t.Fatal("invalid EPay simulator account or merchant key handoff")
	}
}

func TestBootstrapAndReplay(t *testing.T) {
	setupKubectl(t)
	c := generate(t, nil, testTime)
	checkInventory(t, c, contract)
	checkKeys(t, c)
	routes := map[string]string{
		"POST /api/v1/platform/channel-accounts/credentials":           "payment.channel.manage",
		"GET /api/v1/platform/orders/:order_id/forced-close":           "payment.order.force_close.read",
		"POST /api/v1/platform/orders/:order_id/forced-close-requests": "payment.order.force_close.submit",
		"POST /api/v1/platform/forced-closes/approvals/:id/assertions": "payment.order.force_close.approve",
	}
	checkRoutes := func(rows []map[string]any) {
		t.Helper()
		counts := map[string]int{}
		for _, row := range rows {
			key := row["method"].(string) + " " + row["path"].(string)
			if permission, ok := routes[key]; ok {
				counts[key]++
				if row["permission"] != permission || !reflect.DeepEqual(row["audiences"], []any{"payment"}) {
					t.Errorf("incorrect policy for %s", key)
				}
			}
		}
		for key := range routes {
			if counts[key] != 1 {
				t.Errorf("found %d entries for %s", counts[key], key)
			}
		}
	}
	portal, err := os.ReadFile("../../../portal-routes.json")
	if err != nil {
		t.Fatal(err)
	}
	checkRoutes(decoded[[]map[string]any](t, string(portal)))
	checkRoutes(decoded[[]map[string]any](t, raw(t, c, iamInputs, "routes.json")))
	calls, err := os.ReadFile(os.Getenv("SEED_TEST_CALLS"))
	if err != nil || !slices.Equal(strings.Fields(string(calls)), []string{business, ledger, recon, sim}) {
		t.Fatal("wrong kubectl namespaces")
	}
	if c[iamInputs].Data["signer-valid-from"] != "2026-11-19T12:30:10.765000Z" {
		t.Fatal("IAM requires microsecond signer validity")
	}
	if c[backendInputs].Data["bot-api-base-url"] != "http://demo-fixtures.kaivo-sim.svc.cluster.local:8081" ||
		c[notifierInputs].Data["egress-proxy"] != "http://demo-fixtures.kaivo-sim.svc.cluster.local:3128" ||
		c[notifierInputs].Data["allowed-hosts"] != "demo-fixtures.kaivo-sim.svc.cluster.local" {
		t.Fatal("incorrect fixture DNS")
	}
	if raw(t, c, paymentInputs, "seller-reviews.json") != "[]\n" {
		t.Fatal("expected empty seller reviews")
	}
	c[paymentInputs].Data["seller-reviews.json"] = `[{"seller_account_id":"reviewed"}]`
	// An unchanged resourceVersion permits reapplying the current chain only.
	// Seller files are owned by the demo driver and stay outside the seed manifest.
	c[bootstrapDataset].Data["chain.json"] = strings.Replace(c[bootstrapDataset].Data["chain.json"], `"timestamp":"0x0"`, `"timestamp":"0x1"`, 1)
	for id, obj := range c {
		obj.Metadata.ResourceVersion = "42"
		c[id] = obj
	}
	replay := generate(t, c, testTime.Add(time.Hour))
	if !reflect.DeepEqual(c, replay) {
		t.Fatal("bootstrap replaced existing data or lost resourceVersion")
	}
}

func TestUpgradeFormMD5Seed(t *testing.T) {
	setupKubectl(t)
	c := generate(t, nil, testTime)
	cfg := decoded[map[string]any](t, raw(t, c, simPrivate, "config.json"))
	accounts := cfg["accounts"].([]any)[:1]
	accounts[0].(map[string]any)["scenario"] = map[string]any{"query_unknown": true}
	cfg["accounts"] = accounts
	c[simPrivate].Data["config.json"] = base64.StdEncoding.EncodeToString([]byte(jsonFile(cfg)))
	delete(c[handoff].Data, "epay.json")

	next := generate(t, c, testTime.Add(time.Hour))
	checkPair(t, next)
	upgraded := decoded[map[string]any](t, raw(t, next, simPrivate, "config.json"))
	upgraded["accounts"] = upgraded["accounts"].([]any)[:1]
	if !reflect.DeepEqual(upgraded, cfg) ||
		next[handoff].Data["query.json"] != c[handoff].Data["query.json"] ||
		next[paymentPrivate].Data["plugins.json"] != c[paymentPrivate].Data["plugins.json"] {
		t.Fatal("upgrade changed existing simulator credentials")
	}
	if !reflect.DeepEqual(next, generate(t, next, testTime.Add(2*time.Hour))) {
		t.Fatal("repeated upgrade changed staged materials")
	}
}

func TestPartialApplication(t *testing.T) {
	setupKubectl(t)
	original := generate(t, nil, testTime)
	for _, tc := range []struct {
		name string
		ids  []objectID
	}{
		{"simulator alone", []objectID{simPrivate}},
		{"plugin and query without simulator", []objectID{paymentPrivate, handoff}},
		{"handoff alone", []objectID{handoff}},
		{"fixture token alone", []objectID{fixturePrivate}},
		{"EPay surviving in IAM", []objectID{iamPrivate}},
		{"registry and all source keys", []objectID{registries[1], iamPrivate, paymentPrivate, ledgerPrivate, reconPrivate, collectionPrivate}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			partial := cluster{}
			for _, id := range tc.ids {
				partial[id] = original[id]
			}
			result := generate(t, partial, testTime)
			checkInventory(t, result, contract)
			checkKeys(t, result)
			for id, obj := range partial {
				if !maps.Equal(obj.Data, result[id].Data) {
					t.Fatalf("replaced surviving %s", id.name)
				}
			}
		})
	}
	// Individual keys can also be missing in an otherwise existing object.
	delete(original[iamPrivate].Data, "epay.der")
	delete(original[registries[0]].Data, "iam.jwks")
	checkKeys(t, generate(t, original, testTime))
}

func expectFailure(t *testing.T, args ...string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli(args, &stdout, &stderr, testTime)
	if code == 0 || stdout.Len() != 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), "secret-in-") {
		t.Fatal("expected nonzero exit, empty stdout and a redacted stderr diagnostic")
	}
}

func TestRejectConflict(t *testing.T) {
	setupKubectl(t)
	original := generate(t, nil, testTime)
	other := generate(t, nil, testTime)
	for _, tc := range []struct {
		name   string
		change func(cluster)
	}{
		{"EPay mismatch", func(c cluster) { c[iamPrivate].Data["epay.der"] = other[iamPrivate].Data["epay.der"] }},
		{"JWKS mismatch", func(c cluster) { c[registries[1]].Data["iam.jwks"] = other[registries[1]].Data["iam.jwks"] }},
		{"wrong kid", func(c cluster) {
			c[registries[0]].Data["ledger.jwks"] = strings.ReplaceAll(c[registries[0]].Data["ledger.jwks"], "ledger-dev", "wrong-dev")
		}},
		{"report public mismatch", func(c cluster) {
			c[registries[2]].Data["ledger-report-public.pem"] = other[registries[2]].Data["ledger-report-public.pem"]
		}},
		{"platform public mismatch", func(c cluster) {
			c[registries[0]].Data["platform-public.pem"] = other[registries[0]].Data["platform-public.pem"]
		}},
		{"collection public mismatch in sim", func(c cluster) {
			c[collectionPrivate].Data["collection.jwks"] = other[collectionPrivate].Data["collection.jwks"]
		}},
		{"collection private missing", func(c cluster) { delete(c, collectionPrivate) }},
		{"fixture token mismatch", func(c cluster) { c[fixturePrivate].Data["bot-token"] = other[fixturePrivate].Data["bot-token"] }},
		{"lost signer", func(c cluster) { delete(c, iamPrivate) }},
		{"lost RSA", func(c cluster) {
			for _, id := range []objectID{backendPrivate, iamPrivate, paymentPrivate} {
				delete(c[id].Data, "epay.der")
			}
		}},
		{"signer reused for reports", func(c cluster) {
			c[ledgerPrivate].Data["report.pem"] = c[ledgerPrivate].Data["signing.pem"]
			for _, id := range registries {
				delete(c, id)
			}
		}},
		{"sealers equal", func(c cluster) { c[iamPrivate].Data["sealer.key"] = c[reconPrivate].Data["sealer.key"] }},
		{"transaction mismatch", func(c cluster) { c[paymentPrivate].Data["plugins.json"] = other[paymentPrivate].Data["plugins.json"] }},
		{"EPay merchant key mismatch", func(c cluster) { c[handoff].Data["epay.json"] = other[handoff].Data["epay.json"] }},
		{"malformed EPay handoff", func(c cluster) {
			c[handoff].Data["epay.json"] = base64.StdEncoding.EncodeToString([]byte(`{"merchant_key":"secret-in-handoff"}`))
		}},
		{"query mismatch", func(c cluster) { c[handoff].Data["query.json"] = other[handoff].Data["query.json"] }},
		{"query reused for transactions", func(c cluster) {
			cfg := decoded[simConfig](t, raw(t, c, simPrivate, "config.json"))
			cfg.Accounts[0].Query = cfg.Accounts[0].Shared
			c[simPrivate].Data["config.json"] = base64.StdEncoding.EncodeToString([]byte(jsonFile(cfg)))
			delete(c, handoff)
		}},
		{"broken existing Secret", func(c cluster) { c[backendPrivate].Data["bot-token"] = "secret-in-base64" }},
		{"empty existing key", func(c cluster) { c[iamPrivate].Data["data-key"] = "" }},
		{"invalid signer timestamp precision", func(c cluster) { c[iamInputs].Data["signer-valid-from"] = "2026-11-19T12:30:10.765000123Z" }},
		{"unreadable plugin file", func(c cluster) {
			c[paymentPrivate].Data["plugins.json"] = base64.StdEncoding.EncodeToString([]byte("secret-in-plugins"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cluster{}
			for id, obj := range original {
				obj.Data = maps.Clone(obj.Data)
				c[id] = obj
			}
			tc.change(c)
			serve(t, c, false)
			expectFailure(t)
		})
	}
}

func TestReadFailuresAndUsage(t *testing.T) {
	setupKubectl(t)
	serve(t, nil, false)
	t.Run("kubectl stderr", func(t *testing.T) { t.Setenv("SEED_TEST_FAILURE", sim); expectFailure(t) })
	t.Run("malformed response", func(t *testing.T) { t.Setenv("SEED_TEST_RECON", "secret-in-response"); expectFailure(t) })
	t.Run("absent items", func(t *testing.T) { t.Setenv("SEED_TEST_BUSINESS", "{}"); expectFailure(t) })
	t.Run("unmanaged name collision", func(t *testing.T) { t.Setenv("SEED_TEST_COLLISION", "secret/backend-private"); expectFailure(t) })
	t.Run("unknown argument", func(t *testing.T) { expectFailure(t, "secret-in-argument") })
}

func TestNamespaceOverrides(t *testing.T) {
	setupKubectl(t)
	for _, name := range []string{"business", "ledger", "reconciliation", "sim"} {
		t.Setenv("AIPAY_DEMO_NS_"+strings.ToUpper(name), "custom-"+name)
	}
	c := generate(t, nil, testTime)
	if c[objectID{"custom-business", configMap, "notifier-inputs"}].Data["allowed-hosts"] != "demo-fixtures.custom-sim.svc.cluster.local" {
		t.Fatal("sim namespace not applied to notifier target")
	}
	market := generate(t, nil, testTime, "market")
	for _, id := range marketObjects {
		id.namespace = namespace(id.namespace)
		if _, ok := market[id]; !ok {
			t.Fatal("market manifest targeted a different namespace")
		}
	}
}
