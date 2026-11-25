package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/Kaivodev/servicekit/dev/tools/internal/devchain"
)

// Generated from stack_config.routes(), including dev/portal-routes.json. The binary
// can run outside a checkout. TestStackParity verifies the embedded copy.
//go:generate python3 -B -c "import json,pathlib,sys; sys.path.insert(0,'../../..'); import stack_config; pathlib.Path('routes.json').write_text('[\\n' + ',\\n'.join('  ' + json.dumps(row, ensure_ascii=False) for row in stack_config.routes()) + '\\n]\\n')"

//go:embed routes.json
var routesJSON string

type simAccount struct {
	ID     string `json:"id"`
	Style  string `json:"style"`
	Shared string `json:"shared_secret"`
	Query  string `json:"query_shared_secret"`
}

type simConfig struct {
	Environment string       `json:"environment"`
	Listen      string       `json:"listen"`
	BaseURL     string       `json:"base_url"`
	Control     string       `json:"control_token"`
	Accounts    []simAccount `json:"accounts"`
}

type credential struct {
	Secrets fields `json:"secrets"`
}
type pluginConfig struct {
	Credentials map[string]credential `json:"credentials"`
	EvidenceKey string                `json:"evidence_key"`
}

func jsonFile(v any) string {
	// Callers supply only JSON strings, booleans, integers or validated raw JSON.
	data, err := json.Marshal(v)
	if err != nil {
		panic("invalid internal JSON value")
	}
	return string(data) + "\n"
}

// Resolve either surviving endpoint first. An existing malformed file is never
// treated as evidence that its keys should be regenerated.
func pairedSecret(left, right string) (string, error) {
	if left != "" && right != "" && left != right {
		return "", errors.New("simulator credential pair does not match")
	}
	if left != "" {
		return left, nil
	}
	if right != "" {
		return right, nil
	}
	return randomHex(), nil
}

func simulatorInputs(old, result materials) error {
	var account simAccount
	simFile, hasSim := old[simPrivate]["config.json"]
	if hasSim {
		var c simConfig
		if jsonv2.Unmarshal([]byte(simFile), &c) != nil || c.Environment != "test" || c.Listen != "0.0.0.0:9080" ||
			c.BaseURL != "http://127.0.0.1:9080" || len(c.Control) < 16 || len(c.Accounts) != 1 {
			return invalid(simPrivate, "config.json")
		}
		account = c.Accounts[0]
		if account.ID != "md5-demo" || account.Style != "form-md5" || account.Shared == "" || account.Query == "" {
			return invalid(simPrivate, "config.json")
		}
	}
	var pluginShared string
	var plugins pluginConfig
	pluginFile, hasPlugin := old[paymentPrivate]["plugins.json"]
	if hasPlugin {
		if jsonv2.Unmarshal([]byte(pluginFile), &plugins) != nil || !encoded32(base64.StdEncoding, plugins.EvidenceKey) {
			return invalid(paymentPrivate, "plugins.json")
		}
		raw, err := base64.StdEncoding.DecodeString(plugins.Credentials["sim-md5-v1"].Secrets["shared"])
		if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
			return invalid(paymentPrivate, "plugins.json")
		}
		pluginShared = string(raw)
	}
	var query fields
	queryFile, hasQuery := old[handoff]["query.json"]
	if hasQuery && (jsonv2.Unmarshal([]byte(queryFile), &query) != nil || query["query_key"] == "") {
		return invalid(handoff, "query.json")
	}
	shared, err := pairedSecret(account.Shared, pluginShared)
	if err != nil {
		return invalid(paymentPrivate, "plugins.json")
	}
	readOnly, err := pairedSecret(account.Query, query["query_key"])
	if err != nil {
		return invalid(handoff, "query.json")
	}
	if shared == readOnly {
		return errors.New("transaction and query credentials must be independent")
	}

	if !hasPlugin {
		plugins = pluginConfig{map[string]credential{"sim-md5-v1": {fields{"shared": base64.StdEncoding.EncodeToString([]byte(shared))}}}, randomBase64()}
		pluginFile = jsonFile(plugins)
	}
	evidence, _ := base64.StdEncoding.DecodeString(plugins.EvidenceKey)
	for _, peer := range []string{shared, readOnly} {
		raw, err := hex.DecodeString(peer)
		if string(evidence) == peer || (err == nil && string(evidence) == string(raw)) {
			return invalid(paymentPrivate, "plugins.json")
		}
	}
	if !hasSim {
		simFile = jsonFile(simConfig{"test", "0.0.0.0:9080", "http://127.0.0.1:9080", randomURL(),
			[]simAccount{{"md5-demo", "form-md5", shared, readOnly}}})
	}
	if !hasQuery {
		queryFile = jsonFile(fields{"query_key": readOnly})
	}
	result[simPrivate]["config.json"] = simFile
	result[paymentPrivate]["plugins.json"] = pluginFile
	result[handoff]["query.json"] = queryFile
	return nil
}

func seedInputs(old, result materials, now time.Time) error {
	// Bring devchain up before IAM has enrolled a seller. A later bootstrap
	// publishes the live chain at its resourceVersion, preserving driver-owned keys.
	chain, exists := old[bootstrapDataset]["chain.json"]
	if !exists {
		if len(old[bootstrapDataset]) != 0 {
			return invalid(bootstrapDataset, "chain.json")
		}
		chain = `{"chain_id":31337,"finalized":0,"blocks":[{"number":"0x0","hash":"0x5f0d9193a57369a69324c793ef1684dbce61da4fa2e64b85f0b8ef24a0f926ee","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x0","transactions":[]}],"receipts":{}}` + "\n"
	}
	if _, err := devchain.Parse([]byte(chain), ""); err != nil {
		return invalid(bootstrapDataset, "chain.json")
	}
	result[bootstrapDataset]["chain.json"] = chain
	if err := opaqueKeys(old, result); err != nil {
		return err
	}
	if err := simulatorInputs(old, result); err != nil {
		return err
	}
	fixtureHost := "demo-fixtures." + namespace(sim) + ".svc.cluster.local"
	result[backendInputs]["bot-api-base-url"] = "http://" + fixtureHost + ":8081"
	result[notifierInputs]["egress-proxy"] = "http://" + fixtureHost + ":3128"
	result[notifierInputs]["allowed-hosts"] = fixtureHost
	result[iamInputs]["routes.json"] = routesJSON
	since, ok := old[iamInputs]["signer-valid-from"]
	if !ok {
		since = stamp(now)
	}
	if start, err := time.Parse(time.RFC3339Nano, since); err != nil || start.Nanosecond()%1000 != 0 {
		return invalid(iamInputs, "signer-valid-from")
	}
	result[iamInputs]["signer-valid-from"] = since
	reviews, ok := old[paymentInputs]["seller-reviews.json"]
	if !ok {
		reviews = "[]\n"
	}
	var rows []json.RawMessage
	if json.Unmarshal([]byte(reviews), &rows) != nil || rows == nil {
		return invalid(paymentInputs, "seller-reviews.json")
	}
	result[paymentInputs]["seller-reviews.json"] = reviews
	return nil
}
