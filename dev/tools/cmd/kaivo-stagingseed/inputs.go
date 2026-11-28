package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"math/big"
	"strings"
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
	Query  string `json:"query_shared_secret,omitempty"`
	PID    int    `json:"pid,omitzero"`
	// Preserve simulator-owned settings such as a seeded order scenario on upgrade.
	Extra jsontext.Value `json:",embed"`
}

type simConfig struct {
	Environment string         `json:"environment"`
	Listen      string         `json:"listen"`
	BaseURL     string         `json:"base_url"`
	Control     string         `json:"control_token"`
	Accounts    []simAccount   `json:"accounts"`
	Extra       jsontext.Value `json:",embed"`
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

const merchantKeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func validMerchantKey(key string) bool {
	return len(key) == 32 && strings.Trim(key, merchantKeyAlphabet) == ""
}

// EPay V1 uses the same merchant key for payment and verification. Recover
// either surviving copy before creating one on a fresh or form-md5-only seed.
func epayMerchantKey(accountKey string, old fields) (string, error) {
	if file, ok := old["epay.json"]; ok {
		var cred fields
		if jsonv2.Unmarshal([]byte(file), &cred) != nil || len(cred) != 1 || !validMerchantKey(cred["merchant_key"]) ||
			(accountKey != "" && accountKey != cred["merchant_key"]) {
			return "", invalid(handoff, "epay.json")
		}
		return cred["merchant_key"], nil
	}
	if accountKey != "" {
		return accountKey, nil
	}
	var key [32]byte
	limit := big.NewInt(int64(len(merchantKeyAlphabet)))
	for i := range key {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", errors.New("could not generate simulator merchant key")
		}
		key[i] = merchantKeyAlphabet[n.Int64()]
	}
	return string(key[:]), nil
}

func simulatorInputs(old, result materials) error {
	var cfg simConfig
	var account, epay simAccount
	simFile, hasSim := old[simPrivate]["config.json"]
	if hasSim {
		if jsonv2.Unmarshal([]byte(simFile), &cfg) != nil || cfg.Environment != "test" || cfg.Listen != "0.0.0.0:9080" ||
			cfg.BaseURL != "http://127.0.0.1:9080" || len(cfg.Control) < 16 {
			return invalid(simPrivate, "config.json")
		}
		for _, a := range cfg.Accounts {
			switch {
			case a.ID == "md5-demo" && a.Style == "form-md5" && a.Shared != "" && a.Query != "" && a.PID == 0 && account.ID == "":
				account = a
			case a.ID == "epay-demo" && a.Style == "epay-v1" && a.PID == 1001 && validMerchantKey(a.Shared) && a.Query == "" && epay.ID == "":
				epay = a
			default:
				return invalid(simPrivate, "config.json")
			}
		}
		if account.ID == "" {
			return invalid(simPrivate, "config.json")
		}
	}
	// The demo reads the trade handoff from md5-demo in the simulator Secret.
	// Recover the old key if a previous bootstrap stopped before publishing that Secret.
	shared := account.Shared
	if !hasSim {
		if legacy, ok := old[paymentPrivate]["plugins.json"]; ok {
			var cfg struct {
				Credentials map[string]struct {
					Secrets fields `json:"secrets"`
				} `json:"credentials"`
			}
			if err := jsonv2.Unmarshal([]byte(legacy), &cfg); err != nil {
				return invalid(paymentPrivate, "plugins.json")
			}
			raw, err := base64.StdEncoding.DecodeString(cfg.Credentials["sim-md5-v1"].Secrets["shared"])
			if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
				return invalid(paymentPrivate, "plugins.json")
			}
			shared = string(raw)
		} else {
			shared = randomHex()
		}
	}
	var query fields
	queryFile, hasQuery := old[handoff]["query.json"]
	if hasQuery && (jsonv2.Unmarshal([]byte(queryFile), &query) != nil || query["query_key"] == "") {
		return invalid(handoff, "query.json")
	}
	readOnly, err := pairedSecret(account.Query, query["query_key"])
	if err != nil {
		return invalid(handoff, "query.json")
	}
	if shared == readOnly {
		return errors.New("transaction and query credentials must be independent")
	}

	if !hasSim {
		cfg = simConfig{Environment: "test", Listen: "0.0.0.0:9080", BaseURL: "http://127.0.0.1:9080", Control: randomURL(),
			Accounts: []simAccount{{ID: "md5-demo", Style: "form-md5", Shared: shared, Query: readOnly}}}
	}
	merchantKey, err := epayMerchantKey(epay.Shared, old[handoff])
	if err != nil {
		return err
	}
	if epay.ID == "" {
		cfg.Accounts = append(cfg.Accounts, simAccount{ID: "epay-demo", Style: "epay-v1", PID: 1001, Shared: merchantKey})
		data, err := jsonv2.Marshal(cfg)
		if err != nil {
			return invalid(simPrivate, "config.json")
		}
		simFile = string(data) + "\n"
	}
	if !hasQuery {
		queryFile = jsonFile(fields{"query_key": readOnly})
	}
	result[simPrivate]["config.json"] = simFile
	result[handoff]["query.json"] = queryFile
	epayFile, ok := old[handoff]["epay.json"]
	if !ok {
		epayFile = jsonFile(fields{"merchant_key": merchantKey})
	}
	result[handoff]["epay.json"] = epayFile
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
