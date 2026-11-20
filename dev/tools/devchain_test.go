package tools_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kaivodev/servicekit/dev/tools/internal/devchain"
)

func TestChainProjection(t *testing.T) {
	dir := fixtures(t)
	file := filepath.Join(dir, "chain.json")
	d, err := devchain.Load(file, "")
	if err != nil {
		t.Fatal(err)
	}
	claim := readClaim(t, filepath.Join(dir, "scenario.json"), "mismatch")
	// The server can start and handle every RPC with the producer input absent.
	if err = os.Remove(filepath.Join(dir, "scenario.json")); err != nil {
		t.Fatal(err)
	}
	call := func(method, params string) map[string]json.RawMessage {
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"jsonrpc":"2.0","id":"req","method":"`+method+`","params":`+params+`}`))
		w := httptest.NewRecorder()
		d.ServeHTTP(w, r)
		var reply map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || string(reply["id"]) != `"req"` {
			t.Fatal("invalid RPC response", err)
		}
		return reply
	}
	if got := string(call("eth_chainId", "null")["result"]); got != `"0x7a69"` {
		t.Fatal(got)
	}
	block := func(tag string, want int) {
		t.Helper()
		got := call("eth_getBlockByNumber", `["`+tag+`",false]`)["result"]
		if string(got) != string(d.Blocks[want]) {
			t.Fatalf("%s: %s", tag, got)
		}
	}
	block("latest", 3)
	block("finalized", 2)
	block("0x1", 1)
	d, err = devchain.Load(file, "0")
	if err != nil {
		t.Fatal(err)
	}
	block("finalized", 0)
	if _, err := devchain.Load(file, "4"); err == nil {
		t.Fatal("accepted invalid finalized height")
	}
	tx := claim.ChainTransactionId
	got := call("eth_getTransactionReceipt", `["`+tx+`"]`)["result"]
	if string(got) != string(d.Receipts[tx]) {
		t.Fatal("incorrect RPC receipt")
	}
	var receipt struct {
		Logs []struct {
			LogIndex, Address, Data string
			Topics                  []string
		}
	}
	if json.Unmarshal(got, &receipt) != nil || len(receipt.Logs) != 1 {
		t.Fatal("missing transfer log")
	}
	log := receipt.Logs[0]
	if log.LogIndex != "0x1" || log.Address != claim.Asset.ContractAddress || len(log.Topics) != 3 || len(log.Data) != 66 {
		t.Fatal("invalid ERC-20 log")
	}
	if got := string(call("eth_getTransactionReceipt", `["0x`+strings.Repeat("0", 64)+`"]`)["result"]); got != "null" {
		t.Fatal(got)
	}
	if got := string(call("eth_getBalance", "[]")["error"]); !strings.Contains(got, "-32601") {
		t.Fatal(got)
	}
}
