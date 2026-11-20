// Package devchain serves the read-only RPC projection generated from the chain fixture.
package devchain

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Dataset struct {
	ChainID   int                        `json:"chain_id"`
	Finalized uint64                     `json:"finalized"`
	Blocks    []json.RawMessage          `json:"blocks"`
	Receipts  map[string]json.RawMessage `json:"receipts"`
}

func Load(path string, override string) (*Dataset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read chain dataset failed")
	}
	var d Dataset
	if json.Unmarshal(data, &d) != nil || d.ChainID != 31337 || len(d.Blocks) == 0 || d.Receipts == nil {
		return nil, errors.New("invalid development chain dataset")
	}
	parent := "0x" + strings.Repeat("00", 32)
	for i, raw := range d.Blocks {
		var b struct{ Number, Hash, ParentHash string }
		if json.Unmarshal(raw, &b) != nil || b.Number != quantity(uint64(i)) || len(b.Hash) != 66 || b.ParentHash != parent {
			return nil, errors.New("invalid canonical block chain")
		}
		parent = b.Hash
	}
	if override != "" {
		d.Finalized, err = strconv.ParseUint(override, 10, 64)
	}
	if err != nil || d.Finalized >= uint64(len(d.Blocks)) {
		return nil, errors.New("finalized height outside dataset")
	}
	return &d, nil
}

func quantity(n uint64) string { return "0x" + strconv.FormatUint(n, 16) }

type request struct {
	Version string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (d *Dataset) call(req request) (any, *rpcError) {
	bad := &rpcError{-32602, "Invalid params"}
	var arg string
	switch req.Method {
	case "eth_chainId":
		if len(req.Params) != 0 {
			return nil, bad
		}
		return quantity(uint64(d.ChainID)), nil
	case "eth_getBlockByNumber":
		if len(req.Params) != 2 || json.Unmarshal(req.Params[0], &arg) != nil || string(req.Params[1]) != "false" {
			return nil, bad
		}
		var height uint64
		switch arg {
		case "latest":
			height = uint64(len(d.Blocks) - 1)
		case "finalized":
			height = d.Finalized
		default:
			n, err := strconv.ParseUint(strings.TrimPrefix(arg, "0x"), 16, 64)
			if err != nil || quantity(n) != arg {
				return nil, bad
			}
			height = n
		}
		if height >= uint64(len(d.Blocks)) {
			return nil, nil
		}
		return d.Blocks[height], nil
	case "eth_getTransactionReceipt":
		if len(req.Params) != 1 || json.Unmarshal(req.Params[0], &arg) != nil {
			return nil, bad
		}
		return d.Receipts[strings.ToLower(arg)], nil
	default:
		return nil, &rpcError{-32601, "Method not found"}
	}
}

func (d *Dataset) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req request
	var result any
	var problem *rpcError
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	switch {
	case err != nil || !json.Valid(data):
		problem = &rpcError{-32700, "Parse error"}
	case json.Unmarshal(data, &req) != nil || req.Version != "2.0" || req.Method == "":
		problem = &rpcError{-32600, "Invalid Request"}
	default:
		result, problem = d.call(req)
	}
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if problem != nil {
		response["error"] = problem
	} else {
		response["result"] = result
	}
	_ = json.NewEncoder(w).Encode(response)
}
