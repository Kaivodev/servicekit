package main

import (
	"encoding/json"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMarketOnly(t *testing.T) {
	setupKubectl(t)
	c := generate(t, nil, testTime)
	next := generate(t, c, testTime.Add(time.Minute), "market")
	checkInventory(t, next, map[objectID]string{reconInputs: "coverage.json market.json", ledgerInputs: "usd-rates.json", paymentInputs: "rate.json"})
	for _, file := range []struct {
		id        objectID
		name      string
		perMinute int
	}{
		{reconInputs, "market.json", 2}, {ledgerInputs, "usd-rates.json", 1},
	} {
		before := decoded[[]json.RawMessage](t, c[file.id].Data[file.name])
		after := decoded[[]json.RawMessage](t, next[file.id].Data[file.name])
		if len(before) != file.perMinute || len(after) != 2*file.perMinute || !reflect.DeepEqual(before, after[:len(before)]) {
			t.Fatal("lost or duplicated historical observations")
		}
	}
	again := generate(t, next, testTime.Add(time.Minute), "market")
	if !reflect.DeepEqual(next, again) {
		t.Fatal("market refresh not idempotent within one instant")
	}

	// A failed apply left only one source for the current minute. Rebuild the
	// missing observation without adding a second ledger rate or changing the quote ID.
	rows := decoded[[]json.RawMessage](t, next[reconInputs].Data["market.json"])
	next[reconInputs].Data["market.json"] = jsonFile(rows[:3])
	retry := generate(t, next, testTime.Add(65*time.Second), "market")
	if retry[reconInputs].Data["market.json"] != again[reconInputs].Data["market.json"] ||
		retry[paymentInputs].Data["rate.json"] != again[paymentInputs].Data["rate.json"] ||
		retry[ledgerInputs].Data["usd-rates.json"] != again[ledgerInputs].Data["usd-rates.json"] {
		t.Fatal("partial market refresh changed previous observations or snapshot ID")
	}
}

func TestMarketLimits(t *testing.T) {
	for _, tc := range []struct {
		id        objectID
		file, row string
		limit     int
	}{
		{ledgerInputs, "usd-rates.json", `{"asset":"USDT","observed_at":"2026-01-01T00:00:00Z","source_a":"dev-a","rate_a":"1.0000","source_b":"dev-b","rate_b":"0.9999"}`, ledgerLimit},
		{reconInputs, "market.json", `{"source":"okx","minute":"2026-01-01T00:00:00Z","median":"7.2","samples":10}`, marketLimit},
	} {
		for _, bad := range []string{"null", "{}", "[{}]", "secret-in-malformed-history",
			"[" + strings.Repeat(tc.row+",", (tc.limit-3)/(len(tc.row)+1)-1) + tc.row + "]"} {
			old := materials{tc.id: {tc.file: bad}}
			if marketInputs(old, newMaterials(marketObjects), testTime, true) == nil {
				t.Fatalf("accepted invalid or full %s", tc.file)
			}
		}
	}
}

func TestStackParity(t *testing.T) {
	// Exercise the reference implementation at two UTC minutes. Python writes
	// only public market observations in its temporary directory.
	cmd := exec.Command("python3", "-B", "-c", `
import json, pathlib, sys, tempfile
from datetime import datetime, timedelta, timezone
sys.path.insert(0, '../../..')
import stack_config as cfg
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    for service in ('payment', 'ledger', 'reconciliation'):
        (root / 'inputs' / service).mkdir(parents=True)
    now = datetime(2026, 11, 19, 12, 30, 10, 765000, tzinfo=timezone.utc)
    cfg.refresh(root, now)
    cfg.refresh(root, now + timedelta(minutes=1))
    data = {f.name: json.loads(f.read_text()) for f in (root / 'inputs').glob('*/*.json')}
    print(json.dumps(dict(data, routes=cfg.routes())))
`)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal("could not run development stack reference")
	}
	ref := decoded[map[string]json.RawMessage](t, string(out))
	if !reflect.DeepEqual(decoded[any](t, routesJSON), decoded[any](t, string(ref["routes"]))) {
		t.Fatal("embedded IAM routes differ from stack_config.routes(); run go generate")
	}
	first := newMaterials(marketObjects)
	if err := marketInputs(nil, first, testTime, true); err != nil {
		t.Fatal(err)
	}
	second := newMaterials(marketObjects)
	if err := marketInputs(first, second, testTime.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, fields := range second {
		for name, value := range fields {
			files = append(files, name)
			if !reflect.DeepEqual(decoded[any](t, value), decoded[any](t, string(ref[name]))) {
				t.Fatalf("reference mismatch for %s", name)
			}
		}
	}
	slices.Sort(files)
	if strings.Join(files, " ") != "coverage.json market.json rate.json usd-rates.json" {
		t.Fatal("incorrect set of market files")
	}
}
