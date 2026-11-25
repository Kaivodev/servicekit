package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"time"
)

const (
	marketLimit = 1 << 20
	ledgerLimit = 64 << 10
)

func stamp(t time.Time) string {
	t = t.UTC().Truncate(time.Microsecond)
	if t.Nanosecond() == 0 {
		return t.Format(time.RFC3339)
	}
	return t.Format("2006-01-02T15:04:05.000000Z")
}

// Same UUIDv7 as stack_config.minute_snapshot_id: 48 timestamp bits and
// 74 bits taken from the SHA-256 of this UTC minute.
func snapshotID(minute time.Time) string {
	h := sha256.Sum256([]byte("kaivo-dev-rate:" + stamp(minute)))
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], uint64(minute.UnixMilli())<<16)
	id[6] = 0x70 | h[0]>>4
	id[7] = h[0]<<4 | h[1]>>4
	copy(id[8:], h[2:10])
	id[8] = 0x80 | id[8]&0x3f
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func history(old materials, id objectID, file string, limit int) ([]json.RawMessage, error) {
	data, ok := old[id][file]
	if !ok {
		return []json.RawMessage{}, nil
	}
	var rows []json.RawMessage
	if len(data) > limit || json.Unmarshal([]byte(data), &rows) != nil || rows == nil {
		return nil, invalid(id, file)
	}
	return rows, nil
}

func marketInputs(old, result materials, now time.Time, refresh bool) error {
	observations, err := history(old, reconInputs, "market.json", marketLimit)
	if err != nil {
		return err
	}
	usd, err := history(old, ledgerInputs, "usd-rates.json", ledgerLimit)
	if err != nil {
		return err
	}

	end := now.UTC().Truncate(time.Minute)
	minute := end.Add(-time.Minute)
	at := stamp(minute)
	sources := map[string]bool{}
	for _, raw := range observations {
		var row struct{ Source, Minute string }
		if json.Unmarshal(raw, &row) != nil || row.Source == "" || row.Minute == "" {
			return invalid(reconInputs, "market.json")
		}
		if row.Minute == at {
			sources[row.Source] = true
		}
	}
	haveUSD := false
	for _, raw := range usd {
		var row struct {
			Asset      string
			ObservedAt string `json:"observed_at"`
		}
		if json.Unmarshal(raw, &row) != nil || row.Asset == "" || row.ObservedAt == "" {
			return invalid(ledgerInputs, "usd-rates.json")
		}
		if row.Asset == "USDT" && row.ObservedAt == at {
			haveUSD = true
		}
	}

	// A complete bootstrap replay does not refresh quotes or take fields back
	// from the market field manager. A partial bootstrap repairs all four together.
	if !refresh && old[reconInputs]["market.json"] != "" && old[reconInputs]["coverage.json"] != "" &&
		old[paymentInputs]["rate.json"] != "" && old[ledgerInputs]["usd-rates.json"] != "" {
		result[reconInputs]["market.json"] = old[reconInputs]["market.json"]
		result[reconInputs]["coverage.json"] = old[reconInputs]["coverage.json"]
		result[paymentInputs]["rate.json"] = old[paymentInputs]["rate.json"]
		result[ledgerInputs]["usd-rates.json"] = old[ledgerInputs]["usd-rates.json"]
		return nil
	}
	key := snapshotID(minute)
	rate := map[string]any{"rate_snapshot_id": key, "minute": at, "collected_at": stamp(end),
		"usable_for_quoting": true, "expires_at": stamp(minute.Add(10 * time.Minute))}
	for _, quote := range []struct{ source, median string }{{"okx", "7.2"}, {"binance", "7.21"}} {
		rate[quote.source+"_median"] = fields{"base_currency": "USDT", "quote_currency": "CNY", "value": quote.median, "version_id": key}
		rate[quote.source+"_sample_count"] = 10
		if !sources[quote.source] {
			h := sha256.Sum256([]byte("development " + quote.source + " " + at + " " + quote.median))
			row := map[string]any{"source": quote.source, "minute": at, "median": quote.median, "samples": 10,
				"collected_at": stamp(end), "recorded_at": stamp(end), "raw_sha256": base64.StdEncoding.EncodeToString(h[:])}
			observations = append(observations, json.RawMessage(jsonFile(row)))
		}
	}
	market := jsonFile(observations)
	coverage := jsonFile(map[string]any{"covered": true, "as_of": stamp(now), "expires_at": stamp(now.Add(time.Hour))})
	// stack_config.refresh measures json.dumps(records) with Python's default
	// comma/colon spacing; the two actual ConfigMap values must fit as well.
	spaced := jsontext.Value(market)
	if err := spaced.Format(jsontext.SpaceAfterComma(true), jsontext.SpaceAfterColon(true)); err != nil {
		return invalid(reconInputs, "market.json")
	}
	if len(spaced) >= marketLimit || len(market)+len(coverage) > marketLimit {
		return errors.New("market history is full; archive completed minutes before refreshing")
	}
	dollars := old[ledgerInputs]["usd-rates.json"]
	if !haveUSD {
		usd = append(usd, json.RawMessage(jsonFile(fields{"asset": "USDT", "source_a": "dev-a", "rate_a": "1.0000", "source_b": "dev-b",
			"rate_b": "0.9999", "observed_at": at})))
		dollars = jsonFile(usd)
	}
	if len(dollars) > ledgerLimit {
		return errors.New("ledger USD rate history is full; archive completed minutes before refreshing")
	}
	result[reconInputs]["market.json"] = market
	result[reconInputs]["coverage.json"] = coverage
	result[paymentInputs]["rate.json"] = jsonFile(rate)
	result[ledgerInputs]["usd-rates.json"] = dollars
	return nil
}
