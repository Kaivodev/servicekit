package marketdata

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, source Source) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/recorded/" + string(source) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type obj = map[string]any

func mutated(t *testing.T, source Source, edit func(obj)) []byte {
	t.Helper()
	var o obj
	if err := json.Unmarshal(fixture(t, source), &o); err != nil {
		t.Fatal(err)
	}
	edit(o)
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func okRows(o obj) []any            { return o["data"].(obj)["sell"].([]any) }
func binRows(o obj) []any           { return o["data"].([]any) }
func editOK(f func(obj)) func(obj)  { return func(o obj) { f(okRows(o)[0].(obj)) } }
func editAdv(f func(obj)) func(obj) { return func(o obj) { f(binRows(o)[0].(obj)["adv"].(obj)) } }

func TestStrictFields(t *testing.T) {
	s, err := testConfig(t).settings()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		source Source
		edit   func(obj)
	}{
		{"ok-code-string", OKX, func(o obj) { o["code"] = "0" }},
		{"ok-code-nonzero", OKX, func(o obj) { o["code"] = 1 }},
		{"sell-object", OKX, func(o obj) { o["data"].(obj)["sell"] = obj{} }},
		{"missing-sell", OKX, func(o obj) { delete(o["data"].(obj), "sell") }},
		{"missing-min", OKX, editOK(func(a obj) { delete(a, "quoteMinAmountPerOrder") })},
		{"side-even-if-filtered", OKX, editOK(func(a obj) { a["creatorType"] = "personal"; a["side"] = "buy" })},
		{"quote", OKX, editOK(func(a obj) { a["quoteCurrency"] = "usd" })},
		{"base", OKX, editOK(func(a obj) { a["baseCurrency"] = "usdc" })},
		{"null-method", OKX, editOK(func(a obj) { a["paymentMethods"] = []any{nil} })},
		{"methods-not-array", OKX, editOK(func(a obj) { a["paymentMethods"] = "aliPay" })},
		{"methods-null", OKX, editOK(func(a obj) { a["paymentMethods"] = nil })},
		{"invalid-c2c-price", OKX, editOK(func(a obj) { a["paymentMethods"] = []string{"wxPay"}; a["price"] = "6e0" })},
		{"invalid-c2c-price-filtered-limit", Binance, editAdv(func(a obj) { a["price"] = "-1" })},
		{"binance-code", Binance, func(o obj) { o["code"] = "0" }},
		{"success-false", Binance, func(o obj) { o["success"] = false }},
		{"success-string", Binance, func(o obj) { o["success"] = "true" }},
		{"data-object", Binance, func(o obj) { o["data"] = obj{} }},
		{"data-null", Binance, func(o obj) { o["data"] = nil }},
		{"missing-advertiser", Binance, func(o obj) { delete(binRows(o)[0].(obj), "advertiser") }},
		{"missing-adv", Binance, func(o obj) { delete(binRows(o)[0].(obj), "adv") }},
		{"numeric-price", Binance, editAdv(func(a obj) { a["price"] = 7 })},
		{"dynamic-null", Binance, editAdv(func(a obj) { a["dynamicMaxSingleTransAmount"] = nil })},
		{"dynamic-number", Binance, editAdv(func(a obj) { a["dynamicMaxSingleTransAmount"] = 7 })},
		{"binance-buy", Binance, editAdv(func(a obj) { a["tradeType"] = "BUY" })},
		{"binance-asset", Binance, editAdv(func(a obj) { a["asset"] = "usdt" })},
		{"binance-fiat", Binance, editAdv(func(a obj) { a["fiatUnit"] = "USD" })},
		{"missing-price", Coinbase, func(o obj) { delete(o, "price") }},
		{"price-null", Coinbase, func(o obj) { o["price"] = nil }},
		{"price-number", Coinbase, func(o obj) { o["price"] = 1 }},
		{"wrong-key", Kraken, func(o obj) { o["result"] = obj{"USDTUSD": o["result"].(obj)["USDTZUSD"]} }},
		{"two-keys", Kraken, func(o obj) { o["result"].(obj)["extra"] = obj{} }},
		{"api-error", Kraken, func(o obj) { o["error"] = []string{"sensitive exchange detail"} }},
		{"null-error", Kraken, func(o obj) { o["error"] = nil }},
		{"no-last", Kraken, func(o obj) { o["result"].(obj)["USDTZUSD"].(obj)["c"] = []any{} }},
		{"numeric-last", Kraken, func(o obj) { o["result"].(obj)["USDTZUSD"].(obj)["c"] = []any{1} }},
		{"out-of-range-last", Kraken, func(o obj) { o["result"].(obj)["USDTZUSD"].(obj)["c"] = []string{"1.50001"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := s.parse(tc.source, mutated(t, tc.source, tc.edit))
			if err == nil || errors.Is(err, errSamples) || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	for _, p := range []string{"-1", "+1", ".9", "1.", "1e0", "1,0", "0", "0.49999", "1.50001", "1.00000000001"} {
		t.Run(p, func(t *testing.T) {
			b := mutated(t, Coinbase, func(o obj) { o["price"] = p })
			if _, _, err := s.parse(Coinbase, b); err == nil {
				t.Fatal("accepted price", p)
			}
		})
	}
}

func fetchBook(t *testing.T, source Source, edit func(obj)) attemptResult {
	t.Helper()
	body := mutated(t, source, edit)
	c := newCollector(t, testConfig(t), single(source), &records{}, nil, io.Discard)
	c.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	return c.fetch(t.Context(), source, testMinute, 1)
}

func bookAds(o obj, source Source) []obj {
	var ads []obj
	if source == OKX {
		for _, row := range okRows(o) {
			ads = append(ads, row.(obj))
		}
	} else {
		for _, row := range binRows(o) {
			ads = append(ads, row.(obj)["adv"].(obj))
		}
	}
	return ads
}

func setMethods(a obj, source Source, ids ...string) {
	if source == OKX {
		a["paymentMethods"] = ids
		return
	}
	methods := make([]obj, len(ids))
	for i, id := range ids {
		methods[i] = obj{"identifier": id}
	}
	a["tradeMethods"] = methods
}

func TestBookPaymentFilter(t *testing.T) {
	for _, tc := range []struct {
		source                 Source
		other, wrongCase, bank string
		wantSamples            int
	}{
		{OKX, "wxPay", "ALIPAY", "bank", 16},
		{Binance, "WECHAT", "bank", "BANK", 11},
	} {
		t.Run(string(tc.source), func(t *testing.T) {
			r := fetchBook(t, tc.source, func(o obj) {
				ads := bookAds(o, tc.source)
				for _, a := range ads[2:4] {
					setMethods(a, tc.source, tc.other)
				}
				setMethods(ads[4], tc.source, tc.wrongCase)
				setMethods(ads[6], tc.source, tc.other, tc.bank)
			})
			if r.Outcome != OK || r.Observation.Samples != tc.wantSamples {
				t.Fatalf("partial filter: outcome=%s samples=%d", r.Outcome, r.samples)
			}
			r = fetchBook(t, tc.source, func(o obj) {
				for _, a := range bookAds(o, tc.source) {
					setMethods(a, tc.source, tc.other)
				}
			})
			if r.Outcome != InsufficientSamples || r.samples != 0 || !strings.Contains(r.Detail, "before=20 after=0") {
				t.Fatalf("all filtered: outcome=%s detail=%s", r.Outcome, r.Detail)
			}
		})
	}
}

func TestBinanceTradeMethodsShape(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods any
	}{
		{"missing", nil},
		{"null", json.RawMessage("null")},
		{"not-array", obj{"identifier": "ALIPAY"}},
		{"not-object", []string{"BANK"}},
		{"null-element", []any{nil}},
		{"missing-identifier-after-match", []obj{{"identifier": "BANK"}, {}}},
		{"numeric-identifier", []obj{{"identifier": 1}}},
		{"null-identifier", []obj{{"identifier": nil}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fetchBook(t, Binance, editAdv(func(a obj) {
				if tc.methods == nil {
					delete(a, "tradeMethods")
				} else {
					a["tradeMethods"] = tc.methods
				}
			}))
			if r.Outcome != ParseError {
				t.Fatal(r.Outcome)
			}
		})
	}
}

func TestBookPriceFiltering(t *testing.T) {
	for _, tc := range []struct {
		source      Source
		wantSamples int
		median      string
	}{{OKX, 17, "6.71"}, {Binance, 12, "6.7"}} {
		t.Run(string(tc.source), func(t *testing.T) {
			r := fetchBook(t, tc.source, func(o obj) {
				ads := bookAds(o, tc.source)
				ads[2]["price"], ads[3]["price"] = "2.99999", "15.00001"
			})
			if r.Outcome != OK || r.Observation.Samples != tc.wantSamples || r.Observation.Value != tc.median {
				t.Fatalf("outliers: outcome=%s observation=%+v", r.Outcome, r.Observation)
			}
			r = fetchBook(t, tc.source, func(o obj) {
				for _, a := range bookAds(o, tc.source) {
					// Recorded prices have two fractional digits. Convert yuan to cents.
					a["price"] = strings.Replace(a["price"].(string), ".", "", 1)
				}
			})
			if r.Outcome != InsufficientSamples || r.samples != 0 || !strings.Contains(r.Detail, "before=20 after=0") {
				t.Fatalf("prices in cents: outcome=%s detail=%s", r.Outcome, r.Detail)
			}
		})
	}
}

func TestFilteringAndMedian(t *testing.T) {
	s, _ := testConfig(t).settings()
	for _, source := range []Source{OKX, Binance} {
		b := mutated(t, source, func(o obj) {
			if source == OKX {
				o["data"].(obj)["sell"] = []any{}
			} else {
				o["data"] = []any{}
			}
		})
		_, n, err := s.parse(source, b)
		if n != 0 || !errors.Is(err, errSamples) || !strings.Contains(err.Error(), "before=0 after=0") {
			t.Fatalf("empty %s: %v", source, err)
		}
	}
	// Both intersection endpoints, non-merchant toggle, and an exact even median.
	b := mutated(t, OKX, func(o obj) {
		rows := okRows(o)[:3]
		o["data"].(obj)["sell"] = rows
		for i, row := range rows {
			a := row.(obj)
			a["side"], a["quoteCurrency"], a["baseCurrency"] = "SELL", "CNY", "USDT"
			a["price"] = []string{"6.70", "6.71", "6.82"}[i]
		}
		rows[0].(obj)["quoteMinAmountPerOrder"], rows[0].(obj)["quoteMaxAmountPerOrder"] = "50000", "51000"
		rows[1].(obj)["quoteMinAmountPerOrder"], rows[1].(obj)["quoteMaxAmountPerOrder"] = "0", "100"
		rows[2].(obj)["creatorType"] = "personal"
	})
	_, n, err := s.parse(OKX, b)
	if n != 2 || !errors.Is(err, errSamples) || !strings.Contains(err.Error(), "before=3 after=2") {
		t.Fatal(n, err)
	}
	s.minSamples = 2
	v, n, err := s.parse(OKX, b)
	if v != "6.705" || n != 2 || err != nil {
		t.Fatal(v, n, err)
	}
	s.certifiedOnly = false
	v, n, err = s.parse(OKX, b)
	if v != "6.71" || n != 3 || err != nil {
		t.Fatal(v, n, err)
	}

	// Ignore even an invalid row beyond the first 20.
	b = mutated(t, Binance, func(o obj) { o["data"] = append(binRows(o), nil) })
	v, n, err = s.parse(Binance, b)
	if v != "6.7" || n != 14 || err != nil {
		t.Fatal(v, n, err)
	}
	s.minSamples = 1
	for _, dynamic := range []any{"absent", "", "99", "100"} {
		b = mutated(t, Binance, func(o obj) {
			rows := binRows(o)[:1]
			o["data"] = rows
			a := rows[0].(obj)["adv"].(obj)
			a["minSingleTransAmount"], a["maxSingleTransAmount"] = "1", "50000"
			a["dynamicMaxSingleTransAmount"] = dynamic
			if dynamic == "absent" {
				delete(a, "dynamicMaxSingleTransAmount")
			}
			rows[0].(obj)["advertiser"].(obj)["userType"] = "individual"
		})
		s.certifiedOnly = true
		if _, n, err := s.parse(Binance, b); n != 0 || !errors.Is(err, errSamples) {
			t.Fatal(n, err)
		}
		s.certifiedOnly = false
		_, n, err = s.parse(Binance, b)
		if dynamic == "99" {
			if n != 0 || !errors.Is(err, errSamples) {
				t.Fatal(n, err)
			}
		} else if n != 1 || err != nil {
			t.Fatal(n, err)
		}
	}
	b = mutated(t, OKX, func(o obj) {
		rows := okRows(o)[:2]
		o["data"].(obj)["sell"] = rows
		rows[0].(obj)["price"], rows[1].(obj)["price"] = "6.0000000001", "6.0000000002"
	})
	if _, _, err := s.parse(OKX, b); err == nil {
		t.Fatal("rounded inexact median")
	}
}

func TestCanonicalDecimalEndpoints(t *testing.T) {
	s, _ := testConfig(t).settings()
	for _, tc := range []struct{ raw, want string }{{"000.5000", "0.5"}, {"01.500", "1.5"}, {"0001", "1"}, {"0001.0000000000", "1"}} {
		v, n, err := s.parse(Coinbase, mutated(t, Coinbase, func(o obj) { o["price"] = tc.raw }))
		if err != nil || n != 1 || v != tc.want {
			t.Fatal(tc.raw, v, n, err)
		}
	}
	s.minSamples = 1
	for _, p := range []string{"3", "15"} {
		b := mutated(t, OKX, func(o obj) { rows := okRows(o)[:1]; rows[0].(obj)["price"] = p; o["data"].(obj)["sell"] = rows })
		v, n, err := s.parse(OKX, b)
		if v != p || n != 1 || err != nil {
			t.Fatal(v, n, err)
		}
	}
}
