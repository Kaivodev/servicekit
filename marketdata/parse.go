package marketdata

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
)

type object map[string]json.RawMessage

var (
	zeroCode     = regexp.MustCompile(`^-?0(\.0+)?([Ee][+-]?[0-9]+)?$`)
	errShape     = errors.New("invalid response fields or types")
	errMarket    = errors.New("unexpected market or trade direction")
	errDecimal   = errors.New("invalid decimal")
	errRange     = errors.New("price outside expected range")
	errSamples   = errors.New("insufficient samples")
	inputDecimal = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

// A JSON null is never a valid required field, including array elements.
func decode[T any](raw json.RawMessage) (T, error) {
	var value T
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil {
		return value, errShape
	}
	return value, nil
}

func stringFields(o object, keys ...string) (map[string]string, error) {
	fields := make(map[string]string, len(keys))
	for _, k := range keys {
		v, err := decode[string](o[k])
		if err != nil {
			return nil, err
		}
		fields[k] = v
	}
	return fields, nil
}

func decimal(s string) (*big.Rat, error) {
	if !inputDecimal.MatchString(s) {
		return nil, errDecimal
	}
	// Discard insignificant digits before constructing the rational. This also
	// keeps exchange padding from inflating the numerator and denominator.
	s = strings.TrimLeft(s, "0")
	if strings.Contains(s, ".") {
		s = strings.TrimSuffix(strings.TrimRight(s, "0"), ".")
	}
	if s == "" {
		return new(big.Rat), nil
	}
	v, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errDecimal
	}
	return v, nil
}

func inBookPriceRange(v *big.Rat) bool {
	return v.Cmp(big.NewRat(3, 1)) >= 0 && v.Cmp(big.NewRat(15, 1)) <= 0
}

func normalized(v *big.Rat) (string, error) {
	places, exact := v.FloatPrec()
	if !exact || places > 10 {
		return "", errors.New("price exceeds decimal precision")
	}
	return v.FloatString(places), nil
}

type ad struct {
	price, min, max string
	certified       bool
	acceptsPayment  bool
}

func okxAd(row json.RawMessage) (ad, error) {
	o, err := decode[object](row)
	if err != nil {
		return ad{}, err
	}
	f, err := stringFields(o, "price", "quoteMinAmountPerOrder", "quoteMaxAmountPerOrder", "creatorType", "side", "quoteCurrency", "baseCurrency")
	if err != nil {
		return ad{}, err
	}
	methods, err := decode[[]json.RawMessage](o["paymentMethods"])
	if err != nil {
		return ad{}, err
	}
	var acceptsPayment bool
	for _, m := range methods {
		method, err := decode[string](m)
		if err != nil {
			return ad{}, err
		}
		if method == "aliPay" || method == "bank" {
			acceptsPayment = true
		}
	}
	if !strings.EqualFold(f["side"], "sell") || !strings.EqualFold(f["quoteCurrency"], "cny") || !strings.EqualFold(f["baseCurrency"], "usdt") {
		return ad{}, errMarket
	}
	return ad{
		price:          f["price"],
		min:            f["quoteMinAmountPerOrder"],
		max:            f["quoteMaxAmountPerOrder"],
		certified:      f["creatorType"] == "certified" || f["creatorType"] == "diamond",
		acceptsPayment: acceptsPayment,
	}, nil
}

func binanceAd(row json.RawMessage) (ad, error) {
	o, err := decode[object](row)
	if err != nil {
		return ad{}, err
	}
	adv, err := decode[object](o["adv"])
	if err != nil {
		return ad{}, err
	}
	f, err := stringFields(adv, "price", "minSingleTransAmount", "maxSingleTransAmount", "tradeType", "asset", "fiatUnit")
	if err != nil {
		return ad{}, err
	}
	advertiser, err := decode[object](o["advertiser"])
	if err != nil {
		return ad{}, err
	}
	kind, err := decode[string](advertiser["userType"])
	if err != nil {
		return ad{}, err
	}
	if f["tradeType"] != "SELL" || f["asset"] != "USDT" || f["fiatUnit"] != "CNY" {
		return ad{}, errMarket
	}
	maximum := f["maxSingleTransAmount"]
	if raw, ok := adv["dynamicMaxSingleTransAmount"]; ok {
		dynamic, err := decode[string](raw)
		if err != nil {
			return ad{}, err
		}
		if dynamic != "" {
			maximum = dynamic
		}
	}
	methods, err := decode[[]object](adv["tradeMethods"])
	if err != nil {
		return ad{}, err
	}
	var acceptsPayment bool
	for _, m := range methods {
		id, err := decode[string](m["identifier"])
		if err != nil {
			return ad{}, err
		}
		if id == "ALIPAY" || id == "BANK" {
			acceptsPayment = true
		}
	}
	return ad{
		price:          f["price"],
		min:            f["minSingleTransAmount"],
		max:            maximum,
		certified:      kind == "merchant",
		acceptsPayment: acceptsPayment,
	}, nil
}

func (s settings) book(source Source, top object) (string, int, error) {
	var list json.RawMessage
	readAd := okxAd
	if source == OKX {
		if !zeroCode.Match(top["code"]) {
			return "", 0, errShape
		}
		data, err := decode[object](top["data"])
		if err != nil {
			return "", 0, err
		}
		list = data["sell"]
	} else {
		code, err := decode[string](top["code"])
		success, okErr := decode[bool](top["success"])
		if err != nil || code != "000000" || okErr != nil || !success {
			return "", 0, errShape
		}
		list = top["data"]
		readAd = binanceAd
	}
	rows, err := decode[[]json.RawMessage](list)
	if err != nil {
		return "", 0, err
	}
	rows = rows[:min(len(rows), 20)]
	var prices []*big.Rat
	for _, row := range rows {
		a, err := readAd(row)
		if err != nil {
			return "", 0, err
		}
		p, err := decimal(a.price)
		if err != nil {
			return "", 0, err
		}
		lo, err := decimal(a.min)
		if err != nil {
			return "", 0, err
		}
		hi, err := decimal(a.max)
		if err != nil {
			return "", 0, err
		}
		if !a.acceptsPayment || !inBookPriceRange(p) || (s.certifiedOnly && !a.certified) ||
			lo.Cmp(hi) > 0 || lo.Cmp(s.maxOrder) > 0 || hi.Cmp(s.minOrder) < 0 {
			continue
		}
		prices = append(prices, p)
	}
	n := len(prices)
	if n < s.minSamples {
		return "", n, fmt.Errorf("%w: before=%d after=%d", errSamples, len(rows), n)
	}
	slices.SortFunc(prices, (*big.Rat).Cmp)
	median := prices[n/2]
	if n%2 == 0 {
		median = new(big.Rat).Quo(new(big.Rat).Add(prices[n/2-1], median), big.NewRat(2, 1))
	}
	if !inBookPriceRange(median) {
		return "", n, errRange
	}
	value, err := normalized(median)
	return value, n, err
}

func (s settings) parse(source Source, body []byte) (string, int, error) {
	top, err := decode[object](body)
	if err != nil {
		return "", 0, err
	}
	if source == OKX || source == Binance {
		return s.book(source, top)
	}
	raw := top["price"]
	if source == Kraken {
		apiErrors, err := decode[[]json.RawMessage](top["error"])
		if err != nil || len(apiErrors) != 0 {
			return "", 0, errShape
		}
		result, err := decode[object](top["result"])
		if err != nil || len(result) != 1 {
			return "", 0, errShape
		}
		ticker, err := decode[object](result["USDTZUSD"])
		if err != nil {
			return "", 0, err
		}
		last, err := decode[[]json.RawMessage](ticker["c"])
		if err != nil || len(last) == 0 {
			return "", 0, errShape
		}
		raw = last[0]
	}
	str, err := decode[string](raw)
	if err != nil {
		return "", 0, err
	}
	p, err := decimal(str)
	if err != nil {
		return "", 0, err
	}
	if p.Cmp(big.NewRat(1, 2)) < 0 || p.Cmp(big.NewRat(3, 2)) > 0 {
		return "", 0, errRange
	}
	value, err := normalized(p)
	return value, 1, err
}
