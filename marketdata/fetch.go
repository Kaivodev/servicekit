package marketdata

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 2 << 20
const binanceQuery = `{"fiat":"CNY","page":1,"rows":20,"tradeType":"BUY","asset":"USDT","countries":[],"proMerchantAds":false,"shieldMerchantAds":false,"publisherType":null,"payTypes":[]}`

type endpoint struct{ base, path string }

func endpoints() map[Source]endpoint {
	return map[Source]endpoint{
		OKX:      {"https://www.okx.com", "/v3/c2c/tradingOrders/books?quoteCurrency=cny&baseCurrency=usdt&side=sell&paymentMethod=all&userType=all&receivingAds=false&limit=20"},
		Binance:  {"https://p2p.binance.com", "/bapi/c2c/v2/friendly/c2c/adv/search"},
		Coinbase: {"https://api.exchange.coinbase.com", "/products/USDT-USD/ticker"},
		Kraken:   {"https://api.kraken.com", "/0/public/Ticker?pair=USDTUSD"},
	}
}

func newTransport(proxy *url.URL, timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                  http.ProxyURL(proxy),
		DialContext:            (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		MaxResponseHeaderBytes: 1 << 20,
		// A fresh connection for each scheduled attempt prevents the transport
		// from replaying requests on a stale pooled connection.
		DisableKeepAlives: true,
	}
}

func rawResponse(b []byte) *Raw {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b) // bytes.Buffer writes cannot fail.
	_ = w.Close()
	return &Raw{SHA256: sha256.Sum256(b), Gzip: buf.Bytes(), Size: len(b)}
}

type attemptResult struct {
	Result
	samples int
	retry   bool
}

func (c *Collector) fetch(ctx context.Context, source Source, minute time.Time, attempt int) attemptResult {
	r := attemptResult{Result: Result{Source: source, Minute: minute, Attempt: attempt}}
	ep := c.endpoints[source]
	method := http.MethodGet
	var body io.Reader
	if source == Binance {
		method = http.MethodPost
		body = strings.NewReader(binanceQuery)
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.settings.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, ep.base+ep.path, body)
	if err != nil {
		panic("invalid static market endpoint")
	}
	req.Header.Set("User-Agent", "kaivo-market-collector")
	req.Header.Set("Accept", "application/json")
	if source == Binance {
		req.Header.Set("Content-Type", "application/json")
	}
	// One round trip preserves every 3xx body, even with a malformed Location.
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		r.Outcome, r.Detail, r.retry = TransportError, "request failed", true
		return r
	}
	defer resp.Body.Close()
	b, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	collected := c.clock.now().UTC().Truncate(time.Microsecond)
	if readErr != nil && len(b) == 0 {
		r.Outcome, r.Detail, r.retry = TransportError, "body read failed", true
		return r
	}
	r.Raw = rawResponse(b[:min(len(b), maxBody)])
	switch {
	case len(b) > maxBody:
		r.Outcome, r.Detail = ParseError, "response exceeds 2 MiB"
	case readErr != nil:
		r.Outcome, r.Detail = ParseError, "incomplete response body"
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		r.Outcome, r.Detail = HTTPStatus, fmt.Sprintf("HTTP %d", resp.StatusCode)
		r.retry = resp.StatusCode == 429 || resp.StatusCode >= 500 && resp.StatusCode < 600
	default:
		value, samples, err := c.settings.parse(source, b)
		r.samples = samples
		switch {
		case errors.Is(err, errSamples):
			r.Outcome, r.Detail = InsufficientSamples, err.Error()
		case err != nil:
			r.Outcome, r.Detail = ParseError, err.Error()
		default:
			r.Outcome = OK
			r.Observation = &Observation{source, minute, value, samples, collected}
		}
	}
	return r
}
