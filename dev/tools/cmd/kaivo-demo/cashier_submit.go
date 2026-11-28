package main

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
)

const cashierSubmit = "cashier-submit"

func (d *driver) submitEPay(proto string, params url.Values) string {
	params.Del("clientip")
	params.Del("method")
	d.signEPay(proto, params)
	b := d.browser("merchant")
	path := "/api/pay/submit"
	var req *http.Request
	if proto == "v1" {
		path = "/submit.php"
		req = b.request(http.MethodGet, path+"?"+params.Encode(), "", nil, nil)
	} else {
		req = b.request(http.MethodPost, path, "application/x-www-form-urlencoded", form(params), nil)
	}
	status, _, headers := b.sendWithHeaders(req, path)
	require(status == http.StatusSeeOther, path+" must redirect to the buyer cashier with HTTP 303")
	link := headers.Get("Location")
	d.cashierToken(link)
	return link
}

func (t tradeRun) verifyCashierReturn(location, tradeNo string) {
	query, ok := strings.CutPrefix(location, merchantReturnURL+"?")
	require(ok && !strings.Contains(query, "#"), "unexpected merchant return destination")
	fields, err := url.ParseQuery(query)
	require(err == nil, "invalid merchant return query")
	d := t.d
	if t.proto == "v1" {
		sig := v1Sign(fields, d.merchantV1Key())
		require(fields.Get("sign_type") == "MD5" && sig != "" && subtle.ConstantTimeCompare([]byte(sig), []byte(fields.Get("sign"))) == 1, "invalid merchant return signature")
	} else {
		d.verifyPlatformSignature(fields)
	}
	require(fields.Get("trade_status") == "TRADE_SUCCESS" && fields.Get("out_trade_no") == t.number &&
		fields.Get("trade_no") == tradeNo && fields.Get("money") == t.amount && fields.Get("pid") == d.required("pid/"+t.proto),
		"signed merchant return differs from the paid order")
}

func (d *driver) checkCashierRefusals(token string) {
	d.cashierGet(d.ctx, cashierPath, "invalid", 400)
	landing := d.cashierAction(d.ctx, cashierPath+"/go", token, d.origins.platform)
	require(landing == d.origins.cashier+"/c", "cross-origin cashier action must redirect to the tokenless cashier page")
}

func (d *driver) runCashierSubmit() {
	require(d.gatewayMode(), "cashier-submit requires gateway mode")
	require(d.origins.cashier != "", "cashier-submit requires a prepared AIPAY_CASHIER_ORIGIN")
	for _, proto := range []string{"v1", "v2"} {
		t := d.trade(proto, proto)
		key := d.scope + "/" + t.name
		token := d.cashierToken(d.required("submit-link/" + key))
		t.step("Reject an invalid token and cross-origin navigation", func() {
			d.checkCashierRefusals(token)
		})
		t.paid(1)
		t.notify()
		t.step("Verify the signed merchant return", func() {
			ctx, cancel := context.WithTimeout(d.ctx, cashierTimeout)
			defer cancel()
			d.awaitCashier(ctx, token, true)
			location := d.cashierAction(ctx, cashierPath+"/return", token, "")
			t.verifyCashierReturn(location, d.required("trade-no/"+key))
		})
		t.release()
	}
}
