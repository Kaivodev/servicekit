package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	cashierPath    = "/api/v1/cashier"
	cashierTimeout = 60 * time.Second
	desktopAgent   = "Mozilla/5.0 (X11; Linux x86_64) KaivoDemo/1.0"
)

var (
	simulatorPath       = regexp.MustCompile(`^/cashier/[A-Za-z0-9_-]+$`)
	cashierTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func (d *driver) simulatorLink(link string) bool {
	u, err := url.Parse(link)
	return err == nil && u.Scheme+"://"+u.Host == d.addresses().cashier && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && simulatorPath.MatchString(u.EscapedPath())
}

func cashierLinkParts(link string) (origin, token string, ok bool) {
	origin, token, ok = strings.Cut(link, "/c#")
	if !ok || !cashierTokenPattern.MatchString(token) {
		return "", "", false
	}
	u, err := url.Parse(origin)
	return origin, token, err == nil && u.Host != "" && origin == "https://"+u.Host
}

func (d *driver) buyerToken(link string) (string, bool) {
	origin, token, ok := cashierLinkParts(link)
	return token, ok && origin == d.origins.cashier
}

func (d *driver) cashierToken(link string) string {
	token, ok := d.buyerToken(link)
	require(ok, "unexpected cashier link")
	return token
}

type cashierView struct {
	State       string `json:"state"`
	PollAfterMS int64  `json:"poll_after_ms"`
	ReturnReady bool   `json:"return_ready"`
	Instruction struct {
		Kind   string `json:"kind"`
		QRCode string `json:"qrcode"`
	} `json:"instruction"`
}

// Dial the public listener directly. The token belongs only in the authorization
// header or action form. Redirect destinations and response bodies stay out of traces.
func (d *driver) cashierRequest(ctx context.Context, method, path, token, origin string) *http.Response {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(url.Values{"token": {token}}.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+d.addresses().public+path, body)
	check(err)
	req.Host = strings.TrimPrefix(d.origins.cashier, "https://")
	req.Header.Set("User-Agent", desktopAgent)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res, err := d.doHTTP(localHTTP, req)
	if err != nil {
		check(ctx.Err())
		stop("cashier API transport failed")
	}
	d.trace(fmt.Sprintf("%s %s → HTTP %d", method, path, res.StatusCode))
	return res
}

func (d *driver) cashierGet(ctx context.Context, path, token string, wantCode int) cashierView {
	res := d.cashierRequest(ctx, http.MethodGet, path, token, "")
	defer res.Body.Close()
	require(res.StatusCode == http.StatusOK, fmt.Sprintf("cashier API returned HTTP %d", res.StatusCode))
	var env struct {
		Code int
		Data cashierView
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	check(ctx.Err())
	require(err == nil && decodeJSON(data, &env) == nil, "invalid cashier API envelope")
	require(env.Code == wantCode, fmt.Sprintf("cashier API returned envelope code %d, expected %d", env.Code, wantCode))
	return env.Data
}

func (d *driver) cashierAction(ctx context.Context, path, token, origin string) string {
	res := d.cashierRequest(ctx, http.MethodPost, path, token, origin)
	defer res.Body.Close()
	require(res.StatusCode == http.StatusSeeOther, fmt.Sprintf("%s returned HTTP %d, expected 303", path, res.StatusCode))
	return res.Header.Get("Location")
}

func (d *driver) awaitCashier(ctx context.Context, token string, forReturn bool) cashierView {
	path := cashierPath
	if forReturn {
		path += "/status"
	}
	for {
		view := d.cashierGet(ctx, path, token, 200)
		switch view.State {
		case "preparing", "ready", "paid", "expired", "closed", "failed":
			d.evidence("cashier_state", view.State)
		default:
			stop("cashier API returned an unknown state")
		}
		if forReturn {
			if view.State == "paid" && view.ReturnReady {
				return view
			}
			require(view.State == "preparing" || view.State == "ready" || view.State == "paid", "return unavailable in cashier state "+view.State)
		} else {
			require(!view.ReturnReady, "cashier exposed a merchant return before payment")
			if view.State == "ready" {
				return view
			}
			require(view.State == "preparing", "expected a ready cashier, got "+view.State)
		}
		// poll_after_ms is the server's minimum interval; 0 means the state will not advance by polling.
		require(view.PollAfterMS > 0, "cashier stopped polling in state "+view.State)
		ms := min(view.PollAfterMS, cashierTimeout.Milliseconds())
		select {
		case <-ctx.Done():
			check(ctx.Err())
		case <-time.After(time.Duration(ms) * time.Millisecond):
		}
	}
}

func (d *driver) resolveCashier(link string) string {
	if d.simulatorLink(link) {
		return link
	}
	token := d.cashierToken(link)
	d.evidence("cashier_link", paymentLinkEvidence(link))
	ctx, cancel := context.WithTimeout(d.ctx, cashierTimeout)
	defer cancel()
	view := d.awaitCashier(ctx, token, false)
	var upstream string
	switch view.Instruction.Kind {
	case "url":
		upstream = d.cashierAction(ctx, cashierPath+"/go", token, "")
	case "qrcode":
		upstream = view.Instruction.QRCode
	default:
		stop("ready cashier has an unknown instruction kind")
	}
	require(d.simulatorLink(upstream), "cashier instruction must point to the simulator")
	return upstream
}
