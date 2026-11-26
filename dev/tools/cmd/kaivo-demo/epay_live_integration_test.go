//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	syncatomic "sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestLiveOrderRouteAndResume(t *testing.T) {
	dsn := os.Getenv("AIPAY_TEST_DATABASE_URL")
	require(dsn != "", "isolated PostgreSQL required")
	ctx := t.Context()
	db, err := pgx.Connect(ctx, dsn)
	check(err)
	defer db.Close(context.Background())
	schema := "live_test_" + strings.ReplaceAll(id(), "-", "")
	_, err = db.Exec(ctx, "CREATE SCHEMA "+schema)
	check(err)
	defer db.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	_, err = db.Exec(ctx, "SET search_path TO "+schema)
	check(err)
	_, err = db.Exec(ctx, `CREATE TABLE payment_orders(id text, channel_code text, channel_account_id text, data jsonb,
		account_id text, application_id text, out_trade_no text);
		CREATE TABLE ledger_trade_reservations(order_id text, paid_verified_at timestamptz)`)
	check(err)
	root := t.TempDir()
	u, err := url.Parse(dsn)
	check(err)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	for _, owner := range []string{"payment", "ledger"} {
		check(atomic(filepath.Join(root, "env", owner+"-migrate.env"), []byte("AIPAY_DATABASE_URL="+u.String())))
	}
	check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=test")))
	liveFile(t, testEnv)
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_WAIT", "0s")
	t.Setenv("AIPAY_DEMO_EPAY_LIVE_CLIENT_IP", "::1")
	d := newDriver(root, "", livePhase)
	d.liveEPay = true
	d.put(channelKey(liveVariant, "operator-file-sha"), readLiveCredentials().fingerprint())
	d.put("uuid/"+channelKey(liveVariant, "channel"), "live-account")
	d.put("merchant-account", "merchant")
	d.put("app/v1", "app")
	d.put("pid/v1", "123")
	check(atomic(filepath.Join(d.dir, "merchant-key.json"), encoded(object{"Key": "test-merchant-key"})))
	d.put("step/epay-live/测试上游 余额基线", result{Name: "测试上游 余额基线", Status: "ok"})

	number := d.key(livePhase + "/order-number")
	const evidenceLink = "https://cashier.example.test/checkout/sample"
	const link = evidenceLink + "?pid=" + testPID + "&sign=query-sentinel#fragment-sentinel"
	_, err = db.Exec(ctx, `INSERT INTO payment_orders VALUES ('order','epay_v1','sim-account',
		$2::jsonb,'merchant','app',$1)`, number, encoded(object{
		"snapshot": object{"trade": object{"quote": object{"fiat_amount": 111}}}, "payment_instruction": object{"qrcode": link},
	}))
	check(err)
	_, err = db.Exec(ctx, "INSERT INTO ledger_trade_reservations VALUES ('order',NULL)")
	check(err)
	var creates syncatomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mapi.php" || r.Method != "POST" || r.FormValue("out_trade_no") != number ||
			r.FormValue("money") != "1.11" || r.FormValue("type") != "alipay" || r.FormValue("clientip") != "::1" {
			t.Error("unexpected merchant request")
			return
		}
		creates.Add(1)
		fmt.Fprintf(w, `{"code":1,"qrcode":%q}`, link)
	}))
	defer srv.Close()
	d.browser("merchant").addr = strings.TrimPrefix(srv.URL, "http://")
	capture := func(run func()) (string, string) {
		rd, wr, err := os.Pipe()
		check(err)
		defer rd.Close()
		defer wr.Close()
		saved := os.Stdout
		defer func() { os.Stdout = saved }()
		os.Stdout = wr
		msg := failureText(run)
		check(wr.Close())
		out, err := io.ReadAll(rd)
		check(err)
		return msg, string(out)
	}
	if msg, out := capture(d.runLiveEPay); !strings.Contains(msg, "epay_v1 channel account sim-account") || out != "" {
		t.Fatal("expected account mismatch on the shared plugin")
	}
	if strings.Contains(string(file(filepath.Join(d.dir, "reports/epay-live.md"))), link) {
		t.Fatal("instruction was exposed before the route was checked")
	}
	// Replace the synthetic route with the live binding for the paid-wait test.
	_, err = db.Exec(ctx, "UPDATE payment_orders SET channel_account_id='live-account'")
	check(err)
	wantPrompt := livePaymentPrompt + " " + link + "\n"
	if msg, out := capture(d.runLiveEPay); msg != "未付款" || out != wantPrompt {
		t.Fatal("expected unpaid timeout")
	}
	restarted := newDriver(root, "", livePhase)
	restarted.liveEPay = true
	restarted.browser("merchant").addr = strings.TrimPrefix(srv.URL, "http://")
	if msg, out := capture(restarted.runLiveEPay); msg != "未付款" || out != wantPrompt || creates.Load() != 2 || restarted.key(livePhase+"/order-number") != number {
		t.Fatal("restart must resume the unpaid order without creating another")
	}
	report := string(file(filepath.Join(d.dir, "reports/epay-live.md")))
	if !strings.Contains(report, evidenceLink) || !strings.Contains(report, livePaymentPrompt) || !strings.Contains(report, "未付款") {
		t.Fatal("unpaid report missing the existing payment instruction or status")
	}
	for _, name := range []string{"state.json", "reports/epay-live.md", "reports/epay-live.json"} {
		b := string(file(filepath.Join(d.dir, name)))
		if !strings.Contains(b, evidenceLink) || strings.Contains(b, "query-sentinel") ||
			strings.Contains(b, "fragment-sentinel") || strings.Contains(b, testPID) {
			t.Fatalf("%s retained payment link parameters", name)
		}
	}
}
