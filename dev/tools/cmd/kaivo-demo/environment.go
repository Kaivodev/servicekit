package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The report, checkpoints, plugin builds and user-supplied declarations belong
// to the driver. All access to a running stack goes through this boundary.
type demoEnvironment interface {
	native() bool
	pause(time.Duration)
	env(service string) map[string]string
	addresses() endpoints
	callbackCIDRs() []string
	database(owner string) *pgx.ConnConfig
	input(name string) []byte
	mailBody(recipient, subject string) []byte
	fixtureRecord(name string) []byte
	syncMerchantKeys()
	doHTTP(*http.Client, *http.Request) (*http.Response, error)
	cashierClient() (*http.Client, string)
	owner(service, dbvar string, args ...string) []byte
	refreshMarket()
	stack(args ...string) []byte
	cursorMoved(service, since string) bool
}

type endpoints struct{ public, admin, seller, sim, gateway, cashier, notify string }
type nativeEnvironment struct{ root, repo, dir string }

func (nativeEnvironment) native() bool              { return true }
func (nativeEnvironment) pause(delay time.Duration) { time.Sleep(delay) }
func (nativeEnvironment) addresses() endpoints {
	return endpoints{"127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082", "http://127.0.0.1:9080", "http://127.0.0.1:9080", "https://127.0.0.1:9443", notifyOrigin}
}
func (nativeEnvironment) callbackCIDRs() []string { return []string{"127.0.0.1/32"} }
func (d nativeEnvironment) env(s string) map[string]string {
	return envFile(filepath.Join(d.root, "env", s+".env"))
}
func (d nativeEnvironment) input(name string) []byte {
	if name == "seller-reviews.json" {
		return file(d.env("payment")["AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE"])
	}
	return file(filepath.Join(d.root, name))
}
func (d nativeEnvironment) database(owner string) *pgx.ConnConfig {
	role := owner + "-migrate"
	if owner == "devcollection" {
		role = owner
	}
	cfg, e := pgx.ParseConfig(d.env(role)["AIPAY_DATABASE_URL"])
	require(e == nil, "invalid "+owner+" evidence connection")
	return cfg
}
func (d nativeEnvironment) fixtureRecord(name string) []byte {
	b, e := os.ReadFile(filepath.Join(d.dir, name))
	if os.IsNotExist(e) && (name == "messages.json" || name == "notifications.json") {
		return []byte("[]")
	}
	check(e)
	return b
}
func (nativeEnvironment) syncMerchantKeys() {}
func (nativeEnvironment) doHTTP(client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req)
}

func (d nativeEnvironment) cashierClient() (*http.Client, string) {
	roots := x509.NewCertPool()
	require(roots.AppendCertsFromPEM(d.input("certs/ca.crt")), "missing cashier CA")
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: localHTTP.CheckRedirect}, ""
}
func nativeDelivery(root, id, recipient, subject string) []byte {
	b, err := os.ReadFile(filepath.Join(root, "data/iam/mail", id+".json"))
	if os.IsNotExist(err) {
		return nil
	}
	check(err)
	require(matchesMail(b, recipient, subject), "unexpected IAM mail recipient or subject")
	return b
}

func (d nativeEnvironment) mailBody(recipient, subject string) []byte {
	paths, e := filepath.Glob(filepath.Join(d.root, "data/iam/mail", "*.json"))
	check(e)
	for i := len(paths) - 1; i >= 0; i-- {
		b := file(paths[i])
		if matchesMail(b, recipient, subject) {
			return b
		}
	}
	return nil
}
func (d nativeEnvironment) refreshMarket() { d.stack("refresh-market") }
func (d nativeEnvironment) cursorMoved(service, since string) bool {
	return movedCursor(filepath.Join(d.root, "logs", service, "runtime.log"), since)
}
func (d nativeEnvironment) stack(args ...string) []byte {
	return command(d.repo, os.Environ(), "python3", append([]string{"-B", filepath.Join(d.repo, "dev/native/stack.py")}, args...)...)
}
func (d nativeEnvironment) owner(service, dbvar string, args ...string) []byte {
	ledgerDev := service == "ledger" && len(args) > 0 && args[0] == "dev"
	if ledgerDev {
		require(len(args) >= 2 && args[1] == "enter-read-only", "unsupported ledger dev command")
		require(dbvar == "AIPAY_DATABASE_URL", "ledger dev command requires the ledger owner connection")
	}
	var dsn string
	if dbvar == sellersDatabase {
		dsn = d.env("iam-sellers")[dbvar]
	} else {
		dsn = d.env(service + "-migrate")["AIPAY_DATABASE_URL"]
	}
	require(dsn != "", "missing "+service+" ceremony connection")
	list := []string{"PATH=" + os.Getenv("PATH"), dbvar + "=" + dsn}
	if ledgerDev {
		mode := d.env("ledger")["AIPAY_ENVIRONMENT"]
		require(mode == "development", "ledger dev commands require AIPAY_ENVIRONMENT=development")
		list = append(list, "AIPAY_ENVIRONMENT="+mode)
	}
	bin := filepath.Join(d.root, "bin", service)
	if isPaymentDevCommand(service, args) {
		mode := d.env("payment")["AIPAY_ENVIRONMENT"]
		require(mode == "development", "payment dev commands require AIPAY_ENVIRONMENT=development")
		list = append(list, "AIPAY_ENVIRONMENT="+mode)
		if args[1] == "archive-work" {
			return d.archiveWork(bin, list, args)
		}
	}
	if dbvar == "AIPAY_IAM_BOOTSTRAP_DATABASE_URL" {
		for k, v := range d.env("iam") {
			if k == "AIPAY_ENVIRONMENT" || strings.HasPrefix(k, "AIPAY_IAM_DATA_") || k == "AIPAY_IAM_EMAIL_TTL" {
				list = append(list, k+"="+v)
			}
		}
	}
	return command(d.dir, list, bin, args...)
}

func (d nativeEnvironment) archiveWork(bin string, env, args []string) []byte {
	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var reply []byte
	waitFor(time.Sleep, "payment to release the order work lease", timeout, func() bool {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir, cmd.Env = d.dir, env
		var err error
		reply, err = cmd.Output()
		if exit, ok := err.(*exec.ExitError); ok && bytes.Contains(exit.Stderr, []byte("retry if it is executing")) {
			return false
		}
		require(ctx.Err() == nil, "timed out archiving the order work")
		require(err == nil, "payment dev archive-work failed")
		return true
	})
	return reply
}
