package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The report, checkpoints, plugin builds and user-supplied declarations belong
// to the driver. All access to a running stack goes through this boundary.
type demoEnvironment interface {
	native() bool
	env(service string) map[string]string
	addresses() endpoints
	callbackCIDRs() []string
	database(owner string) *pgx.ConnConfig
	input(name string) []byte
	mailBody(recipient, subject string) []byte
	fixtureRecord(name string) []byte
	syncMerchantKeys()
	cashierClient() *http.Client
	owner(service, dbvar string, args ...string) []byte
	refreshMarket()
	stack(args ...string) []byte
	cursorMoved(service, since string) bool
}

type endpoints struct{ public, admin, seller, sim, gateway, cashier, notify string }
type nativeEnvironment struct{ root, repo, dir string }

func (nativeEnvironment) native() bool { return true }
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
func (d nativeEnvironment) cashierClient() *http.Client {
	roots := x509.NewCertPool()
	require(roots.AppendCertsFromPEM(d.input("certs/ca.crt")), "missing cashier CA")
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: localHTTP.CheckRedirect}
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
	var dsn string
	if dbvar == sellersDatabase {
		dsn = d.env("iam-sellers")[dbvar]
	} else {
		dsn = d.env(service + "-migrate")["AIPAY_DATABASE_URL"]
	}
	require(dsn != "", "missing "+service+" ceremony connection")
	list := []string{"PATH=" + os.Getenv("PATH"), dbvar + "=" + dsn}
	if dbvar == "AIPAY_IAM_BOOTSTRAP_DATABASE_URL" {
		for k, v := range d.env("iam") {
			if k == "AIPAY_ENVIRONMENT" || strings.HasPrefix(k, "AIPAY_IAM_DATA_") || k == "AIPAY_IAM_EMAIL_TTL" {
				list = append(list, k+"="+v)
			}
		}
	}
	return command(d.dir, list, filepath.Join(d.root, "bin", service), args...)
}
