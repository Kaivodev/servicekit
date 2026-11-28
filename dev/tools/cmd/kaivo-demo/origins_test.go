package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPortalOrigins(t *testing.T) {
	const platform, seller = "AIPAY_PLATFORM_ORIGIN", "AIPAY_SELLER_ORIGIN"
	defaults := portalOrigins{"https://admin.aipay.test", "https://seller.aipay.test"}
	custom := "https://" + strings.Repeat("a", 63) + ".web-9.demo"
	for _, tc := range []struct {
		env  map[string]string
		want portalOrigins
	}{
		{nil, defaults}, {map[string]string{platform: "", seller: ""}, defaults},
		{map[string]string{platform: custom}, portalOrigins{custom, defaults.seller}},
		{map[string]string{seller: custom}, portalOrigins{defaults.platform, custom}},
	} {
		if readPortalOrigins(tc.env) != tc.want {
			t.Fatal("unexpected portal origins")
		}
	}
	expectFailure(t, func() { readPortalOrigins(map[string]string{platform: defaults.seller}) })
	for _, key := range []string{platform, seller} {
		for _, value := range []string{"HTTP://a.b", "http://a.b", "https://A.b", "https://local", "https://a.b:443",
			"https://a.b/", "https://a.b?", "https://a.b#", "https://u@a.b", "https://a.b.", "https://*.b", "https://a-.b",
			"https://a.-b", "https://a..b", "https://a_b.c", "https://a.b\n", "https://é.test", "https://127.0.0.1",
			"https://127.1", "https://0x7f.0x1", "https://" + strings.Repeat("a", 64) + ".b",
			"https://" + strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 63)} {
			if msg := failureText(func() { readPortalOrigins(map[string]string{key: value}) }); !strings.Contains(msg, key) {
				t.Errorf("%s accepted or misidentified invalid origin %q", key, value)
			}
		}
	}
}

func TestPreparedBrowserOrigins(t *testing.T) {
	d := newDriver(t.TempDir(), "", "setup")
	d.origins = readPortalOrigins(map[string]string{
		"AIPAY_PLATFORM_ORIGIN": "https://admin.partner.test", "AIPAY_SELLER_ORIGIN": "https://portal.partner.test",
	})
	for name, host := range map[string]string{"admin1": "admin.partner.test", "seller": "portal.partner.test", "merchant": "merchant.aipay.test"} {
		r := d.browser(name).request("POST", "/totp/enroll/test", "", nil, nil)
		if r.Host != host || r.Header.Get("Origin") != "https://"+host {
			t.Error("incorrect browser origin or host", name)
		}
	}
}

func TestPreparedApproverDeclarations(t *testing.T) {
	d := newDriver(t.TempDir(), "", "setup")
	d.origins = readPortalOrigins(map[string]string{"AIPAY_PLATFORM_ORIGIN": "https://admin.partner.test"})
	var ledgerRows []object
	for _, n := range []string{"approver1", "approver2", "approver3"} {
		d.put("user/"+n, n)
		key := d.credential(n)
		ledgerRows = append(ledgerRows, object{
			"id": id(), "approver_id": d.key("person/" + n), "iam_user_id": n,
			"credential_id_sha256": fmt.Sprintf("%x", sha256.Sum256(key.ID)),
			"public_key_sha256":    fmt.Sprintf("%x", sha256.Sum256(key.cose())),
		})
	}
	var registered []string
	d.demoEnvironment = ledgerOwnerFixture{d.demoEnvironment, func(service, dbvar string, args ...string) []byte {
		if service == "ledger" {
			return encoded(ledgerRows)
		}
		if slices.Contains(args, "list") {
			return []byte("[]")
		}
		var decl object
		decode(file(args[len(args)-1]), &decl)
		if decl["rp_id"] != "admin.partner.test" {
			t.Fatal("incorrect RP ID in", service, args[0])
		}
		if service == "payment" {
			registered = append(registered, service)
			key := d.credential(str(decl, "iam_user_id"))
			priv, err := x509.ParseECPrivateKey(key.Key)
			check(err)
			return encoded([]object{{"key_id": id(), "spki_sha256": spkiFingerprint(&priv.PublicKey)}})
		}
		registered = append(registered, args[1])
		decl["credential_id_sha256"] = fmt.Sprintf("%x", sha256.Sum256(standard(str(decl, "credential_id"))))
		decl["public_key_sha256"] = fmt.Sprintf("%x", sha256.Sum256(standard(str(decl, "public_key"))))
		return encoded([]object{decl})
	}}
	d.registration()
	want := []string{"payment", "approvers", "dispute-approvers", "payment", "approvers", "dispute-approvers"}
	if !slices.Equal(registered, want) {
		t.Fatal("missing approver declarations", registered)
	}
}
