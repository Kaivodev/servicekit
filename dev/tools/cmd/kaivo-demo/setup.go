package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

var approvers = []string{"approver1", "approver2"}

func (d *driver) identities() {
	d.step("IAM bootstrap", func() {
		admins := []object{}
		for _, n := range []string{"admin1", "admin2"} {
			admins = append(admins, object{"email": d.email(n), "display_name": n, "verification_ref": "demo/" + n, "roles": []string{"platform-administrator"}})
		}
		manifest := d.declaration("bootstrap", object{"ceremony_id": d.key("bootstrap"), "witness": "demo-witness", "administrators": admins})
		// Use the durable IAM mail outbox so a lost stdout cannot lose a bootstrap capability.
		if !d.bootstrapSealed(manifest) {
			d.owner("iam", "AIPAY_IAM_BOOTSTRAP_DATABASE_URL", "bootstrap", "--manifest", manifest, "--operator", "demo-operator")
		}
	})
	for _, n := range []string{"admin1", "admin2"} {
		d.step("IAM "+n, func() {
			b := d.browser(n)
			b.write("reset/"+n, "/auth/password/reset", func() object {
				return object{"token": d.mail(d.email(n), "重置密码"), "new_password": d.password(n)}
			})
			d.login(n)
		})
	}
	for _, staff := range []struct{ name, role string }{
		{"approver1", "approver"}, {"approver2", "approver"}, {"reviewer", "payment_access_reviewer"},
		{"operations", "operations"}, {"risk", "risk"},
	} {
		d.step("邀请 "+staff.name, func() { d.invite(staff.name, staff.role); d.login(staff.name) })
	}
	for _, staff := range []struct {
		name  string
		roles []string
	}{
		{"finance", []string{"finance"}},
		{"approver3", []string{"approver", "finance", "risk"}},
	} {
		d.step("Invite "+staff.name, func() {
			d.invite(staff.name, staff.roles...)
			d.login(staff.name)
		})
	}
}
func (d *driver) invite(n string, roles ...string) {
	req := invitationRequest{Kind: "platform", Email: d.email(n), Roles: roles}
	if n == "seller" {
		req.Kind, req.SellerAccountID, req.Roles = "seller", d.required("seller-account"), nil
	}
	d.issueInvitation(req, func(admin, path string, body object) object {
		label := "invite/" + n
		if admin == "admin2" {
			label = "approve " + label
		}
		return d.browser(admin).write(label, path, func() object { return body })
	})
	b := d.browser(n)
	res := b.write("accept/"+n, "/auth/invitations/accept", func() object {
		t := d.mail(d.email(n), invitationSubject)
		view := b.post("/auth/invitations/inspect", object{"token": t})
		require(str(view, "email") == d.email(n), "invitation email mismatch")
		if view["existing_user"] == true {
			require(n == "seller", "expected new platform user")
			if path := os.Getenv("AIPAY_DEMO_SELLER_PASSWORD_FILE"); path != "" {
				d.put("password/seller", strings.TrimRight(string(file(path)), "\r\n"))
			}
			if path := os.Getenv("AIPAY_DEMO_SELLER_TOTP_FILE"); path != "" {
				d.put("totp/seller", strings.TrimSpace(string(file(path))))
			}
			require(d.data["password/seller"] != nil, "existing seller needs their password via AIPAY_DEMO_SELLER_PASSWORD_FILE")
			d.login(n)
			return object{"token": t}
		}
		return object{"token": t, "new_user": object{"display_name": n, "password": d.password(n)}}
	})
	user := str(res, "user_id")
	if n == "seller" {
		require(user == d.required("seller-owner"), "accepted seller differs from registered owner")
	}
	d.put("user/"+n, user)
}

const invitationSubject = "账户邀请"

func (d *driver) issueInvitation(req invitationRequest, submit func(admin, path string, body object) object) (string, string) {
	d.login("admin1")
	path := "/invitations/platform-staff"
	body := object{"email": req.Email, "platform_roles": req.Roles}
	if req.Kind == "seller" {
		path = "/invitations/sellers"
		body = object{"email": req.Email, "seller_account_id": req.SellerAccountID}
	}
	inv := submit("admin1", path, body)
	recipient := str(inv, "email")
	require(strings.EqualFold(recipient, req.Email), "invitation recipient mismatch")
	if req.Kind == "seller" {
		require(inv["seller_account_id"] == req.SellerAccountID, "invitation seller account mismatch")
	}
	if slices.Contains(req.Roles, "risk") || slices.Contains(req.Roles, "finance") {
		require(str(inv, "status") == "pending_approval", "protected invitation requires independent approval")
	}
	invID := str(inv, "id")
	require(canonicalID(invID), "invalid invitation ID")
	if str(inv, "status") == "pending_approval" {
		d.login("admin2")
		inviter, approver := d.required("user/admin1"), d.required("user/admin2")
		require(inviter != approver && inv["invited_by"] == inviter, "protected invitation has unexpected inviter")
		inv = submit("admin2", "/invitations/"+invID+"/approvals", object{"expected_version": num(inv, "version")})
		require(inv["id"] == invID && inv["approved_by"] == approver, "protected invitation approval mismatch")
	}
	require(str(inv, "status") == "pending", "invitation not pending")
	return invID, recipient
}

func (d *driver) registration() {
	for _, n := range approvers {
		d.step("审批登记 "+n, func() {
			key := d.credential(n)
			person, user := d.key("person/"+n), d.required("user/"+n)
			from := d.value("registry-start", func() string { return time.Now().Add(-time.Minute).UTC().Truncate(time.Second).Format(time.RFC3339) })
			start, e := time.Parse(time.RFC3339, from)
			check(e)
			until := start.Add(7 * 24 * time.Hour).Format(time.RFC3339)
			p := d.declaration("payment-"+n, object{"approver_id": person, "iam_user_id": user, "credential_id": key.ID, "rp_id": d.origins.rpID(), "public_key_cose": key.cose(), "valid_from": from, "valid_until": until})
			var entries []object
			decode(d.owner("payment", "AIPAY_PAYMENT_APPROVERS_DATABASE_URL", "approvers", "list"), &entries)
			private, e := x509.ParseECPrivateKey(key.Key)
			check(e)
			fingerprint := spkiFingerprint(&private.PublicKey)
			paymentKey := ""
			for _, r := range entries {
				if r["approver_id"] == person && r["iam_user_id"] == user && r["spki_sha256"] == fingerprint && r["revoked_at"] == nil {
					paymentKey = str(r, "key_id")
				}
			}
			if paymentKey == "" {
				decode(d.owner("payment", "AIPAY_PAYMENT_APPROVERS_DATABASE_URL", "approvers", "register", p), &entries)
				require(len(entries) == 1 && entries[0]["spki_sha256"] == fingerprint, "payment registrar fingerprint mismatch")
				paymentKey = str(entries[0], "key_id")
			}
			for _, registry := range []string{"approvers", "dispute-approvers"} {
				kid := d.key(n + "/reconciliation")
				if registry == "dispute-approvers" {
					kid = paymentKey
				}
				decl := object{"id": kid, "person_id": person, "iam_user_id": user, "credential_id": key.ID, "public_key": key.cose(), "rp_id": d.origins.rpID(), "valid_from": from, "valid_until": until, "initial_sign_count": key.Count, "ceremony": "demo-" + n}
				d.registry(registry, kid, decl)
			}
			d.evidence("payment_key_id", paymentKey)
		})
	}
	for _, n := range []string{"approver1", "approver2", "approver3"} {
		d.liveStep("Register ledger "+n, func() { d.registerLedgerApprover(n) })
	}
}

func (d *driver) registerLedgerApprover(n string) {
	const dbvar = "AIPAY_LEDGER_APPROVERS_DATABASE_URL"
	key := d.credential(n)
	cose := key.cose()
	person, user := d.key("person/"+n), d.required("user/"+n)
	credentialHash, keyHash := fmt.Sprintf("%x", sha256.Sum256(key.ID)), fmt.Sprintf("%x", sha256.Sum256(cose))
	lookup := func() string {
		var rows []object
		decode(d.owner("ledger", dbvar, "approvers", "list"), &rows)
		for _, row := range rows {
			if row["revoked_at"] == nil && row["iam_user_id"] == user && row["approver_id"] == person &&
				row["credential_id_sha256"] == credentialHash && row["public_key_sha256"] == keyHash {
				return str(row, "id")
			}
		}
		return ""
	}
	kid := lookup()
	if kid == "" {
		kid = d.key(n + "/ledger")
		path := d.declaration("ledger-"+n, object{
			"id": kid, "approver_id": person, "iam_user_id": user, "ceremony_ref": "demo-" + n, "rp_id": d.origins.rpID(),
			"credential_id": b64.EncodeToString(key.ID), "public_key_cose": b64.EncodeToString(cose),
		})
		d.owner("ledger", dbvar, "approvers", "register", path)
		require(lookup() == kid, "ledger registrar did not activate the declared key")
	}
	d.evidence("ledger_key_id", kid)
}
func spkiFingerprint(k *ecdsa.PublicKey) string {
	b, e := x509.MarshalPKIXPublicKey(k)
	check(e)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func (d *driver) registry(kind, kid string, decl object) {
	// list is also an audited owner ceremony. Recover a committed registration
	// after a lost response only if the recorded bindings and fingerprints match.
	env := "AIPAY_RECONCILIATION_REGISTRY_DATABASE_URL"
	lookup := d.declaration("lookup-"+kid, object{"id": kid})
	var rows []object
	decode(d.owner("reconciliation", env, "registry", kind, "list", "--file", lookup), &rows)
	if len(rows) == 0 {
		p := d.declaration(kind+"-"+kid, decl)
		decode(d.owner("reconciliation", env, "registry", kind, "register", "--file", p), &rows)
	}
	require(len(rows) == 1 && rows[0]["id"] == kid && rows[0]["revoked_at"] == nil, "registry record not active")
	row := rows[0]
	if kind == "attestations" {
		for _, k := range []string{"credentials_sha256", "channel_id", "channel_code", "source", "witness"} {
			require(row[k] == decl[k], "credential attestation mismatch")
		}
	} else {
		for _, k := range []string{"person_id", "iam_user_id", "rp_id"} {
			require(row[k] == decl[k], "approver identity mismatch")
		}
		for k, field := range map[string]string{"credential_id": "credential_id_sha256", "public_key": "public_key_sha256"} {
			require(row[field] == fmt.Sprintf("%x", sha256.Sum256(decl[k].([]byte))), "authenticator fingerprint mismatch")
		}
	}
	expiry, e := time.Parse(time.RFC3339Nano, str(row, "valid_until"))
	check(e)
	require(time.Now().Before(expiry), "registry record expired")
}
func (d *driver) packages() {
	if d.gatewayMode() {
		d.gatewayPackages()
		return
	}
	for _, code := range []string{"sim_form_md5", "sim_form_md5_verify"} {
		d.step("制作 "+code, func() {
			local := filepath.Join(filepath.Dir(d.repo), "upstream-plugins")
			src := filepath.Join(d.dir, "upstream-plugins-v0.2.2")
			if _, e := os.Stat(src); os.IsNotExist(e) {
				command(d.dir, os.Environ(), "git", "clone", "--no-local", "--branch", "v0.2.2", "--depth", "1", local, src)
			}
			env := append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=go1.27.3")
			head := command(src, env, "git", "rev-parse", "HEAD")
			tag := command(local, env, "git", "rev-parse", "v0.2.2^{commit}")
			require(bytes.Equal(head, tag) && len(command(src, env, "git", "status", "--porcelain", "--untracked-files=all")) == 0, "plugin source differs from clean v0.2.2")
			ctl := filepath.Join(d.dir, "pluginctl")
			command(src, env, "go", "build", "-mod=readonly", "-o", ctl, "./cmd/pluginctl")
			out, e := os.MkdirTemp(d.dir, code+"-")
			check(e)
			pkg := filepath.Join(out, "package")
			source := "plugins/" + code
			for _, args := range [][]string{{"build", "--source", source, "--out", out + "/build"}, {"package", "--dir", out + "/build", "--out", pkg}, {"replay", "--dir", pkg, "--out", out + "/report.json"}, {"verify", "--source", source, "--dir", pkg}} {
				d.trace("pluginctl " + args[0] + " " + code)
				result := command(src, env, ctl, args...)
				if args[0] == "package" {
					var v object
					decode(result, &v)
					d.put("hash/"+code, str(v, "package_sha256"))
				}
			}
			d.put("package/"+code, pkg)
			d.evidence("commit", strings.TrimSpace(string(head)))
			d.evidence("package_sha256", d.required("hash/"+code))
		})
	}
}
func (d *driver) upload(code string) object {
	return d.uploadPackage(code, "")
}

func (d *driver) uploadPackage(code, ref string) object {
	key := packageKey(code, ref)
	pkg := d.required("package/" + key)
	var fixtures []object
	e := filepath.WalkDir(filepath.Join(pkg, "fixtures"), func(p string, f fs.DirEntry, e error) error {
		if e != nil || f.IsDir() {
			return e
		}
		require(f.Type().IsRegular(), "invalid fixture")
		rel, e := filepath.Rel(pkg, p)
		check(e)
		fixtures = append(fixtures, object{"path": filepath.ToSlash(rel), "content": b64.EncodeToString(file(p))})
		return nil
	})
	check(e)
	hash, e := hex.DecodeString(d.required("hash/" + key))
	check(e)
	manifest, wasm := file(filepath.Join(pkg, "manifest.json")), file(filepath.Join(pkg, "plugin.wasm"))
	if d.gatewayMode() {
		_, digest := d.checkGatewayPackage(code, manifest, wasm, d.gatewayRevision(ref, ref != ""))
		require(bytes.Equal(digest, hash), "gateway package changed since setup packages")
	} else {
		manifest = canonicalManifest(manifest)
	}
	return object{"manifest_json": b64.EncodeToString(manifest), "package_sha256": b64.EncodeToString(hash), "plugin_wasm": b64.EncodeToString(wasm), "fixtures": fixtures}
}

// canonicalManifest re-encodes the package manifest the way payment,
// reconciliation and the backend command digest expect: compact JSON with
// object keys sorted, integers kept verbatim and no HTML escaping. pluginctl
// writes struct field order, which the owners reject as non-canonical.
func canonicalManifest(raw []byte) []byte {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	check(d.Decode(&v))
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	check(e.Encode(v))
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}
func (d *driver) seller() {
	d.step("卖方开通登记", d.enrollSeller)
	d.step("卖方邀请与 TOTP", func() {
		d.invite("seller", "")
		d.login("seller")
	})
	if reviewer, ok := d.demoEnvironment.(sellerReviewer); ok {
		d.liveStep("开发卖方审核资料", func() {
			reviewer.sellerReview(d.required("seller-account"), d.required("seller-owner"), d.required("seller-email"))
		})
	}
	d.deposits()
}

const sellersDatabase = "AIPAY_IAM_SELLERS_DATABASE_URL"
const setupSellerReason = "演示卖方首次开通上游门户"

func (d *driver) enrollSeller() {
	const telegramID = merchantUser + 1
	email := os.Getenv("AIPAY_DEMO_SELLER_EMAIL")
	d.read("seller-email", &email)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		email = d.email("seller")
	}
	account := os.Getenv("AIPAY_DEMO_SELLER_ACCOUNT_ID")
	d.read("seller-account", &account)
	// A saved bot reply distinguishes a demo registration from an explicitly
	// supplied, already enrolled seller, including states from older drivers.
	if d.data["telegram/"+d.scope+"/seller-balance/reply"] != nil || account == "" {
		botAccount := d.registerTelegramSeller("seller", telegramID)
		require(account == "" || account == botAccount, "seller balance identity mismatch")
		account = botAccount
		user := d.sellerBinding(account, telegramID)
		// Pin the declaration inputs before the CLI can commit and lose its response.
		require(d.value("seller-owner", func() string { return user }) == user, "seller IAM binding changed")
		d.put("seller-email", email)
		d.put("seller-account", account)
		d.evidence("seller_account_id", account)
		d.evidence("user_id_source", "iam_telegram_bindings (account_id, telegram_user_id)")
		d.activateSeller("seller", account, user, email, setupSellerReason)
		return
	}

	var sellers []object
	decode(d.owner("iam", sellersDatabase, "sellers", "list"), &sellers)
	for _, seller := range sellers {
		if seller["account_id"] == account && seller["email"] == email {
			user := str(seller, "user_id")
			d.evidence("user_id_source", "iam sellers list")
			d.evidence("seller_account_id", account)
			d.evidence("user_id", user)
			d.put("seller-email", email)
			d.put("seller-account", account)
			d.put("seller-owner", user)
			return
		}
	}
	stop("no IAM seller registration matches the supplied account and email")
}

func (d *driver) registerTelegramSeller(label string, telegramID int64) string {
	var balance message
	if !d.read("telegram/"+d.scope+"/"+label+"-balance/reply", &balance) {
		start := d.deliver(label+"-start", telegramID, telegramID, func() string { return "/start" })
		require(strings.Contains(start.Text, "注册或登录已完成"), "seller registration refused")
		balance = d.deliver(label+"-balance", telegramID, telegramID, func() string { return "/balance" })
	}
	require(balance.Chat == telegramID, "seller balance identity mismatch")
	return capture("^账户 ("+uuidPattern+")\n", balance.Text)
}

func (d *driver) sellerBinding(account string, telegramID int64) string {
	rows := d.rows("iam", "iam_telegram_bindings",
		"SELECT user_id FROM iam_telegram_bindings WHERE account_id=$1 AND telegram_user_id=$2", account, telegramID)
	require(len(rows) == 1, "expected one IAM binding for seller account and Telegram user")
	return str(rows[0], "user_id")
}

func (d *driver) activateSeller(label, account, user, email, reason string) {
	decl := object{"account_id": account, "user_id": user, "email": email,
		"verification_ref": "demo/telegram/" + account, "declared_by": "demo-operator", "reason": reason}
	path := d.declaration(label, decl)
	d.evidence("demo_verification_ref", decl["verification_ref"])
	d.evidence("demo_declared_by", decl["declared_by"])
	d.evidence("user_id", user)
	var registered object
	decode(d.owner("iam", sellersDatabase, "sellers", "activate", path), &registered)
	require(matchesProposal(registered, decl), "IAM seller activation differs from declaration")
	d.evidence("declared_at", str(registered, "declared_at"))
}
