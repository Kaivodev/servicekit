package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"
)

func (d *driver) channels() {
	d.login("operations")
	op := d.browser("operations")
	for _, spec := range []struct{ code, owner, path string }{{"sim_form_md5", "payment", "/plugins"}, {"sim_form_md5_verify", "reconciliation", "/verification/plugins"}} {
		d.step("双批发布 "+spec.code, func() {
			m := op.approve(spec.code, spec.owner, spec.path, spec.path, d.upload(spec.code))
			d.put("plugin/"+spec.code, str(obj(m["plugin_version"]), "plugin_version_id"))
		})
	}
	ch := d.key("channel")
	seller := d.required("seller-account")
	conf := b64.EncodeToString(encoded(object{"account_id": "md5-demo", "gateway": "http://127.0.0.1:9080"}))
	effect := func() string {
		return time.Now().UTC().Add(90 * time.Second).Truncate(time.Second).Format(time.RFC3339)
	}
	submit := func(label, kind string, body object) object {
		return op.approve(label, "payment", "/"+kind+"/requests", "/"+kind, body)
	}
	d.step("支付方式", func() {
		submit("method", "payment-methods", object{"change": object{"payment_method": "alipay", "name": "支付宝", "enabled": true, "expected_control_version": 0}})
	})
	config := func(enabled bool) object {
		// The seller review is supplied by its reviewer. Never manufacture approval from the seller ID.
		var reviews []object
		decode(file(d.env("payment")["AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE"]), &reviews)
		var digest []byte
		for _, r := range reviews {
			if r["seller_account_id"] == seller {
				var e error
				digest, e = hex.DecodeString(str(r, "review_sha256"))
				check(e)
			}
		}
		require(len(digest) == 32, "payment requires a verified seller review in its configured development seller reviews file")
		return object{"channel_account_id": ch, "channel_code": "sim_form_md5", "name": "Demo MD5", "seller_account_id": seller, "seller_review_sha256": b64.EncodeToString(digest), "payment_methods": []string{"alipay"}, "fiat_currency": "CNY", "min_amount_fiat_minor": "1", "max_amount_fiat_minor": "10000000", "daily_limit_fiat_minor": "100000000", "priority": 1, "weight": 1, "credentials_ref": "sim-md5-v1", "config_json": conf, "enabled": enabled, "callback_source_cidrs": []string{"127.0.0.1/32"}}
	}
	d.step("卖方通道绑定", func() {
		submit("channel", "channel-accounts", object{"change": object{"configuration": config(false), "expected_control_version": 0}})
	})
	for _, side := range []string{"channel", "merchant"} {
		d.step("定价 "+side, func() {
			c := object{"side": side, "fiat_currency": "CNY", "markup_ppm": 0, "fee_rate_ppm": 10000}
			if side == "merchant" {
				c["platform_default"] = object{}
			} else {
				c["channel_account_id"] = ch
			}
			r := op.write("draft/"+side, "/pricing-drafts", func() object { return object{"configuration": c, "effective_at": effect()} })
			approved := submit("pricing/"+side, "pricing-versions", object{"draft_id": str(r, "draft_id"), "expected_revision": num(r, "revision"), "expected_control_version": 0})
			d.put("effective/"+side, str(obj(obj(approved["pricing_version"])["draft"]), "effective_at"))
		})
	}
	d.step("风控", func() {
		approved := d.browser("risk").approve("risk", "payment", "/risk-policies/requests", "/risk-policies", object{"change": object{"risk_policy_version": d.key("risk"), "channel_account_id": ch, "hold_duration_seconds": 20, "exceptional_extension_seconds": 60, "dispute_handling_timeout_seconds": 120, "effective_at": effect(), "expected_control_version": 0}})
		d.put("effective/risk", str(obj(approved["risk_policy"]), "effective_at"))
	})
	version := func() int64 { return num(op.api("GET", "/channel-accounts/"+ch, "", nil), "control_version") }
	d.step("支付插件绑定", func() {
		plugin := d.required("plugin/sim_form_md5")
		// payment binds every enable proposal to the plugin's own control version.
		var pluginVersion int64
		for _, item := range func() []any { v, _ := op.api("GET", "/plugins?limit=100", "", nil)["items"].([]any); return v }() {
			if p := obj(item); str(p, "plugin_version_id") == plugin {
				pluginVersion = num(p, "control_version")
			}
		}
		require(pluginVersion > 0, "published payment plugin not found in the platform plugin list")
		submit("enable-plugin", "plugin-enables", object{"channel_account_id": ch, "plugin_version_id": plugin, "expected_control_version": version(), "expected_plugin_control_version": pluginVersion})
	})
	d.step("通道启用", func() {
		for _, key := range []string{"channel", "merchant", "risk"} {
			t, e := time.Parse(time.RFC3339Nano, d.required("effective/"+key))
			check(e)
			if delay := time.Until(t); delay > 0 {
				time.Sleep(delay)
			}
		}
		submit("enable-channel", "channel-accounts", object{"change": object{"configuration": config(true), "expected_control_version": version()}})
	})
	verifyID := d.key("verify-account")
	d.step("独立只读凭据见证", func() {
		var creds map[string]string
		decode(file(filepath.Join(d.root, "handoff/query.json")), &creds)
		var sim struct {
			Accounts []struct {
				ID     string
				Shared string `json:"shared_secret"`
				Query  string `json:"query_shared_secret"`
			}
		}
		decode(file(filepath.Join(d.root, "inputs/upstream-sim/config.json")), &sim)
		ok := false
		for _, a := range sim.Accounts {
			if a.ID == "md5-demo" && a.Query != "" && a.Query != a.Shared && a.Query == creds["query_key"] {
				ok = true
			}
		}
		require(ok, "query credential does not match independent simulator account")
		b := encoded(creds)
		kid := d.key("attestation")
		d.registry("attestations", kid, object{"id": kid, "channel_id": ch, "channel_code": "sim_form_md5", "credentials_sha256": fmt.Sprintf("%x", sha256.Sum256(b)), "valid_until": time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second), "source": "upstream-sim/md5-demo/query_shared_secret", "witness": "demo-verification-witness"})
		r := op.write("seal", "/verification/credentials", func() object { return object{"channel_account_id": ch, "credentials_json": b64.EncodeToString(b)} })
		d.put("query-ref", str(r, "credentials_ref"))
	})
	d.step("核验账户与启用", func() {
		p := "/verification/accounts"
		c := object{"verification_account_id": verifyID, "channel_account_id": ch, "name": "Demo query", "config_json": conf, "credentials_ref": d.required("query-ref")}
		op.approve("verification-account", "reconciliation", p+"/requests", p, object{"change": object{"expected_control_version": 0, "configuration": c}})
		v := op.api("GET", p+"/"+verifyID, "", nil)
		p = "/verification/enables"
		op.approve("verification-enable", "reconciliation", p+"/requests", p, object{"verification_account_id": verifyID, "expected_control_version": num(v, "control_version"), "plugin_version_id": d.required("plugin/sim_form_md5_verify")})
	})
}
