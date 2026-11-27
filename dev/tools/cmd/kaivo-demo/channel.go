package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"strconv"
	"time"
)

// Existing form-md5 installations resume the original ceremony checkpoints.
func channelKey(variant, key string) string {
	if variant == epayChannel || variant == liveVariant {
		return key + "/" + variant
	}
	return key
}

func channelStepName(variant, label string) string {
	if variant == liveVariant {
		label = "测试上游 " + label
	}
	return channelKey(variant, label)
}

func simulatorAccount(code string) string {
	switch code {
	case md5Channel:
		return "md5-demo"
	case epayChannel:
		return "epay-demo"
	default:
		stop("unknown demo channel %q", code)
		return ""
	}
}

func instructionTTL(raw string) time.Duration {
	ttl := 10 * time.Minute
	if raw != "" {
		var err error
		ttl, err = time.ParseDuration(raw)
		require(err == nil && ttl >= time.Second && ttl <= 24*time.Hour && ttl%time.Microsecond == 0,
			"invalid AIPAY_PLUGIN_INSTRUCTION_TTL (expected 1s..24h at microsecond precision)")
	}
	return ttl
}

func unpaidTimeoutSeconds(raw string) int64 {
	ttl := instructionTTL(raw)
	return int64((ttl + time.Hour + time.Second - 1) / time.Second)
}

func (d *driver) riskHold() time.Duration {
	if d.native() {
		return 20 * time.Second
	}
	return 120 * time.Second
}

func (d *driver) approveChannelRisk(variant, channel, effectiveAt string) {
	label := channelKey(variant, "risk")
	approved := d.browser("risk").approve(label, "payment", "/risk-policies/requests", "/risk-policies", object{"change": object{
		"risk_policy_version": d.key(label), "channel_account_id": channel, "hold_duration_seconds": int64(d.riskHold() / time.Second),
		"exceptional_extension_seconds": 60, "dispute_handling_timeout_seconds": 120, "effective_at": effectiveAt, "expected_control_version": 0,
	}})
	policy := obj(approved["risk_policy"])
	d.evidence("hold_duration_seconds", num(policy, "hold_duration_seconds"))
	d.put(channelKey(variant, "effective/risk"), str(policy, "effective_at"))
}

type channelSpec struct {
	name, minAmount, maxAmount string
	priority                   int
	tradeFile, queryFile       string
	tradeKey, queryKey         string
	tradeConfig, queryConfig   object
}

func channelSetup(code string, gateway bool, address, timeout string) channelSpec {
	if code == epayChannel {
		query := object{"gateway": address, "pid": "1001", "unpaid_timeout_seconds": timeout}
		trade := maps.Clone(query)
		trade["product_name"] = "Demo payment"
		return channelSpec{name: "Demo EPay V1", priority: 1, minAmount: "101", maxAmount: "10000000",
			tradeFile: "handoff/epay.json", queryFile: "handoff/epay.json", tradeKey: "merchant_key", queryKey: "merchant_key",
			tradeConfig: trade, queryConfig: query}
	}
	config := object{"account_id": simulatorAccount(code), "gateway": address}
	maxAmount := "10000000"
	if gateway {
		maxAmount = "100"
	}
	return channelSpec{name: "Demo MD5", priority: 1, minAmount: "1", maxAmount: maxAmount,
		tradeFile: "handoff/trade.json", queryFile: "handoff/query.json", tradeKey: "shared", queryKey: "query_key",
		tradeConfig: config, queryConfig: config}
}

func (spec channelSpec) witnessSource(code string, creds map[string]string, config []byte) string {
	var sim struct {
		Accounts []struct {
			ID     string
			Shared string `json:"shared_secret"`
			Query  string `json:"query_shared_secret"`
		}
	}
	decode(config, &sim)
	for _, a := range sim.Accounts {
		if a.ID != simulatorAccount(code) {
			continue
		}
		if code == epayChannel && a.Shared != "" && a.Shared == creds[spec.queryKey] {
			return "upstream-sim/" + a.ID + "/shared_secret"
		}
		if code == md5Channel && a.Query != "" && a.Query != a.Shared && a.Query == creds[spec.queryKey] {
			return "upstream-sim/" + a.ID + "/query_shared_secret"
		}
	}
	stop("verification handoff does not match the expected simulator credential for %s", code)
	return ""
}

func (d *driver) channels() {
	d.login("operations")
	gateway := d.gatewayMode()
	d.setupChannel(md5Channel, gateway)
	if gateway {
		d.setupChannel(epayChannel, gateway)
	}
}

func (d *driver) setupChannel(variant string, gateway bool) {
	live := variant == liveVariant
	code := variant
	if live {
		code = epayChannel
	}
	op := d.browser("operations")
	key := func(k string) string { return channelKey(variant, k) }
	step := func(label string, run func()) { d.step(channelStepName(variant, label), run) }
	epay := code == epayChannel
	var timeout string
	if epay {
		timeout = strconv.FormatInt(unpaidTimeoutSeconds(d.env("payment")["AIPAY_PLUGIN_INSTRUCTION_TTL"]), 10)
		require(d.value(key("unpaid-timeout"), func() string { return timeout }) == timeout,
			"payment instruction TTL changed since EPay channel setup")
	}
	var spec channelSpec
	if live {
		spec = liveChannelSpec(d.liveCredentials(), timeout)
	} else {
		spec = channelSetup(code, gateway, d.addresses().gateway, timeout)
		d.publishChannelPlugins(code)
	}
	ch := d.key(key("channel"))
	if gateway {
		tradeStep, sealLabel := "交易凭据", "seal-trade"
		if epay {
			tradeStep, sealLabel = "商户密钥凭据", "seal-merchant-key"
		}
		step(tradeStep, func() {
			creds := d.channelCredentials(variant, spec.tradeFile, spec.tradeKey)
			require(len(creds) == 1 && creds[spec.tradeKey] != "", "missing trade credential")
			b := credentialBytes(creds)
			r := op.write(key(sealLabel), "/channel-accounts/credentials", func() object {
				return object{"channel_account_id": ch, "channel_code": code, "credentials_json": b64.EncodeToString(b)}
			})
			d.put(key("trade-digest"), verifiedCredentialDigest(r, b))
			d.put(key("trade-ref"), str(r, "credentials_ref"))
		})
	}
	seller := d.required("seller-account")
	conf := b64.EncodeToString(encoded(spec.tradeConfig))
	effect := func() string {
		return time.Now().UTC().Add(90 * time.Second).Truncate(time.Second).Format(time.RFC3339)
	}
	submit := func(label, kind string, body object) object {
		return op.approve(key(label), "payment", "/"+kind+"/requests", "/"+kind, body)
	}
	if !epay {
		d.step("支付方式", func() {
			submit("method", "payment-methods", object{"change": object{"payment_method": "alipay", "name": "支付宝", "enabled": true, "expected_control_version": 0}})
		})
	}
	config := func(enabled bool) object {
		// Submit the digest that payment will independently read and verify.
		var reviews []object
		decode(d.input("seller-reviews.json"), &reviews)
		var digest []byte
		for _, r := range reviews {
			if r["seller_account_id"] == seller {
				var e error
				digest, e = hex.DecodeString(str(r, "review_sha256"))
				check(e)
			}
		}
		require(len(digest) == 32, "payment requires a verified seller review in its configured development seller reviews file")
		c := object{"channel_account_id": ch, "channel_code": code, "name": spec.name, "seller_account_id": seller, "seller_review_sha256": b64.EncodeToString(digest), "payment_methods": []string{"alipay"}, "fiat_currency": "CNY", "min_amount_fiat_minor": spec.minAmount, "max_amount_fiat_minor": spec.maxAmount, "daily_limit_fiat_minor": "100000000", "priority": spec.priority, "weight": 1, "credentials_ref": "sim-md5-v1", "config_json": conf, "enabled": enabled, "callback_source_cidrs": d.callbackCIDRs()}
		if gateway {
			c["credentials_ref"] = d.required(key("trade-ref"))
			c["credentials_sha256"] = d.required(key("trade-digest"))
		}
		return c
	}
	step("卖方通道绑定", func() {
		submit("channel", "channel-accounts", object{"change": object{"configuration": config(false), "expected_control_version": 0}})
	})
	sides := []string{"channel"}
	if !epay {
		sides = append(sides, "merchant")
	}
	for _, side := range sides {
		label := "定价 " + side
		if epay {
			label = "通道定价"
		}
		step(label, func() {
			c := object{"side": side, "fiat_currency": "CNY", "markup_ppm": 0, "fee_rate_ppm": 10000}
			if side == "merchant" {
				c["platform_default"] = object{}
			} else {
				c["channel_account_id"] = ch
			}
			r := op.write(key("draft/"+side), "/pricing-drafts", func() object { return object{"configuration": c, "effective_at": effect()} })
			approved := submit("pricing/"+side, "pricing-versions", object{"draft_id": str(r, "draft_id"), "expected_revision": num(r, "revision"), "expected_control_version": 0})
			d.put(key("effective/"+side), str(obj(obj(approved["pricing_version"])["draft"]), "effective_at"))
		})
	}
	step("风控", func() {
		d.approveChannelRisk(variant, ch, effect())
	})
	if epay && !live {
		d.liveStep(key("EPay 通道凭据核对"), func() {
			current := op.api("GET", "/channel-accounts/"+ch, "", nil)
			c := obj(current["configuration"])
			require(c["channel_code"] == code, "预期 EPay 通道")
			ref, digest := d.required(key("trade-ref")), d.required(key("trade-digest"))
			if c["credentials_ref"] == ref && c["credentials_sha256"] == digest {
				return
			}
			enabled, ok := c["enabled"].(bool)
			require(ok, "missing channel enabled flag")
			v := num(current, "control_version")
			submit(fmt.Sprintf("update-merchant-key/%d", v), "channel-accounts", object{"change": object{
				"configuration": config(enabled), "expected_control_version": v,
			}})
		})
	}
	version := func() int64 { return num(op.api("GET", "/channel-accounts/"+ch, "", nil), "control_version") }
	step("支付插件绑定", func() {
		plugin := d.required("plugin/" + code)
		// payment binds every enable proposal to the plugin's own control version.
		var pluginVersion int64
		for _, item := range func() []any { v, _ := op.api("GET", "/plugins?limit=100", "", nil)["items"].([]any); return v }() {
			if p := obj(item); str(p, "plugin_version_id") == plugin {
				pluginVersion = num(p, "control_version")
			}
		}
		require(pluginVersion > 0, "published payment plugin not found in the platform plugin list")
		label := "enable-plugin"
		if epay {
			// The previous failed binding cached a request body with the pre-repair channel version.
			label = "enable-plugin-merchant-key"
		}
		submit(label, "plugin-enables", object{"channel_account_id": ch, "plugin_version_id": plugin, "expected_control_version": version(), "expected_plugin_control_version": pluginVersion})
	})
	step("通道启用", func() {
		for _, effective := range []string{key("effective/channel"), "effective/merchant", key("effective/risk")} {
			t, e := time.Parse(time.RFC3339Nano, d.required(effective))
			check(e)
			if delay := time.Until(t); delay > 0 {
				d.sleep(delay)
			}
		}
		v := version()
		if live {
			// Replaying an approved enable must use its original version.
			versionKey := key("enable-control-version")
			if !d.read(versionKey, &v) {
				d.put(versionKey, v)
			}
		}
		submit("enable-channel", "channel-accounts", object{"change": object{"configuration": config(true), "expected_control_version": v}})
	})
	if gateway && code == md5Channel {
		d.liveStep("form-md5 通道限额 1.00 元", func() {
			current := op.api("GET", "/channel-accounts/"+ch, "", nil)
			c := obj(current["configuration"])
			require(c["channel_code"] == md5Channel && c["enabled"] == true, "预期已启用的 form-md5 通道")
			if str(c, "max_amount_fiat_minor") == spec.maxAmount {
				return
			}
			v := num(current, "control_version")
			submit(fmt.Sprintf("limit-form-md5/%d", v), "channel-accounts", object{"change": object{
				"configuration": config(true), "expected_control_version": v,
			}})
		})
	}
	verifyID := d.key(key("verify-account"))
	witnessStep := "独立只读凭据见证"
	if epay {
		witnessStep = "EPay 同钥凭据见证"
	}
	step(witnessStep, func() {
		creds := d.channelCredentials(variant, spec.queryFile, spec.queryKey)
		source := "operator-file/EPAY_TEST_KEY"
		if !live {
			source = spec.witnessSource(code, creds, d.input("inputs/upstream-sim/config.json"))
		}
		b := encoded(creds)
		if gateway {
			require(len(creds) == 1, "unexpected verification credential fields")
			b = credentialBytes(creds)
		}
		sum := sha256.Sum256(b)
		if epay {
			require(b64.EncodeToString(sum[:]) == d.required(key("trade-digest")), "EPay witness differs from sealed trade credential")
		}
		kid := d.key(key("attestation"))
		d.registry("attestations", kid, object{"id": kid, "channel_id": ch, "channel_code": code, "credentials_sha256": fmt.Sprintf("%x", sum), "valid_until": time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second), "source": source, "witness": "demo-verification-witness"})
		r := op.write(key("seal"), "/verification/credentials", func() object { return object{"channel_account_id": ch, "credentials_json": b64.EncodeToString(b)} })
		if gateway {
			d.put(key("query-digest"), verifiedCredentialDigest(r, b))
		}
		d.put(key("query-ref"), str(r, "credentials_ref"))
	})
	step("核验账户与启用", func() {
		p := "/verification/accounts"
		c := object{"verification_account_id": verifyID, "channel_account_id": ch, "name": "Demo query", "config_json": b64.EncodeToString(encoded(spec.queryConfig)), "credentials_ref": d.required(key("query-ref"))}
		if gateway {
			c["credentials_sha256"] = d.required(key("query-digest"))
		}
		op.approve(key("verification-account"), "reconciliation", p+"/requests", p, object{"change": object{"expected_control_version": 0, "configuration": c}})
		v := op.api("GET", p+"/"+verifyID, "", nil)
		p = "/verification/enables"
		op.approve(key("verification-enable"), "reconciliation", p+"/requests", p, object{"verification_account_id": verifyID, "expected_control_version": num(v, "control_version"), "plugin_version_id": d.required("plugin/" + code + "_verify")})
	})
}

func (d *driver) publishChannelPlugins(code string) {
	op := d.browser("operations")
	for _, plugin := range []struct{ code, owner, path string }{{code, "payment", "/plugins"}, {code + "_verify", "reconciliation", "/verification/plugins"}} {
		d.step("双批发布 "+plugin.code, func() {
			m := op.approve(plugin.code, plugin.owner, plugin.path, plugin.path, d.upload(plugin.code))
			d.put("plugin/"+plugin.code, str(obj(m["plugin_version"]), "plugin_version_id"))
		})
	}
}

func (d *driver) channelCredentials(variant, path, field string) map[string]string {
	if variant == liveVariant {
		return map[string]string{field: d.liveCredentials().key}
	}
	var creds map[string]string
	decode(d.input(path), &creds)
	return creds
}
