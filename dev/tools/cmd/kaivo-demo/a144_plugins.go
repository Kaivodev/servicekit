package main

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
)

// The two owners expose different version and publication-status field names.
type a144Plugin struct {
	code, minimum, owner                        string
	accountID, accountPath, accountField        string
	plugins, enables, versionField, statusField string
}

func (p a144Plugin) account(d *driver) object {
	view := d.browser("operations").api("GET", p.accountPath+"/"+p.accountID, "", nil)
	c := obj(view["configuration"])
	require(c[p.accountField] == p.accountID && c["channel_account_id"] == d.required("uuid/"+channelKey(epayChannel, "channel")), "EPay 账户绑定不符")
	var config object
	decode(raw(str(c, "config_json")), &config)
	require(config["gateway"] == d.addresses().gateway && config["pid"] == "1001", "EPay 账户未指向演示模拟器")
	require(config["unpaid_timeout_seconds"] == d.required(channelKey(epayChannel, "unpaid-timeout")), "EPay 未付款超时与开通记录不符")
	if p.owner == "payment" {
		require(c["enabled"] == true && c["channel_code"] == p.code, "EPay 交易通道尚未启用")
	} else {
		require(view["enabled"] == true, "EPay 核验账户尚未启用")
	}
	return view
}

func (p a144Plugin) find(d *driver, field, value string) object {
	seen := map[string]bool{}
	for cursor := ""; ; {
		page := d.browser("operations").api("GET", p.plugins+"?limit=100&cursor="+url.QueryEscape(cursor), "", nil)
		items, ok := page["items"].([]any)
		require(ok, "缺少插件列表 "+p.code)
		for _, item := range items {
			row := obj(item)
			if row["code"] == p.code && row[field] == value {
				return row
			}
		}
		cursor, _ = page["next_cursor"].(string)
		if cursor == "" {
			return nil
		}
		require(!seen[cursor], "插件列表重复返回相同游标")
		seen[cursor] = true
	}
}

func (p a144Plugin) enabled(d *driver) object {
	account := p.account(d)
	plugin := p.find(d, "plugin_version_id", str(account, "plugin_version_id"))
	require(plugin != nil && plugin[p.statusField] == "executed" && plugin["emergency_disabled"] == false, "未找到已批准且可用的绑定插件 "+p.code)
	digest := raw(str(plugin, "package_sha256"))
	require(len(digest) == 32, "绑定插件摘要无效 "+p.code)
	return object{"account_id": p.accountID, "control_version": account["control_version"],
		"code": p.code, "version": str(plugin, p.versionField), "plugin_version_id": plugin["plugin_version_id"],
		"package_sha256": hex.EncodeToString(digest), "publication_approval_request_id": str(plugin, "publication_approval_request_id")}
}

func (p a144Plugin) upgrade(d *driver, version string) {
	op := d.browser("operations")
	digest := d.required("hash/" + p.code)
	label := p.code + "/" + digest
	var target string
	d.liveStep("核对并双批发布 "+p.code, func() {
		d.login("operations")
		plugin := p.find(d, p.versionField, version)
		if plugin != nil {
			require(hex.EncodeToString(raw(str(plugin, "package_sha256"))) == digest, "同版本已登记另一份包摘要 "+p.code+" "+version)
		}
		if plugin != nil && plugin[p.statusField] == "executed" {
			target = str(plugin, "plugin_version_id")
			d.evidence("已发布审批", str(plugin, "publication_approval_request_id"))
		} else {
			m := op.approve(label+"/publish", p.owner, p.plugins, p.plugins, d.upload(p.code))
			target = str(obj(m["plugin_version"]), "plugin_version_id")
		}
		d.evidence("包摘要", digest)
	})
	d.liveStep("双批切换 "+p.code, func() {
		account := p.account(d)
		plugin := p.find(d, "plugin_version_id", target)
		require(plugin != nil && plugin[p.statusField] == "executed" && plugin["emergency_disabled"] == false, "待启用插件尚未发布或已停用 "+p.code)
		if account["plugin_version_id"] != target {
			version := num(account, "control_version")
			pluginVersion := num(plugin, "control_version")
			op.approve(fmt.Sprintf("%s/enable/%d/%d", label, version, pluginVersion), p.owner, p.enables+"/requests", p.enables, object{
				p.accountField: p.accountID, "expected_control_version": version, "plugin_version_id": target, "expected_plugin_control_version": pluginVersion,
			})
		}
		current := p.enabled(d)
		d.evidence("启用后绑定", current)
		require(current["plugin_version_id"] == target && current["package_sha256"] == digest, "启用后插件与审批包不符 "+p.code)
	})
}

// Resolve server-side bindings before the order exists. Setup checkpoints only
// identify the demo accounts; they cannot establish which packages are live.
func (d *driver) a144PluginAccounts() []a144Plugin {
	return []a144Plugin{
		{
			code: epayChannel, minimum: "0.4.0", owner: "payment",
			accountID: d.required("uuid/" + channelKey(epayChannel, "channel")), accountPath: "/channel-accounts", accountField: "channel_account_id",
			plugins: "/plugins", enables: "/plugin-enables", versionField: "version", statusField: "publication_status",
		}, {
			code: epayChannel + "_verify", minimum: "0.3.0", owner: "reconciliation",
			accountID: d.required("uuid/" + channelKey(epayChannel, "verify-account")), accountPath: "/verification/accounts", accountField: "verification_account_id",
			plugins: "/verification/plugins", enables: "/verification/enables", versionField: "semver", statusField: "status",
		},
	}
}

func (d *driver) a144Plugins() map[string]string {
	plugins := d.a144PluginAccounts()
	pins := map[string]string{}
	var outdated []string
	d.liveStep("核对交易与核验插件", func() {
		for _, p := range plugins {
			current := p.enabled(d)
			d.evidence(p.code, current)
			pins[p.code] = str(current, "plugin_version_id")
			if !versionAtLeast(str(current, "version"), p.minimum) {
				outdated = append(outdated, p.code)
			}
		}
	})
	if len(outdated) == 0 {
		return pins
	}
	d.buildGatewayPackages("", outdated...)
	versions := map[string]string{}
	d.liveStep("核对升级包版本", func() {
		for _, p := range plugins {
			if !slices.Contains(outdated, p.code) {
				continue
			}
			var manifest object
			decode(file(filepath.Join(d.required("package/"+p.code), "manifest.json")), &manifest)
			v := str(manifest, "version")
			require(versionAtLeast(v, p.minimum), fmt.Sprintf("upstream-gateway HEAD 的 %s 为 %s，需要 %s 或更高版本", p.code, v, p.minimum))
			versions[p.code] = v
		}
		d.evidence("待升级版本", versions)
	})
	for _, p := range plugins {
		if v, ok := versions[p.code]; ok {
			p.upgrade(d, v)
		}
	}
	d.liveStep("制包审批后刷新行情", d.refreshMarket)
	d.liveStep("下单前确认生效包", func() {
		for _, p := range plugins {
			current := p.enabled(d)
			d.evidence(p.code, current)
			require(versionAtLeast(str(current, "version"), p.minimum), p.code+" 绑定版本不足")
			pins[p.code] = str(current, "plugin_version_id")
		}
	})
	return pins
}
