package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const (
	md5Channel  = "sim_form_md5"
	epayChannel = "epay_v1"
)

func pluginWorld(code string) string {
	if strings.HasSuffix(code, "_verify") {
		return "verification"
	}
	return "payment"
}

var releaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func versionAtLeast(version, minimum string) bool {
	got, want := releaseVersion.FindStringSubmatch(version), releaseVersion.FindStringSubmatch(minimum)
	if got == nil || want == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		// Canonical decimal integers compare by length, then lexically at equal length.
		if len(got[i]) != len(want[i]) {
			return len(got[i]) > len(want[i])
		}
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return true
}

func (d *driver) gatewayMode() bool {
	trade := d.env("payment")["AIPAY_UPSTREAM_GATEWAY_ADDRESS"] != ""
	if !d.native() {
		verification := d.env("reconciliation")["AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS"] != ""
		require(trade == verification, "payment-config/AIPAY_UPSTREAM_GATEWAY_ADDRESS and reconciliation-config/AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS must both be configured or both be absent")
	}
	return trade
}

func (d *driver) gatewayRepo() string {
	return filepath.Join(filepath.Dir(d.repo), "upstream-gateway")
}

func (d *driver) gatewayHead(required bool) string {
	repo := d.gatewayRepo()
	if _, err := os.Stat(repo); os.IsNotExist(err) {
		require(!required, "Rust plugin builds require the sibling upstream-gateway repository or KAIVO_DEMO_PLUGIN_PACKAGES")
		return ""
	} else {
		check(err)
	}
	return strings.TrimSpace(string(command(repo, os.Environ(), "git", "rev-parse", "--verify", "HEAD^{commit}")))
}

func (d *driver) checkGatewayPackage(code string, manifest, wasm []byte, head string) (string, []byte) {
	if !d.native() {
		var m struct {
			Version string
			Domains []string
		}
		decode(manifest, &m)
		minimum := "0.3.1"
		if code == epayChannel+"_verify" {
			minimum = "0.2.1"
		}
		require(versionAtLeast(m.Version, minimum), fmt.Sprintf("%s requires version %s or newer in Kubernetes (manifest version %q)", code, minimum, m.Version))
		sim, err := url.Parse(d.addresses().gateway)
		check(err)
		require(slices.Contains(m.Domains, sim.Hostname()), fmt.Sprintf("%s manifest domains must include %s", code, sim.Hostname()))
	}
	return gatewayPackage(code, manifest, wasm, head)
}

// Read the exact bytes written by Rust pluginctl. Go's JSON escaping rules differ.
func gatewayPackage(code string, manifest, wasm []byte, expectedCommit string) (string, []byte) {
	var manifestObject object
	decode(manifest, &manifestObject)
	var canonical bytes.Buffer
	writeGatewayJSON(&canonical, manifestObject)
	require(bytes.Equal(canonical.Bytes(), manifest), "manifest.json must contain canonical v3 bytes: "+code)
	if code == epayChannel || code == epayChannel+"_verify" {
		config, _ := manifestObject["config"].(object)
		field, _ := config["unpaid_timeout_seconds"].(object)
		require(field["type"] == "string" && field["required"] == true, code+" manifest must declare required string unpaid_timeout_seconds")
		minimum := "0.3.0"
		if pluginWorld(code) == "verification" {
			minimum = "0.2.0"
		}
		v, _ := manifestObject["version"].(string)
		require(versionAtLeast(v, minimum), fmt.Sprintf("%s requires version %s or newer (manifest version %q)", code, minimum, v))
	}
	require(str(manifestObject, "type") == pluginWorld(code), "wrong plugin world: "+code)
	require(str(manifestObject, "code") == code && num(manifestObject, "abi_version") == 3, "wrong plugin code or ABI (expected v3): "+code)
	commit := str(obj(manifestObject["build"]), "source_commit")
	_, err := hex.DecodeString(commit)
	require((len(commit) == 40 || len(commit) == 64) && err == nil, "invalid source_commit for "+code)
	require(expectedCommit == "" || commit == expectedCommit, "source_commit differs from upstream-gateway HEAD: "+code)
	require(len(wasm) > 0, "empty plugin.wasm: "+code)
	h := sha256.New()
	h.Write(manifest)
	h.Write(wasm)
	return commit, h.Sum(nil)
}

// Only public build tools use this runner. Preserve their toolchain diagnostics.
func pluginCommand(dir string, env []string, bin string, args ...string) []byte {
	c := exec.Command(bin, args...)
	c.Dir, c.Env, c.Stderr = dir, env, os.Stderr
	out, err := c.Output()
	if err != nil {
		stop("%s %s failed (%v). Check upstream-gateway/build-config.json and rust-toolchain.toml for the required Rust, wasm32 target, wasm-tools and Python versions", filepath.Base(bin), args[0], err)
	}
	return out
}

func (d *driver) gatewayPackages() {
	d.buildGatewayPackages(os.Getenv("KAIVO_DEMO_PLUGIN_PACKAGES"), md5Channel, md5Channel+"_verify", epayChannel, epayChannel+"_verify")
}

func (d *driver) buildGatewayPackages(prebuilt string, codes ...string) {
	head := d.gatewayHead(prebuilt == "")
	source := filepath.Join(d.dir, "upstream-gateway-"+head)
	packages := prebuilt
	var env []string
	var ctl string
	if prebuilt == "" {
		if _, err := os.Stat(source); os.IsNotExist(err) {
			pluginCommand(d.dir, os.Environ(), "git", "clone", "--no-local", "--", d.gatewayRepo(), source)
		}
		got := command(source, os.Environ(), "git", "rev-parse", "HEAD")
		require(strings.TrimSpace(string(got)) == head, "cloned upstream-gateway HEAD changed; rerun packages")
		require(len(command(source, os.Environ(), "git", "status", "--porcelain", "--untracked-files=all")) == 0, "demo upstream-gateway clone has uncommitted changes")
		target := os.Getenv("CARGO_TARGET_DIR")
		if !filepath.IsAbs(target) {
			if target == "" {
				target = "target"
			}
			target = filepath.Join(source, target)
		}
		env = append(os.Environ(), "CARGO_TARGET_DIR="+target)
		pluginCommand(source, env, "cargo", "build", "--release", "--locked", "-p", "pluginctl")
		ctl = filepath.Join(target, "release", "pluginctl")
		packages = filepath.Join(source, "dist", "packages")
	} else {
		var err error
		packages, err = filepath.Abs(prebuilt)
		check(err)
	}
	for _, code := range codes {
		d.liveStep("Rust 插件 "+code, func() {
			pkg := filepath.Join(packages, code)
			var receipt []byte
			if prebuilt == "" {
				build := filepath.Join(source, "dist", "build", code)
				pluginCommand(source, env, ctl, "build", "--plugin", "guest/plugins/"+code, "--out", build)
				receipt = pluginCommand(source, env, ctl, "package", "--dir", build, "--out", pkg)
				pluginCommand(source, env, ctl, "replay", "--dir", pkg, "--out", filepath.Join(source, "dist", code+"-replay.json"))
			}
			commit, digest := d.checkGatewayPackage(code, file(filepath.Join(pkg, "manifest.json")), file(filepath.Join(pkg, "plugin.wasm")), head)
			fixtures, err := os.ReadDir(filepath.Join(pkg, "fixtures"))
			check(err)
			require(len(fixtures) > 0, "missing gateway package fixtures: "+code)
			hash := hex.EncodeToString(digest)
			if prebuilt == "" {
				require(bytes.Contains(receipt, []byte("package_sha256 "+hash+"\n")), "local digest differs from pluginctl package output")
			}
			fmt.Printf("%s source_commit %s package_sha256 %s\n", code, commit, hash)
			d.evidence("commit", commit)
			d.evidence("package_sha256", hash)
			d.put("hash/"+code, hash)
			d.put("package/"+code, pkg)
		})
	}
}

// The gateway hashes compact UTF-8 JSON with sorted names and lowercase
// four-digit escapes for controls, including newline. There is no trailing LF.
func credentialBytes(creds map[string]string) []byte {
	values := object{}
	for name, value := range creds {
		values[name] = value
	}
	var out bytes.Buffer
	writeGatewayJSON(&out, values)
	return out.Bytes()
}

// These v3 manifests use JSON integers, booleans, strings, arrays and objects.
// Both the Rust manifest writer and the credential contract use this quoting.
func writeGatewayJSON(out *bytes.Buffer, value any) {
	switch v := value.(type) {
	case object:
		out.WriteByte('{')
		for i, key := range slices.Sorted(maps.Keys(v)) {
			if i > 0 {
				out.WriteByte(',')
			}
			writeGatewayJSON(out, key)
			out.WriteByte(':')
			writeGatewayJSON(out, v[key])
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			writeGatewayJSON(out, item)
		}
		out.WriteByte(']')
	case string:
		out.WriteByte('"')
		for _, c := range v {
			switch {
			case c == '"' || c == '\\':
				out.WriteByte('\\')
				out.WriteRune(c)
			case c < 0x20:
				fmt.Fprintf(out, "\\u%04x", c)
			default:
				out.WriteRune(c)
			}
		}
		out.WriteByte('"')
	case json.Number:
		n, err := v.Int64()
		check(err)
		fmt.Fprint(out, n)
	case bool:
		fmt.Fprint(out, v)
	case nil:
		out.WriteString("null")
	default:
		stop("unexpected gateway JSON value")
	}
}

func verifiedCredentialDigest(response object, canonical []byte) string {
	expected := sha256.Sum256(canonical)
	digest := str(response, "credentials_sha256")
	require(bytes.Equal(raw(digest), expected[:]), "stored credentials_sha256 differs from the local content digest")
	return digest
}
