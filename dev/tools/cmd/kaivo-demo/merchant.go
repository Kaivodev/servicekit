package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func capture(pattern, s string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	require(len(m) == 2, "unexpected browser or bot reply format")
	return m[1]
}

const uuidPattern = "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"

func (d *driver) messages() []message {
	ms, e := readRecords[message](filepath.Join(d.dir, "messages.json"))
	check(e)
	return ms
}

type delivery struct {
	ID, After, Chat, User int64
	Command               string
	Date                  int64
}

func (t delivery) update() object {
	kind := "private"
	if t.Chat < 0 {
		kind = "supergroup"
	}
	return object{"update_id": t.ID, "message": object{"message_id": t.ID, "date": t.Date, "from": object{"id": t.User, "is_bot": false, "first_name": "Demo"}, "chat": object{"id": t.Chat, "type": kind}, "text": t.Command}}
}
func (d *driver) telegram(label string, chat int64, command func() string) message {
	return d.deliver(label, merchantUser, chat, command)
}
func (d *driver) deliver(label string, user, chat int64, command func() string) message {
	require(user > 0 && (chat == user || chat < 0), "invalid Telegram sender or chat")
	key := "telegram/" + d.scope + "/" + label
	var saved message
	if d.read(key+"/reply", &saved) {
		return saved
	}
	var t delivery
	if !d.read(key, &t) {
		var serial int64
		d.read("update_id", &serial)
		serial++
		d.put("update_id", serial)
		t = delivery{serial, int64(len(d.messages())), chat, user, command(), time.Now().Unix()}
		d.put(key, t)
	}
	env := d.env("backend")
	route := env["AIPAY_TELEGRAM_WEBHOOK_PATH"]
	if route == "" {
		route = "/telegram/webhook"
	}
	b := d.browser("merchant")
	cmd := strings.Fields(t.Command)[0]
	req := b.request("POST", route, "application/json", encoded(t.update()), map[string]string{"X-Telegram-Bot-Api-Secret-Token": env["AIPAY_TELEGRAM_WEBHOOK_SECRET"]})
	if cmd == "/start" {
		d.queueStart(t.User)
	}
	code, _ := b.send(req, route+" "+cmd)
	require(code == 200, "webhook delivery failed")
	var msg message
	for _, m := range d.messages() {
		replyChat := chat
		if t.Command == "/bind_group" {
			replyChat = user
		}
		if m.ID > t.After && m.Chat == replyChat && !accountNoticeText(m.Text) {
			msg = m
			break
		}
	}
	require(msg.ID > 0, "webhook acknowledged without a bot reply (check monitor and fixtures)")
	if msg.Text == "请求无法处理" || strings.HasPrefix(msg.Text, "输入格式有误") || msg.Text == "尚未开放" {
		// Definitive refusal: a new update (and a fresh TOTP) is needed after the cause is fixed.
		delete(d.data, key)
		if strings.HasPrefix(t.Command, "/access_submit ") {
			delete(d.data, "access-submit-pending")
		}
		d.save()
		stop("backend bot rejected %s", strings.Fields(t.Command)[0])
	}
	require(msg.Text != "" || msg.Document != nil, "bot reply was deleted before delivery could be confirmed")
	d.put(key+"/reply", msg)
	return msg
}
func (d *driver) bot(key, cmd string) string {
	return d.telegram(key, merchantUser, func() string { return cmd }).Text
}
func (d *driver) merchant() {
	d.step("Telegram 注册", func() {
		s := d.bot("start", "/start")
		require(strings.Contains(s, "注册或登录已完成"), "registration refused")
	})
	d.step("商户浏览器 TOTP", func() {
		link := d.bot("enroll", "/totp")
		token := capture(`^https://merchant\.aipay\.test/totp/enroll/([A-Za-z0-9_-]+)$`, link)
		p := "/totp/enroll/" + token
		b := d.browser("merchant")
		code, page := b.http("GET", p, "/totp/enroll/{token}", "", nil, nil)
		require(code == 200, "enrollment page rejected")
		pageHTML := html.UnescapeString(string(page))
		d.put("totp/merchant", qrSecret(standard(capture(`data:image/png;base64,([A-Za-z0-9+/=]+)`, pageHTML))))
		v := url.Values{}
		for _, k := range []string{"csrf", "enrollment_id", "completion_token"} {
			v.Set(k, capture(`name="`+k+`" value="([^"]+)"`, pageHTML))
		}
		v.Set("code", d.freshTOTP("merchant"))
		code, page = b.http("POST", p, "/totp/enroll/{token}", "application/x-www-form-urlencoded", form(v), nil)
		require(code == 200 && strings.Contains(string(page), "TOTP 绑定已完成"), "IAM TOTP confirmation refused")
	})
	d.step("商户账户与业务", func() {
		bal := d.bot("account", "/balance")
		account := capture("^账户 ("+uuidPattern+")", bal)
		d.put("merchant-account", account)
		s := d.telegram("business", merchantUser, func() string { return "/business_create " + account + " Demo " + d.freshTOTP("merchant") }).Text
		d.put("business", capture("^("+uuidPattern+") ·", s))
		d.put("ownership", capture(`归属版本 ([0-9]+)`, s))
		d.evidence("account_id", account)
	})
	for _, proto := range []string{"v1", "v2"} {
		d.step("商户应用 "+proto, func() {
			business := d.required("business")
			s := d.telegram("app-"+proto, merchantUser, func() string {
				mode := proto
				if proto == "v1" {
					mode += " 127.0.0.1/32"
				}
				return "/app_create " + business + " " + mode + " Demo-" + proto + " " + d.freshTOTP("merchant")
			}).Text
			app := capture("^("+uuidPattern+") ·", s)
			d.put("app/"+proto, app)
			d.put("pid/"+proto, capture(` · PID ([0-9]+) ·`, s))
			ver := capture(` · 版本 ([0-9]+)`, s)
			if proto == "v1" {
				m := d.telegram("issue-key", merchantUser, func() string { return "/key_generate " + app + " " + ver + " " + d.freshTOTP("merchant") })
				require(regexp.MustCompile(`^[A-Za-z0-9]{32}$`).MatchString(m.Text), "IAM did not deliver V1 KEY")
				check(atomic(filepath.Join(d.dir, "merchant-key.json"), encoded(object{"PID": d.required("pid/v1"), "Key": m.Text})))
				waitFor("backend deleteMessage for KEY", 6*time.Minute, func() bool {
					for _, msg := range d.messages() {
						if msg.ID == m.ID && msg.Chat == merchantUser {
							return msg.Deleted
						}
					}
					return false
				})
				d.evidence("deleted_message_id", m.ID)
			} else {
				priv := d.merchantRSA()
				spki, e := x509.MarshalPKIXPublicKey(&priv.PublicKey)
				check(e)
				s = d.telegram("upload-key", merchantUser, func() string {
					return "/key_upload " + app + " " + ver + " " + base64.StdEncoding.EncodeToString(spki) + " " + d.freshTOTP("merchant")
				}).Text
				require(s == "已上传 V2 公钥", "RSA upload refused")
			}
			if proto == "v2" {
				keyInfo := d.bot("platform-key", "/platform_key "+app)
				spki := standard(capture(`（SPKI DER Base64）\n([A-Za-z0-9+/=]+)$`, keyInfo))
				key, e := x509.ParsePKIXPublicKey(spki)
				check(e)
				_, ok := key.(*rsa.PublicKey)
				require(ok, "invalid platform RSA key")
				check(atomic(filepath.Join(d.dir, "merchant-v2.json"), encoded(object{"pid": d.required("pid/v2"), "spki": spki})))
			}
			info := d.bot("app-info/"+proto, "/app "+app)
			if strings.Contains(info, "启用 false") {
				d.telegram("app-enable/"+proto, merchantUser, func() string {
					return "/app_enabled " + app + " " + capture(` · 版本 ([0-9]+)`, info) + " on " + d.freshTOTP("merchant")
				})
			}
		})
	}
	d.step("商户收款申请", func() {
		app1, app2 := d.required("app/v1"), d.required("app/v2")
		var cmd string
		if !d.read("access-submit-pending", &cmd) {
			prompt := d.bot("form/resume/"+id(), "/access_apply")
			for i := 0; !strings.Contains(prompt, "确认 /access_submit"); i++ {
				require(i < 9, "unexpected number of access form prompts")
				revision := capture(`/access_next ([0-9]+) <内容>`, prompt)
				var input string
				switch {
				case strings.HasPrefix(prompt, "请输入业务 ID"):
					input = d.required("business") + " " + d.required("ownership")
				case strings.HasPrefix(prompt, "请输入支付方式"):
					input = "alipay 0"
				case strings.HasPrefix(prompt, "请输入业务名称"):
					input = "Kaivo Demo"
				case strings.HasPrefix(prompt, "请输入商品"):
					input = "阶段二担保收款"
				case strings.HasPrefix(prompt, "请输入经营域名"):
					input = "merchant.aipay.test"
				case strings.HasPrefix(prompt, "请输入该业务的应用 ID"):
					input = app1 + " " + app2
				case strings.HasPrefix(prompt, "请输入应用 "+app1+" "), strings.HasPrefix(prompt, "请输入应用 "+app2+" "):
					input = notifyOrigin + " https://merchant.aipay.test"
				default:
					stop("unknown merchant access prompt")
				}
				prompt = d.bot("form/next/"+revision, "/access_next "+revision+" "+input)
			}
			cmd = capture(`确认 (/access_submit [0-9]+ [0-9a-f-]+)`, prompt)
			d.put("access-submit-pending", cmd)
		}
		s := d.bot("submit/"+strings.Fields(cmd)[1], cmd)
		d.put("access", capture("^("+uuidPattern+") ·", s))
	})
	d.step("审核员审核与商户启用", func() {
		d.login("reviewer")
		p := "/payment-accesses/" + d.required("access")
		b := d.browser("reviewer")
		v := b.api("GET", p, "", nil)
		rev := obj(v["current_revision"])
		require(str(v, "account_id") == d.required("merchant-account") && str(v, "business_id") == d.required("business"), "review scope mismatch")
		materials := obj(rev["materials"])
		targets, _ := materials["notification_targets"].([]any)
		require(len(targets) == 2 && str(v, "payment_method") == "alipay", "review method or target count mismatch")
		apps := map[string]bool{d.required("app/v1"): true, d.required("app/v2"): true}
		domains, ok := materials["domains"].([]any)
		require(ok && len(domains) == 1 && domains[0] == "merchant.aipay.test", "review operating domain mismatch")
		for _, t := range targets {
			target := obj(t)
			app := str(target, "application_id")
			require(apps[app] && str(target, "notify_origin") == notifyOrigin && str(target, "return_origin") == "https://merchant.aipay.test", "unexpected application notification target")
			delete(apps, app)
		}
		h := sha256.Sum256(encoded(materials))
		b.write("review", p+"/reviews", func() object {
			return object{"expected_control_version": num(v, "control_version"), "expected_revision_version": num(rev, "version"), "materials_sha256": str(rev, "materials_sha256"), "decision": "approve", "reason": "核对演示业务及两应用通知来源", "evidence_sha256": b64.EncodeToString(h[:])}
		})
		s := d.bot("access-detail", "/access "+d.required("access"))
		cmd := capture(`启用命令 (/access_enable [0-9a-f-]+ [0-9]+)`, s)
		require(strings.Contains(d.bot("enable", cmd), "启用 true"), "access not enabled")
	})
}
func (d *driver) merchantRSA() *rsa.PrivateKey {
	s := d.value("merchant-rsa", func() string {
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		check(e)
		return b64.EncodeToString(x509.MarshalPKCS1PrivateKey(k))
	})
	k, e := x509.ParsePKCS1PrivateKey(raw(s))
	check(e)
	return k
}
func micro(s string) int64 {
	whole, part, ok := strings.Cut(s, ".")
	require(ok && len(part) == 6, "expected six-digit USDT amount")
	n, e := strconv.ParseInt(whole+part, 10, 64)
	check(e)
	return n
}
