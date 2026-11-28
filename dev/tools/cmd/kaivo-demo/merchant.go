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
	var ms []message
	decode(d.fixtureRecord("messages.json"), &ms)
	return ms
}

type delivery struct {
	ID, After, Chat, User int64
	Command               string
	Date                  int64
	TOTPStep              int64
	Sent                  bool
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
	// Loading the webhook configuration can cross a TOTP step on a resumed run.
	env := d.env("backend")
	var t delivery
	pending := d.read(key, &t)
	if pending && t.TOTPStep != 0 {
		now := totpStep(time.Now())
		if t.TOTPStep < now-iamTOTPSkewSteps || t.TOTPStep > now+iamTOTPSkewSteps {
			// A crash can fall between the HTTP write and its checkpoint. Reconcile
			// an expired pending update even if the write was never confirmed.
			if msg, found := d.checkExpiredDelivery(label, t); found {
				d.put(key+"/reply", msg)
				return msg
			}
			delete(d.data, key)
			d.save()
			pending = false
		}
	}
	if !pending {
		t = d.newDelivery(user, chat, command)
		d.put(key, t)
	}
	d.sendDelivery(env, key, &t, !pending)
	replies := d.deliveryReplies(t)
	require(len(replies) > 0, "webhook acknowledged without a bot reply (check monitor and fixtures)")
	msg := replies[0]
	if botRefused(msg.Text) {
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

func (d *driver) newDelivery(user, chat int64, command func() string) delivery {
	var serial int64
	if !d.read("update_id", &serial) {
		// Backend keeps update digests for 24 hours, including across fresh driver states.
		serial = time.Now().UnixMilli()
	}
	serial++
	d.put("update_id", serial)
	t := delivery{ID: serial, After: int64(len(d.messages())), Chat: chat, User: user}
	previous := d.commandTOTPStep
	d.commandTOTPStep = &t.TOTPStep
	defer func() { d.commandTOTPStep = previous }()
	t.Command = command()
	t.Date = time.Now().Unix()
	return t
}

func (d *driver) sendDelivery(env map[string]string, key string, t *delivery, firstAttempt bool) {
	defer func() {
		// A failed replay cannot rule out a write by an earlier driver.
		if firstAttempt && !t.Sent {
			delete(d.data, key)
			d.save()
		}
	}()
	d.postTelegram(env, *t, func() error {
		if t.Sent {
			return nil
		}
		t.Sent = true
		d.data[key] = encoded(t)
		return d.saveState()
	})
}

func (d *driver) postTelegram(env map[string]string, t delivery, markSent func() error) {
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
	var code int
	if markSent == nil {
		code, _ = b.send(req, route+" "+cmd)
	} else {
		code = b.sendTracked(req, route+" "+cmd, markSent)
	}
	require(code == 200, "webhook delivery failed")
}

func (d *driver) deliveryReplies(t delivery) []message {
	var replies []message
	replyChat := t.Chat
	if t.Command == "/bind_group" {
		replyChat = t.User
	}
	for _, m := range d.messages() {
		if m.ID > t.After && m.Chat == replyChat && !accountNoticeText(m.Text) {
			replies = append(replies, m)
		}
	}
	return replies
}

func botRefused(s string) bool {
	return s == "\u8bf7\u6c42\u65e0\u6cd5\u5904\u7406" || strings.HasPrefix(s, "\u8f93\u5165\u683c\u5f0f\u6709\u8bef") || s == "\u5c1a\u672a\u5f00\u653e"
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
				require(v1KeyReply.MatchString(m.Text), "IAM did not deliver V1 KEY")
				check(atomic(filepath.Join(d.dir, "merchant-key.json"), encoded(object{"PID": d.required("pid/v1"), "Key": m.Text})))
				d.syncMerchantKeys()
				d.waitFor("backend deleteMessage for KEY", 6*time.Minute, func() bool {
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
				require(s == v2UploadReply, "RSA upload refused")
			}
			if proto == "v2" {
				keyInfo := d.bot("platform-key", "/platform_key "+app)
				spki := standard(capture(`（SPKI DER Base64）\n([A-Za-z0-9+/=]+)$`, keyInfo))
				key, e := x509.ParsePKIXPublicKey(spki)
				check(e)
				_, ok := key.(*rsa.PublicKey)
				require(ok, "invalid platform RSA key")
				check(atomic(filepath.Join(d.dir, "merchant-v2.json"), encoded(object{"pid": d.required("pid/v2"), "spki": spki})))
				d.syncMerchantKeys()
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
					input = d.addresses().notify + " https://merchant.aipay.test"
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
			require(apps[app] && str(target, "notify_origin") == d.addresses().notify && str(target, "return_origin") == "https://merchant.aipay.test", "unexpected application notification target")
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
