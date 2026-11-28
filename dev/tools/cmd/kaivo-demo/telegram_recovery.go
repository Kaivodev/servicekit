package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Each lookup uses the sender and chat of the original update.
var telegramRecoveryChecks = map[string]string{
	"/business_create": "/businesses",
	"/app_create":      "/apps",
	"/key_generate":    "/app",
	"/key_upload":      "/app",
	"/app_enabled":     "/app",
}

// Localized fields in the bot's wire format.
const (
	botSeparator   = " \u00b7 "
	accountPrefix  = "\u4e2a\u4eba\u8d26\u6237 "
	nextPagePrefix = "\u4e0b\u4e00\u9875\u6e38\u6807 "
	noBotRecords   = "\u65e0\u8bb0\u5f55"
	v2UploadReply  = "\u5df2\u4e0a\u4f20 V2 \u516c\u94a5"
)

var (
	businessRow = regexp.MustCompile("^(" + uuidPattern + ")" + botSeparator + "(.+)" + botSeparator + "\u5f52\u5c5e\u7248\u672c [1-9][0-9]*$")
	appRow      = regexp.MustCompile("^(" + uuidPattern + ")" + botSeparator + "(.+)" + botSeparator + "PID [0-9]+" + botSeparator +
		"\u4e1a\u52a1 (" + uuidPattern + ")" + botSeparator + "\u542f\u7528 (true|false)" + botSeparator +
		"\u7248\u672c ([1-9][0-9]*)" + botSeparator + "V1 (true|false)" + botSeparator + "V2 (true|false)$")
	v1KeyReply = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
)

type botApplication struct {
	id, name, business string
	enabled, v1, v2    bool
	version            uint64
}

func parseBotApplication(line, why string) botApplication {
	m := appRow.FindStringSubmatch(line)
	require(m != nil, why+": invalid application row")
	version, err := strconv.ParseUint(m[5], 10, 64)
	require(err == nil, why+": invalid application version")
	return botApplication{id: m[1], name: m[2], business: m[3], enabled: m[4] == "true", version: version, v1: m[6] == "true", v2: m[7] == "true"}
}

// Use a fresh update for each read. A cached absence cannot authorize a retry.
func (d *driver) queryBot(t delivery, command, why string) message {
	q := d.newDelivery(t.User, t.Chat, func() string { return command })
	d.postTelegram(d.env("backend"), q, nil)
	replies := d.deliveryReplies(q)
	require(len(replies) > 0, why+": missing read-only reply")
	var text strings.Builder
	for i, m := range replies {
		require(!m.Deleted && m.Text != "" && m.Document == nil && !botRefused(m.Text), why+": invalid read-only reply")
		// Backend splits a long reply into consecutive messages of 2000 runes.
		require(i == len(replies)-1 || utf8.RuneCountInString(m.Text) == 2000, why+": ambiguous read-only replies")
		text.WriteString(m.Text)
	}
	reply := replies[0]
	reply.Text = text.String()
	return reply
}

func (d *driver) checkExpiredDelivery(label string, t delivery) (message, bool) {
	fields := strings.Fields(t.Command)
	require(len(fields) > 0, "empty Telegram command for label "+label)
	cmd := fields[0]
	why := fmt.Sprintf("cannot confirm expired %s for label %q", cmd, label)
	check, ok := telegramRecoveryChecks[cmd]
	require(ok, why+": no read-only check")
	require(len(fields) >= 4, why+": invalid stored command")
	// Omit the command and the secret from the arguments used by lookups.
	args := fields[1 : len(fields)-1]
	switch check {
	case "/businesses":
		name := strings.Join(args[1:], " ")
		return d.findBotRow(t, check, accountPrefix+args[0], why, func(line string) bool {
			m := businessRow.FindStringSubmatch(line)
			require(m != nil, why+": invalid business row")
			return m[2] == name
		})
	case "/apps":
		v1 := args[1] == "v1"
		nameAt := 2
		if v1 {
			nameAt++ // V1 has a CIDR argument before the name.
		}
		require((v1 || args[1] == "v2") && len(args) > nameAt, why+": invalid stored application command")
		name := strings.Join(args[nameAt:], " ")
		return d.findBotRow(t, check+" "+args[0], "", why, func(line string) bool {
			app := parseBotApplication(line, why)
			require(app.business == args[0], why+": unexpected business")
			if app.name != name {
				return false
			}
			require(app.v1 == v1 && app.v2 != v1, why+": application protocol mismatch")
			return true
		})
	default: // All three versioned commands check the exact application.
		return d.checkBotApplication(t, cmd, args, check+" "+args[0], why)
	}
}

func (d *driver) findBotRow(t delivery, query, header, why string, matches func(string) bool) (message, bool) {
	var found message
	command := query
	seen := map[string]bool{}
	for {
		reply := d.queryBot(t, command, why)
		lines := strings.Split(reply.Text, "\n")
		cursor := ""
		if tail, ok := strings.CutPrefix(lines[len(lines)-1], nextPagePrefix); ok {
			require(tail != "" && !strings.ContainsAny(tail, " \t\r\n") && !seen[tail], why+": invalid pagination cursor")
			cursor = tail
			seen[cursor] = true
			lines = lines[:len(lines)-1]
		}
		if header != "" {
			require(len(lines) > 0 && lines[0] == header, why+": unexpected account")
			lines = lines[1:]
		} else if len(lines) == 1 && lines[0] == noBotRecords {
			lines = nil
		} else {
			require(len(lines) > 0, why+": missing list contents")
		}
		for _, line := range lines {
			if matches(line) {
				require(found.ID == 0, why+": multiple matching rows")
				found = reply
				found.Text = line
			}
		}
		if cursor == "" {
			return found, found.ID != 0
		}
		command = query + " " + cursor
	}
}

func (d *driver) checkBotApplication(t delivery, cmd string, args []string, query, why string) (message, bool) {
	expected, err := strconv.ParseUint(args[1], 10, 64)
	require(err == nil && expected > 0, why+": invalid stored version")
	reply := d.queryBot(t, query, why)
	app := parseBotApplication(reply.Text, why)
	require(app.id == args[0], why+": unexpected application")
	switch cmd {
	case "/app_enabled":
		require(len(args) == 3 && (args[2] == "on" || args[2] == "off"), why+": invalid stored enabled state")
		if app.enabled == (args[2] == "on") {
			return reply, true
		}
		require(app.version == expected, why+": enabled state and version changed")
		return message{}, false
	case "/key_generate":
		require(len(args) == 2 && app.v1, why+": expected a V1 application")
	case "/key_upload":
		require(len(args) == 3 && app.v2, why+": expected a V2 application")
	}
	if app.version == expected {
		return message{}, false
	}
	// Other mutations also advance the version. The original acknowledgement
	// identifies the key operation and supplies the one-time V1 secret and ID.
	require(app.version-1 == expected, why+": unexpected application version")
	original := d.deliveryReplies(t)
	require(len(original) > 0 && original[0].ID < reply.ID && !original[0].Deleted &&
		(cmd == "/key_generate" && v1KeyReply.MatchString(original[0].Text) ||
			cmd == "/key_upload" && original[0].Text == v2UploadReply), why+": original key reply unavailable")
	return original[0], true
}
