package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type invitationRequest struct {
	Kind            string   `json:"kind"`
	Email           string   `json:"email"`
	Roles           []string `json:"roles,omitempty"`
	SellerAccountID string   `json:"seller_account_id,omitempty"`
}

type invitationFile struct {
	invitationRequest
	InvitationID string    `json:"invitation_id"`
	Origin       string    `json:"origin"`
	Token        string    `json:"token"`
	CreatedAt    time.Time `json:"created_at"`
}

var platformRole = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func parseInvitation(args []string) invitationRequest {
	require(len(args) >= 2, "expected invite platform EMAIL ROLE [ROLE...] or invite seller EMAIL")
	req := invitationRequest{Kind: args[0], Email: args[1]}
	local, domain, ok := strings.Cut(req.Email, "@")
	require(ok && local != "" && domain != "" && !strings.Contains(domain, "@") && len(req.Email) <= 254 &&
		strings.IndexFunc(req.Email, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0, "invalid invitation email")
	switch req.Kind {
	case "platform":
		req.Roles = args[2:]
		require(len(req.Roles) > 0, "platform invitations require at least one role")
		seen := map[string]bool{}
		for _, role := range req.Roles {
			require(platformRole.MatchString(role) && !seen[role], "invalid or duplicate platform role")
			seen[role] = true
		}
	case "seller":
		require(len(args) == 2, "seller invitations take only an email address")
	default:
		stop("unknown invitation kind")
	}
	return req
}

func invitationDirectory(dir string) string {
	dir = filepath.Join(dir, "invitations")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		check(err)
	}
	info, err := os.Lstat(dir)
	check(err)
	require(info.IsDir() && privateDir(dir), "invitations directory must be owned by you with mode 0700")
	return dir
}

func canonicalID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.String() == value
}

func writeInvitation(dir string, invite invitationFile) string {
	require(canonicalID(invite.InvitationID), "invalid invitation ID")
	path := filepath.Join(dir, invite.InvitationID+".json")
	// Publish the complete private file exclusively, even after a crash or a retry.
	f, err := os.CreateTemp(dir, ".invitation-*")
	check(err)
	defer os.Remove(f.Name())
	_, err = f.Write(encoded(invite))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	check(err)
	check(closeErr)
	check(os.Link(f.Name(), path))
	return path
}

// The private handoff survives removal of the transient request keys, including
// handoffs published by older drivers. Ignore temporary or unrelated files.
func publishedInvitationID(dir string, req invitationRequest) string {
	entries, err := os.ReadDir(dir)
	check(err)
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !canonicalID(name) || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		var prior invitationRequest
		require(json.Unmarshal(file(path), &prior) == nil, "invalid published invitation file")
		if prior.Kind == req.Kind && strings.ToLower(prior.Email) == strings.ToLower(req.Email) &&
			prior.SellerAccountID == req.SellerAccountID && slices.Equal(prior.Roles, req.Roles) {
			return name
		}
	}
	return ""
}

// The driver lock serializes allocation. Entries stay in the checkpoint so a
// partner keeps the same Telegram identity after a crash or another invitation.
func (d *driver) partnerTelegramID(email string) int64 {
	const key = "partner-telegram-ids"
	ids := map[string]int64{}
	d.read(key, &ids)
	email = strings.ToLower(email)
	if telegramID, ok := ids[email]; ok {
		return telegramID
	}
	telegramID := merchantUser + 2 + int64(len(ids))
	ids[email] = telegramID
	d.put(key, ids)
	return telegramID
}

func (d *driver) partnerSellerAccount(email, setupAccount string, binding func(string, int64) string) string {
	telegramID := d.partnerTelegramID(email)
	label := fmt.Sprintf("partner-seller-%d", telegramID)
	return d.value(label+"/activated-account", func() string {
		account := d.registerTelegramSeller(label, telegramID)
		require(account != setupAccount, "partner registration returned the setup seller account")
		user := d.value(label+"/owner", func() string { return binding(account, telegramID) })
		d.activateSeller(label, account, user, strings.ToLower(email), "Partner front-end integration")
		return account
	})
}

// The mailbox can contain several invitations to one address. IAM names each
// native delivery file after its outbox ID, which is distinct from the invitation ID.
func (d *driver) invitationMailID(email, invitationID string) string {
	rows := d.rows("iam", "iam_email_outbox",
		"SELECT id FROM iam_email_outbox WHERE invitation_id=$1 AND recipient=$2 AND kind='invitation'", invitationID, email)
	require(len(rows) == 1, "expected one IAM mail delivery for the pending invitation")
	return str(rows[0], "id")
}

func (d *driver) exportInvitation(req invitationRequest, mailID func(email, invitationID string) string) string {
	require(d.native(), "demo invite requires the native target")
	var last result
	require(d.read("step/setup/"+merchantActivationStep, &last) && last.Status == "ok", "complete demo setup before inviting a partner")
	for _, name := range []string{"admin1", "admin2"} {
		d.required("user/" + name)
		d.required("password/" + name)
		require(d.data["authenticator/"+name] != nil, "missing setup authenticator for "+name)
	}
	account := d.required("seller-account")
	origin := d.origins.platform
	requestedEmail := req.Email
	partner := req.Kind == "seller" && strings.ToLower(req.Email) != strings.ToLower(d.required("seller-email"))
	if partner {
		require(d.env("backend")["AIPAY_TELEGRAM_API_BASE_URL"] == "http://127.0.0.1:9081",
			"opening a partner seller account requires mock Telegram mode")
	}
	dir := invitationDirectory(d.dir)
	if req.Kind == "seller" {
		req.SellerAccountID, origin = account, d.origins.seller
		if partner {
			// IAM normalizes email. A retry with different casing must replay
			// the same invitation body and idempotency key.
			req.Email = strings.ToLower(req.Email)
			req.SellerAccountID = d.partnerSellerAccount(req.Email, account, d.sellerBinding)
		}
	}
	key := fmt.Sprintf("partner-invitation/%x", sha256.Sum256(encoded(req)))
	var published string
	if !d.read(key+"/published", &published) {
		published = publishedInvitationID(dir, req)
		if published != "" {
			delete(d.data, key)
			d.put(key+"/published", published)
		}
	}
	if published != "" {
		stop("invitation already published: %s", filepath.Join(dir, published+".json"))
	}

	// A retry can recover a committed creation or approval even if the
	// response or mail was delayed. Only the ID is retained after publication.
	var keys [2]string
	if !d.read(key, &keys) {
		keys = [2]string{id(), id()}
		d.put(key, keys)
	}
	invID, recipient := d.issueInvitation(req, func(admin, path string, body object) object {
		requestID := keys[0]
		if admin == "admin2" {
			requestID = keys[1]
		}
		return d.browser(admin).api("POST", path, requestID, body)
	})
	delivery := mailID(recipient, invID)
	require(canonicalID(delivery), "invalid IAM mail ID")
	token := d.waitForMail(recipient, func() []byte {
		return nativeDelivery(d.root, delivery, recipient, invitationSubject)
	})
	req.Email = requestedEmail
	path := writeInvitation(dir, invitationFile{
		invitationRequest: req, InvitationID: invID, Origin: origin, Token: token, CreatedAt: time.Now().UTC(),
	})
	delete(d.data, key)
	d.put(key+"/published", invID)
	return path
}
