package authz

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
)

func TestTelegramBotAssertions(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name     string
		amr      []string
		bot      TelegramBot
		entry    WebEntry
		merchant bool
		upstream bool
		guardErr error
	}{
		{name: "merchant bot", amr: []string{"telegram"}, bot: TelegramBotMerchant, merchant: true},
		{name: "upstream bot", amr: []string{"pwd", "telegram"}, bot: TelegramBotUpstream, upstream: true, guardErr: ErrUpstreamBotAssertion},
		{name: "legacy Telegram", amr: []string{"pwd", "telegram"}, merchant: true},
		{name: "upstream web portal", amr: []string{"pwd"}, entry: WebEntryUpstreamPortal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := f.token(t, func(c *Claims) {
				c.Permission = "settlement.record.read"
				c.AMR, c.TelegramBot, c.WebEntry = tc.amr, tc.bot, tc.entry
			})
			call, _, err := f.call("Read", "backend", token)
			if err != nil {
				t.Fatal(err)
			}
			a, ok := call.Assertion()
			if !ok {
				t.Fatal("missing verified assertion")
			}
			if got := a.TelegramBot(); got != tc.bot {
				t.Errorf("TelegramBot() = %q, want %q", got, tc.bot)
			}
			if got := a.MerchantBot(); got != tc.merchant {
				t.Errorf("MerchantBot() = %t, want %t", got, tc.merchant)
			}
			if got := a.UpstreamBot(); got != tc.upstream {
				t.Errorf("UpstreamBot() = %t, want %t", got, tc.upstream)
			}
			if got := DenyUpstreamBot(a); !errors.Is(got, tc.guardErr) {
				t.Errorf("DenyUpstreamBot(a) = %v, want %v", got, tc.guardErr)
			}
			if got := call.DenyUpstreamBot(); !errors.Is(got, tc.guardErr) {
				t.Errorf("call.DenyUpstreamBot() = %v, want %v", got, tc.guardErr)
			}
		})
	}
}

func TestDenyUpstreamBotWithoutAssertion(t *testing.T) {
	if err := DenyUpstreamBot(nil); err != nil {
		t.Errorf("DenyUpstreamBot(nil) = %v, want nil", err)
	}
	call, _, err := newFixture(t).call("Read", "ledger")
	if err != nil {
		t.Fatal(err)
	}
	if err := call.DenyUpstreamBot(); err != nil {
		t.Errorf("service call guard = %v, want nil", err)
	}
}

func TestInvalidTelegramBotClaims(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name  string
		bot   TelegramBot
		amr   []string
		entry WebEntry
	}{
		{name: "unknown bot", bot: "seller", amr: []string{"telegram"}},
		{name: "missing Telegram method", bot: TelegramBotUpstream, amr: []string{"pwd"}},
		{name: "bot with web entry", bot: TelegramBotMerchant, amr: []string{"telegram"}, entry: WebEntryPlatformAdmin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			claims.TelegramBot, claims.AMR, claims.WebEntry = tc.bot, tc.amr, tc.entry
			if _, err := SignAssertion(context.Background(), f.iam, claims); !errors.Is(err, errMalformed) {
				t.Errorf("SignAssertion error = %v, want malformed assertion", err)
			}
			body, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = f.call("Read", "backend", signRaw(t, f.iam, string(body)))
			expect(t, err, codes.Unauthenticated)
		})
	}
}

func TestTelegramBotRejectsInvalidJSONValues(t *testing.T) {
	f := newFixture(t)
	claims := validClaims()
	claims.AMR = []string{"telegram"}
	for name, value := range map[string]string{"empty": `""`, "null": "null", "nonstring": "true"} {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(struct {
				Claims
				Bot json.RawMessage `json:"telegram_bot"`
			}{claims, json.RawMessage(value)})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = f.call("Read", "backend", signRaw(t, f.iam, string(body)))
			expect(t, err, codes.Unauthenticated)
		})
	}
}
