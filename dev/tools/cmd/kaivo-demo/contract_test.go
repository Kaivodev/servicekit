package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The standalone module can run without siblings. On a demo checkout, check the
// browser commands against the same Swagger document the verification host uses.
func TestBackendRequestContracts(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "backend", "kaivo.json")
	raw, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		t.Skip("backend checkout unavailable")
	}
	if e != nil {
		t.Fatal(e)
	}
	type schema struct {
		Ref        string `json:"$ref"`
		Properties map[string]json.RawMessage
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				In     string
				Schema schema
			}
		}
		Definitions map[string]schema
	}
	if e := json.Unmarshal(raw, &spec); e != nil {
		t.Fatal(e)
	}
	check := func(path, fields string) {
		t.Helper()
		op, ok := spec.Paths["/api/v1/"+path]["post"]
		if !ok {
			t.Error("missing POST", path)
			return
		}
		for _, p := range op.Parameters {
			if p.In == "body" {
				s, ok := spec.Definitions[strings.TrimPrefix(p.Schema.Ref, "#/definitions/")]
				if !ok {
					t.Error(path, "missing body definition")
					return
				}
				for _, k := range strings.Fields(fields) {
					if _, ok := s.Properties[k]; !ok {
						t.Error(path, "missing request field", k)
					}
				}
				return
			}
		}
		t.Error(path, "missing request body")
	}
	for _, entry := range []string{"platform", "seller"} {
		for p, fields := range map[string]string{"auth/login": "email password", "auth/invitations/inspect": "token", "auth/invitations/accept": "token new_user"} {
			check(entry+"/"+p, fields)
		}
	}
	for p, fields := range map[string]string{
		"platform/auth/password/reset": "token new_password", "platform/auth/challenges/{id}/verify": "assertion", "seller/auth/challenges/{id}/verify": "method code",
		"platform/me/webauthn/enrollments": "name", "platform/me/webauthn/enrollments/{id}/confirm": "credential_id client_data_json attestation_object transports",
		"seller/me/mfa/totp/enrollments": "", "seller/me/mfa/totp/confirm": "enrollment_id code", "platform/invitations/platform-staff": "email platform_roles", "platform/invitations/sellers": "email seller_account_id", "platform/invitations/{id}/approvals": "expected_version", "platform/plugins": "manifest_json plugin_wasm fixtures package_sha256", "platform/verification/plugins": "manifest_json plugin_wasm fixtures package_sha256", "platform/pricing-drafts": "configuration effective_at", "platform/pricing-versions/requests": "draft_id expected_revision expected_control_version", "platform/plugin-enables/requests": "channel_account_id expected_control_version plugin_version_id", "platform/verification/credentials": "channel_account_id credentials_json", "platform/verification/enables/requests": "verification_account_id expected_control_version plugin_version_id", "platform/payment-accesses/{id}/reviews": "expected_control_version expected_revision_version materials_sha256 decision reason evidence_sha256", "platform/disputes": "order_id escrow_reservation_id expected_control_version reason evidence", "platform/disputes/{id}/rulings": "expected_control_version outcome reason", "seller/accounts/{seller_account_id}/disputes/{id}/evidence": "expected_evidence_version evidence",
	} {
		check(p, fields)
	}
	for _, p := range []string{"channel-accounts", "payment-methods", "risk-policies", "verification/accounts"} {
		check("platform/"+p+"/requests", "change")
	}
	for _, p := range []string{"channel-accounts", "payment-methods", "risk-policies", "verification/accounts", "plugins", "plugin-enables", "pricing-versions", "verification/plugins", "verification/enables", "dispute-rulings"} {
		check("platform/"+p+"/approvals/{id}/assertions", "assertion")
	}
	for _, path := range []string{"/mapi.php", "/api/pay/create", "/api/pay/refund", "/api/pay/close", "/api/pay/refundquery", "/telegram/webhook", "/totp/enroll/{token}"} {
		if _, ok := spec.Paths[path]["post"]; !ok {
			t.Error("missing public POST", path)
		}
	}
}
