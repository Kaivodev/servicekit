package authz

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aipay-dev/servicekit/config"
	"github.com/aipay-dev/servicekit/signing"
)

// IAM identity assertions are compact JWS (RFC 7515) signed with ES256 by a
// non-exportable IAM key. The header is exactly {"alg":"ES256","kid":...,
// "typ":"aipay-assertion+jwt"}; the claims are Claims. Each receiver verifies
// them with its own deployment-configured registry of IAM public keys.
const (
	MetadataKey   = "x-aipay-assertion"
	AssertionType = "aipay-assertion+jwt"
	// MaxLifetime is the longest exp - iat any receiver accepts.
	MaxLifetime = 60 * time.Second
	// MaxLeeway bounds the configurable clock skew tolerance.
	MaxLeeway = 30 * time.Second
	// AMRMultiFactor in amr marks a completed multi-factor authentication
	// (RFC 8176 "mfa").
	AMRMultiFactor = "mfa"
	maxTokenBytes  = 8192
)

// Principal types carried in principal_type.
const (
	PrincipalUser                = "user"
	PrincipalMerchantApplication = "merchant_application"
	PrincipalService             = "service"
)

// Claims is the JSON claim set. Times are NumericDate seconds; aud is always
// written as an array and read as a string or an array.
type Claims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	PrincipalType string   `json:"principal_type"`
	ActingScope   Scope    `json:"acting_scope"`
	Audience      Audience `json:"aud"`
	Permission    string   `json:"permission"`
	// Base64url (no padding) SHA-256 request fingerprint computed by IAM.
	RequestFingerprint string   `json:"request_fingerprint"`
	AMR                []string `json:"amr"`
	AuthTime           int64    `json:"auth_time,omitempty"`
	IssuedAt           int64    `json:"iat"`
	NotBefore          int64    `json:"nbf,omitempty"`
	ExpiresAt          int64    `json:"exp"`
	ID                 string   `json:"jti"`
}

type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = many
	return nil
}

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	jtiPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	amrPattern   = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	errMalformed = errors.New("malformed identity assertion")
)

// validate checks the claim shapes independent of the clock and receiver.
func (c Claims) validate() error {
	fingerprint, err := base64.RawURLEncoding.Strict().DecodeString(c.RequestFingerprint)
	switch {
	case c.Issuer == "" || !idPattern.MatchString(c.Subject) || !jtiPattern.MatchString(c.ID):
		return errMalformed
	case c.PrincipalType != PrincipalUser && c.PrincipalType != PrincipalMerchantApplication && c.PrincipalType != PrincipalService:
		return errMalformed
	case !c.ActingScope.valid() || !permissionPattern.MatchString(c.Permission):
		return errMalformed
	case c.PrincipalType == PrincipalMerchantApplication && c.ActingScope.Type != ScopeApplication:
		// Application credentials always act in their application scope.
		return errMalformed
	case err != nil || len(fingerprint) != sha256.Size:
		return errMalformed
	case len(c.Audience) == 0 || len(c.AMR) == 0:
		return errMalformed
	case c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > MaxLifetime:
		return errors.New("identity assertion lifetime is invalid")
	case c.AuthTime < 0 || c.AuthTime > c.IssuedAt || c.NotBefore < 0:
		return errMalformed
	}
	for _, audience := range c.Audience {
		if !config.ValidService(audience) {
			return errMalformed
		}
	}
	seen := map[string]bool{}
	for _, method := range c.AMR {
		if !amrPattern.MatchString(method) || seen[method] {
			return errMalformed
		}
		seen[method] = true
	}
	return nil
}

// Assertion is a verified, read-only view of the claims. Accessors return
// copies; nothing a handler does changes what later checks see.
type Assertion struct {
	claims      Claims
	keyID       string
	fingerprint []byte
}

func (a *Assertion) Subject() string            { return a.claims.Subject }
func (a *Assertion) PrincipalType() string      { return a.claims.PrincipalType }
func (a *Assertion) ActingScope() Scope         { return a.claims.ActingScope }
func (a *Assertion) Permission() string         { return a.claims.Permission }
func (a *Assertion) ID() string                 { return a.claims.ID }
func (a *Assertion) KeyID() string              { return a.keyID }
func (a *Assertion) Audience() []string         { return slices.Clone(a.claims.Audience) }
func (a *Assertion) AMR() []string              { return slices.Clone(a.claims.AMR) }
func (a *Assertion) MFA() bool                  { return slices.Contains(a.claims.AMR, AMRMultiFactor) }
func (a *Assertion) IssuedAt() time.Time        { return time.Unix(a.claims.IssuedAt, 0).UTC() }
func (a *Assertion) ExpiresAt() time.Time       { return time.Unix(a.claims.ExpiresAt, 0).UTC() }
func (a *Assertion) RequestFingerprint() []byte { return bytes.Clone(a.fingerprint) }

// AuthTime is zero when the assertion carries no auth_time.
func (a *Assertion) AuthTime() time.Time {
	if a.claims.AuthTime == 0 {
		return time.Time{}
	}
	return time.Unix(a.claims.AuthTime, 0).UTC()
}

type VerifierConfig struct {
	// Issuer is the expected iss, e.g. "iam".
	Issuer string
	// Audience is the receiving service; aud must contain it.
	Audience string
	// Keys is the IAM public key registry (kid → key).
	Keys signing.PublicKeys
	// Leeway tolerates clock skew on iat, nbf, exp and auth_time; at most 30s.
	Leeway time.Duration
	Now    func() time.Time
}

// LoadVerifierConfig reads AIPAY_IAM_ASSERTION_ISSUER (default iam),
// AIPAY_IAM_ASSERTION_KEYS_FILE (a JSON Web Key Set of IAM public keys) and
// AIPAY_IAM_ASSERTION_LEEWAY (default 5s).
func LoadVerifierConfig(service string, get func(string) string) (VerifierConfig, error) {
	if get == nil {
		return VerifierConfig{}, errors.New("assertion verifier configuration requires a reader")
	}
	cfg := VerifierConfig{Issuer: get("AIPAY_IAM_ASSERTION_ISSUER"), Audience: service, Leeway: 5 * time.Second, Now: time.Now}
	if cfg.Issuer == "" {
		cfg.Issuer = "iam"
	}
	if raw := get("AIPAY_IAM_ASSERTION_LEEWAY"); raw != "" {
		leeway, err := time.ParseDuration(raw)
		if err != nil {
			return VerifierConfig{}, errors.New("AIPAY_IAM_ASSERTION_LEEWAY must be a duration")
		}
		cfg.Leeway = leeway
	}
	path := get("AIPAY_IAM_ASSERTION_KEYS_FILE")
	if path == "" {
		return VerifierConfig{}, errors.New("AIPAY_IAM_ASSERTION_KEYS_FILE is required")
	}
	keys, err := signing.LoadJWKS(path)
	if err != nil {
		return VerifierConfig{}, err
	}
	cfg.Keys = keys
	return cfg, nil
}

type AssertionVerifier struct{ cfg VerifierConfig }

func NewAssertionVerifier(cfg VerifierConfig) (*AssertionVerifier, error) {
	if cfg.Issuer == "" || !config.ValidService(cfg.Audience) || cfg.Keys.Len() == 0 || cfg.Leeway < 0 || cfg.Leeway > MaxLeeway {
		return nil, errors.New("assertion verifier requires an issuer, audience, IAM keys and a leeway of at most 30s")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &AssertionVerifier{cfg: cfg}, nil
}

// Denial explains a rejected call for logs; Reason is a stable identifier and
// never contains credential material.
type Denial struct{ Reason string }

func (d *Denial) Error() string { return "identity assertion rejected: " + d.Reason }

func deny(reason string) error { return &Denial{Reason: reason} }

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// decodeObject parses a JSON object, rejecting duplicate top-level members and
// returning the member names.
func decodeObject(data []byte, target any) (map[string]bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errMalformed
	}
	names := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || names[name] {
			return nil, errMalformed
		}
		names[name] = true
		var skip json.RawMessage
		if err = decoder.Decode(&skip); err != nil {
			return nil, errMalformed
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errMalformed
	}
	if _, err := decoder.Token(); err == nil {
		return nil, errMalformed
	}
	if err := json.Unmarshal(data, target); err != nil {
		return nil, errMalformed
	}
	return names, nil
}

// Verify checks signature, header, issuer, audience, lifetime and claim
// shapes. Permission, MFA, recency and single use depend on the method rule
// and are checked by the Authorizer.
func (v *AssertionVerifier) Verify(token string) (*Assertion, error) {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return nil, deny("assertion_malformed")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, deny("assertion_malformed")
	}
	decode := base64.RawURLEncoding.Strict()
	rawHeader, errHeader := decode.DecodeString(parts[0])
	rawClaims, errClaims := decode.DecodeString(parts[1])
	signature, errSignature := decode.DecodeString(parts[2])
	if errHeader != nil || errClaims != nil || errSignature != nil || len(signature) != 64 {
		return nil, deny("assertion_malformed")
	}
	var h header
	names, err := decodeObject(rawHeader, &h)
	// Only these members: no crit, jku, jwk, x5u or embedded keys.
	if err != nil || len(names) != 3 || !names["alg"] || !names["kid"] || !names["typ"] || h.Alg != "ES256" || h.Typ != AssertionType {
		return nil, deny("assertion_header")
	}
	key, ok := v.cfg.Keys.Lookup(h.Kid)
	if !ok {
		return nil, deny("assertion_unknown_key")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, deny("assertion_signature")
	}
	var claims Claims
	if _, err = decodeObject(rawClaims, &claims); err != nil {
		return nil, deny("assertion_malformed")
	}
	if err = claims.validate(); err != nil {
		return nil, deny("assertion_claims")
	}
	if claims.Issuer != v.cfg.Issuer {
		return nil, deny("assertion_issuer")
	}
	if !slices.Contains(claims.Audience, v.cfg.Audience) {
		return nil, deny("assertion_audience")
	}
	now, leeway := v.cfg.Now(), v.cfg.Leeway
	switch {
	case time.Unix(claims.IssuedAt, 0).After(now.Add(leeway)), claims.NotBefore != 0 && time.Unix(claims.NotBefore, 0).After(now.Add(leeway)):
		return nil, deny("assertion_not_yet_valid")
	case !now.Before(time.Unix(claims.ExpiresAt, 0).Add(leeway)):
		return nil, deny("assertion_expired")
	}
	fingerprint, _ := decode.DecodeString(claims.RequestFingerprint)
	return &Assertion{claims: claims, keyID: h.Kid, fingerprint: fingerprint}, nil
}

// SignAssertion issues a compact JWS for claims with signer, converting its
// DER signature to the fixed-size JWS form. IAM uses it to issue assertions;
// tests use it with a development signer.
func SignAssertion(ctx context.Context, signer signing.Signer, claims Claims) (string, error) {
	if err := claims.validate(); err != nil {
		return "", err
	}
	headerJSON, err := json.Marshal(header{Alg: "ES256", Kid: signer.KeyID(), Typ: AssertionType})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encode := base64.RawURLEncoding
	input := encode.EncodeToString(headerJSON) + "." + encode.EncodeToString(claimsJSON)
	der, err := signer.Sign(ctx, []byte(input))
	if err != nil {
		return "", err
	}
	var parsed struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &parsed); err != nil || len(rest) != 0 {
		return "", errors.New("signer returned an invalid DER signature")
	}
	raw := make([]byte, 64)
	parsed.R.FillBytes(raw[:32])
	parsed.S.FillBytes(raw[32:])
	return input + "." + encode.EncodeToString(raw), nil
}
