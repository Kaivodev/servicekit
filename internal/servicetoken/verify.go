package servicetoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"github.com/Kaivodev/servicekit/config"
)

func signed(key crypto.PublicKey, alg, message string, signature []byte) bool {
	digest := sha256.Sum256([]byte(message))
	switch public := key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" && rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) == nil
	case *ecdsa.PublicKey:
		return alg == "ES256" && len(signature) == 64 && ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	default:
		return false
	}
}

func audienceMatches(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []*string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	match := false
	for _, audience := range many {
		if audience == nil {
			return false
		}
		match = match || *audience == want
	}
	return match
}

// Decode exact, case-sensitive JWT member names. Errors never contain token bytes.
func (t *Transport) verify(token string, now time.Time) (string, string) {
	if len(token) > maxTokenBytes {
		return "", "token_malformed"
	}
	header, rest, ok := strings.Cut(token, ".")
	payload, sig, last := strings.Cut(rest, ".")
	if !ok || !last || strings.Contains(sig, ".") || header == "" || payload == "" || sig == "" {
		return "", "token_malformed"
	}
	h, errH := rawURL.DecodeString(header)
	p, errP := rawURL.DecodeString(payload)
	signature, errS := rawURL.DecodeString(sig)
	var hdr map[string]json.RawMessage
	if errH != nil || errP != nil || errS != nil || json.Unmarshal(h, &hdr) != nil || hdr["crit"] != nil || hdr["b64"] != nil {
		return "", "token_malformed"
	}
	var alg, kid string
	if json.Unmarshal(hdr["alg"], &alg) != nil || json.Unmarshal(hdr["kid"], &kid) != nil || kid == "" || (alg != "ES256" && alg != "RS256") {
		return "", "token_malformed"
	}
	if !signed(t.keys.Load().keys[kid], alg, header+"."+payload, signature) {
		return "", "token_signature"
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(p, &claims) != nil || claims == nil {
		return "", "token_malformed"
	}
	var issuer, sub string
	if json.Unmarshal(claims["iss"], &issuer) != nil || issuer != t.options.Issuer {
		return "", "token_issuer"
	}
	if !audienceMatches(claims["aud"], "kaivo:"+t.service) {
		return "", "token_audience"
	}
	var exp, nbf, iat *int64
	if json.Unmarshal(claims["exp"], &exp) != nil || json.Unmarshal(claims["nbf"], &nbf) != nil || json.Unmarshal(claims["iat"], &iat) != nil || exp == nil || nbf == nil || iat == nil {
		return "", "token_malformed"
	}
	const skew = 30 * time.Second
	if *exp <= now.Add(-skew).Unix() || *nbf > now.Add(skew).Unix() || *iat > now.Add(skew).Unix() || *exp <= *iat || *exp <= *nbf {
		return "", "token_expired"
	}
	if json.Unmarshal(claims["sub"], &sub) != nil {
		return "", "token_subject"
	}
	parts := strings.Split(sub, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || !config.ValidService(parts[3]) {
		return "", "token_subject"
	}
	ns, sa := parts[2], parts[3]
	if raw := claims["kubernetes.io"]; raw != nil {
		var kube map[string]json.RawMessage
		var account map[string]json.RawMessage
		var name, namespace string
		if json.Unmarshal(raw, &kube) != nil || json.Unmarshal(kube["namespace"], &namespace) != nil || namespace != ns ||
			json.Unmarshal(kube["serviceaccount"], &account) != nil || json.Unmarshal(account["name"], &name) != nil || name != sa {
			return "", "token_subject"
		}
	}
	if t.options.ServiceNamespaces[sa] != ns {
		return "", "token_namespace"
	}
	return sa, ""
}
