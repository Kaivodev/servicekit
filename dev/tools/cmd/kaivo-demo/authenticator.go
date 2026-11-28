package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"image/png"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/Kaivodev/servicekit/approval"
	"github.com/fxamacker/cbor/v2"
)

const rp = "admin.aipay.test"
const adminOrigin = "https://" + rp

type credential struct {
	Key, ID []byte
	Count   uint32
}

func (d *driver) credential(name string) credential {
	var a credential
	if !d.read("authenticator/"+name, &a) {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		check(e)
		a.Key, e = x509.MarshalECPrivateKey(k)
		check(e)
		a.ID = random(32)
		d.put("authenticator/"+name, a)
	}
	return a
}
func (a credential) cose() []byte {
	k, e := x509.ParseECPrivateKey(a.Key)
	check(e)
	p, e := k.PublicKey.Bytes()
	check(e)
	enc, e := cbor.CanonicalEncOptions().EncMode()
	check(e)
	b, e := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: p[1:33], -3: p[33:]})
	check(e)
	return b
}
func clientData(kind string, challenge []byte) []byte {
	require(len(challenge) > 0, "empty WebAuthn challenge")
	return encoded(object{"type": kind, "origin": adminOrigin, "challenge": b64.EncodeToString(challenge), "crossOrigin": false})
}
func (a credential) authData(flags byte) []byte {
	h := sha256.Sum256([]byte(rp))
	return binary.BigEndian.AppendUint32(append(h[:], flags), a.Count)
}
func options(field string) object { var m object; decode(raw(field), &m); return m }
func (a credential) register(o object) object {
	require(str(obj(o["rp"]), "id") == rp, "registration RP mismatch")
	ok := false
	params, _ := o["pubKeyCredParams"].([]any)
	for _, v := range params {
		p := obj(v)
		if str(p, "type") == "public-key" && num(p, "alg") == -7 {
			ok = true
		}
	}
	require(ok, "ES256 not offered")
	data := append(a.authData(0x45), make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(a.ID)))
	data = append(data, a.ID...)
	data = append(data, a.cose()...)
	att, e := cbor.Marshal(object{"fmt": "none", "attStmt": object{}, "authData": data})
	check(e)
	return object{"credential_id": b64.EncodeToString(a.ID), "attestation_object": b64.EncodeToString(att), "transports": []string{"internal"}, "client_data_json": b64.EncodeToString(clientData("webauthn.create", raw(str(o, "challenge"))))}
}
func (d *driver) assert(name string, challenge []byte) object {
	a := d.credential(name)
	require(a.Count < math.MaxUint32, "authenticator counter exhausted")
	a.Count++
	d.put("authenticator/"+name, a)
	data := a.authData(5)
	client := clientData("webauthn.get", challenge)
	h := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(data), h[:]...))
	key, e := x509.ParseECPrivateKey(a.Key)
	check(e)
	sig, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	check(e)
	return object{"credential_id": b64.EncodeToString(a.ID), "client_data_json": b64.EncodeToString(client), "authenticator_data": b64.EncodeToString(data), "signature": b64.EncodeToString(sig)}
}
func appendField(b []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
}
func emergencyChallenge(owner, user, key, version string, control uint64, reason string) [32]byte {
	require(owner == "payment" || owner == "reconciliation", "unknown approval owner")
	var b []byte
	for _, s := range []string{"aipay." + owner + ".plugin.emergency_disable.v1", user, key, version} {
		b = appendField(b, s)
	}
	b = binary.BigEndian.AppendUint64(b, control)
	return approval.Digest(appendField(b, reason))
}
func totpStep(at time.Time) int64 { return at.Unix() / 30 }

func totp(secret string, at time.Time) string {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	check(e)
	h := hmac.New(sha1.New, key)
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(totpStep(at))))
	sum := h.Sum(nil)
	n := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[n:])&0x7fffffff)%1000000)
}

// IAM renders a pristine Model 2 v6-L, byte-mode, mask-zero QR with four quiet modules.
// Read the same PNG visible to the browser. IAM verifies the recovered secret via the confirmation code.
func qrSecret(b []byte) string {
	im, e := png.Decode(bytes.NewReader(b))
	check(e)
	size := im.Bounds().Dx()
	require(size == im.Bounds().Dy() && size%49 == 0 && size >= 49, "unsupported enrollment QR size")
	scale := size / 49
	var words [173]byte
	index := 0
	up := true
	for right := 40; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for row := range 41 {
			y := row
			if up {
				y = 40 - row
			}
			for j := range 2 {
				x := right - j
				if x == 6 || y == 6 || x <= 8 && y <= 8 || x >= 33 && y <= 8 || x <= 8 && y >= 33 || x >= 32 && x <= 36 && y >= 32 && y <= 36 {
					continue
				}
				r, _, _, _ := im.At((x+4)*scale+scale/2, (y+4)*scale+scale/2).RGBA()
				if (r < 0x8000) != ((x+y)%2 == 0) {
					words[index/8] |= 1 << uint(7-index%8)
				}
				index++
			}
		}
		up = !up
	}
	require(index == 1383, "invalid QR layout")
	var data [136]byte
	for i := range 68 {
		data[i], data[i+68] = words[2*i], words[2*i+1]
	}
	n := int(data[0]&15)<<4 | int(data[1]>>4)
	require(data[0]>>4 == 4 && n > 0 && n <= 134, "unsupported enrollment QR payload")
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = data[i+1]<<4 | data[i+2]>>4
	}
	u, e := url.Parse(string(payload))
	require(e == nil && u.Scheme == "otpauth" && u.Host == "totp" && u.Query().Get("issuer") == "Kaivo", "invalid enrollment URI")
	s := u.Query().Get("secret")
	require(strings.TrimSpace(s) == s && s != "", "missing enrollment secret")
	return s
}
