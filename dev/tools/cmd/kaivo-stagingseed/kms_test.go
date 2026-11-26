package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/servicekit/signing"
)

func testSpec() kmsSpec {
	const prefix = "projects/test/locations/test/keyRings/"
	const version = "/cryptoKeyVersions/1"
	const iam = prefix + "business/cryptoKeys/iam-"
	const ledger = prefix + "ledger/cryptoKeys/ledger-"
	return kmsSpec{specFormat, map[string]serviceSpec{
		"iam": {
			Signing: []signingSpec{
				{"iam-event-v1", iam + "events" + version, "iam.jwks", ""},
				{"iam-assertion-v1", iam + "assertion" + version, "iam-assertion.jwks", ""},
			},
			Sealing: []sealingSpec{
				{"data", iam + "data", "data-keys.json"},
				{"epay", iam + "epay", "epay-keys.json"},
			},
		},
		"ledger": {Signing: []signingSpec{
			{"ledger-event-v1", ledger + "events" + version, "ledger.jwks", ""},
			{"ledger-checkpoint-v1", ledger + "checkpoint" + version, "ledger.jwks", ""},
			{"ledger-report-v1", ledger + "report" + version, "ledger-report.jwks", "ledger-report-public.pem"},
		}},
	}}
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestKMSSpec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	original := jsonFile(testSpec())
	writeTestFile(t, path, original)
	if _, err := readKMSSpec(path); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"format", specFormat, "v0"},
		{"service", `"iam":`, `"other":`},
		{"unknown top member", `"format":`, `"secret-in-field":1,"format":`},
		{"unknown service member", `"signing":`, `"signer":[],"signing":`},
		{"unknown signer member", `"kid":`, `"private":"secret-in-input","kid":`},
		{"unknown sealing member", `"purpose":`, `"raw":"secret-in-input","purpose":`},
		{"case", `"registry":`, `"Registry":`},
		{"duplicate member", `"kid":`, `"kid":"first","kid":`},
		{"invalid kid", "iam-event-v1", "bad!"},
		{"dev kid", "iam-event-v1", "iam-dev"},
		{"report dev kid", "iam-event-v1", "ledger-report-dev"},
		{"another dev kid", "iam-event-v1", "payment-dev"},
		{"global duplicate", "iam-event-v1", "ledger-event-v1"},
		{"unversioned signer", "/cryptoKeyVersions/1", ""},
		{"versioned kek", `iam-data"`, `iam-data/cryptoKeyVersions/1"`},
		{"bad resource", "/keyRings/", "/invalid/"},
		{"wrong registry", "iam.jwks", "payment.jwks"},
		{"iam using ledger registry", "iam.jwks", "ledger-report.jwks"},
		{"ledger using iam registry", "ledger.jwks", "iam-assertion.jwks"},
		{"pem name", "ledger-report-public.pem", "other.pem"},
		{"empty pem", "ledger-report-public.pem", ""},
		{"null pem", `"ledger-report-public.pem"`, "null"},
		{"wrong pem registry", "ledger-report.jwks", "ledger.jwks"},
		{"duplicate pem", `"registry":"ledger.jwks"`, `"registry":"ledger-report.jwks","pem":"ledger-report-public.pem"`},
		{"uppercase purpose", `"purpose":"data"`, `"purpose":"Data"`},
		{"digit in purpose", `"purpose":"data"`, `"purpose":"data1"`},
		{"duplicate purpose", `"purpose":"data"`, `"purpose":"epay"`},
		{"duplicate file", "epay-keys.json", "data-keys.json"},
		{"unknown file", "data-keys.json", "../data.json"},
		{"ledger sealing", `"ledger":{"signing"`, `"ledger":{"sealing":[{"purpose":"x","kek":"projects/p/locations/r/keyRings/r/cryptoKeys/k","file":"data-keys.json"}],"signing"`},
		{"trailing JSON", "}\n", "}{}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.Replace(original, tc.from, tc.to, 1)
			if changed == original {
				t.Fatal("invalid test fixture")
			}
			writeTestFile(t, path, changed)
			if _, err := readKMSSpec(path); err == nil || strings.Contains(err.Error(), "secret-in-") {
				t.Fatal("expected safe spec validation error")
			}
		})
	}
}

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeKMS struct {
	public         map[string]any
	aadByKEK       map[string]string
	plainByKEK     map[string][]byte
	decrypts       []string
	impersonations int
	failDecrypt    bool
}

// Exercise ADC and the real REST adapter through the CLI, without a listener.
func setupKMSJob(t *testing.T, dir string) *fakeKMS {
	t.Helper()
	spec := testSpec()
	path := filepath.Join(dir, "keys.json")
	writeTestFile(t, path, jsonFile(spec))
	t.Setenv("KAIVO_KMS_SPEC_FILE", path)
	token := filepath.Join(dir, "projected")
	writeTestFile(t, token, "test-subject")
	adc := filepath.Join(dir, "adc.json")
	writeTestFile(t, adc, jsonFile(map[string]any{
		"type": "external_account", "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/test/providers/test",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": "https://sts.test/token",
		"service_account_impersonation_url": "https://iam.test/impersonate", "credential_source": fields{"file": token},
	}))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", adc)
	f := &fakeKMS{public: map[string]any{}, aadByKEK: map[string]string{}, plainByKEK: map[string][]byte{}}
	for svc, entries := range spec.Services {
		for _, signing := range entries.Signing {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			f.public[signing.Key] = &key.PublicKey
		}
		for _, sealing := range entries.Sealing {
			f.aadByKEK[sealing.KEK] = "kaivo:" + svc + ":" + sealing.Purpose + ":v1"
		}
	}
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	http.DefaultTransport = testTransport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Host {
		case "sts.test":
			if r.FormValue("subject_token") != "test-subject" {
				t.Error("incorrect projected token")
			}
			fmt.Fprint(w, `{"access_token":"test-sts","token_type":"Bearer","expires_in":3600}`)
		case "iam.test":
			f.impersonations++
			fmt.Fprint(w, jsonFile(fields{"accessToken": "secret-in-token", "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}))
		case "cloudkms.googleapis.com":
			if r.Header.Get("Authorization") != "Bearer secret-in-token" {
				t.Error("missing impersonated identity")
			}
			f.serve(t, w, r)
		default:
			t.Error("unexpected HTTP destination")
			w.WriteHeader(http.StatusForbidden)
		}
		return w.Result(), nil
	})
	return f
}

func testCRC(data []byte) string {
	return fmt.Sprint(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
}

func (f *fakeKMS) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if key, ok := strings.CutSuffix(path, "/publicKey"); ok {
		der, err := x509.MarshalPKIXPublicKey(f.public[key])
		if err != nil {
			t.Error("unexpected signing resource")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		algorithm := "EC_SIGN_P256_SHA256"
		if _, rsaKey := f.public[key].(*rsa.PublicKey); rsaKey {
			algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		fmt.Fprint(w, jsonFile(fields{"name": key, "algorithm": algorithm, "pem": string(data), "pemCrc32c": testCRC(data)}))
		return
	}
	var req struct {
		Plaintext, Ciphertext, AdditionalAuthenticatedData []byte
	}
	key, op, _ := strings.Cut(path, ":")
	aad, ok := f.aadByKEK[key]
	if !ok || json.NewDecoder(r.Body).Decode(&req) != nil || string(req.AdditionalAuthenticatedData) != aad {
		t.Error("wrong KEK, request or service/purpose/version binding")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch op {
	case "encrypt":
		if len(req.Plaintext) != 32 {
			t.Error("wrong data key size")
		}
		f.plainByKEK[key] = req.Plaintext
		opaque := sha256.Sum256(req.Plaintext)
		fmt.Fprint(w, jsonFile(map[string]any{"name": key + "/cryptoKeyVersions/1", "ciphertext": opaque[:],
			"ciphertextCrc32c": testCRC(opaque[:]), "verifiedPlaintextCrc32c": true, "verifiedAdditionalAuthenticatedDataCrc32c": true}))
	case "decrypt":
		f.decrypts = append(f.decrypts, key)
		plain := f.plainByKEK[key]
		opaque := sha256.Sum256(plain)
		if f.failDecrypt || !bytes.Equal(req.Ciphertext, opaque[:]) {
			http.Error(w, "secret-in-kms-response", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, jsonFile(map[string]any{"plaintext": plain, "plaintextCrc32c": testCRC(plain)}))
	default:
		t.Error("unexpected KMS operation")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func jobOutput(t *testing.T, svc string) string {
	t.Helper()
	var out, diag bytes.Buffer
	if cli([]string{"kms-export", svc}, &out, &diag, testTime) != 0 || diag.Len() != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("expected a single JSON document: %s", diag.String())
	}
	return out.String()
}

func TestKMSExport(t *testing.T) {
	dir := t.TempDir()
	job := setupKMSJob(t, dir)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	spec := testSpec()
	for _, svc := range []string{"iam", "ledger"} {
		data := jobOutput(t, svc)
		var want bytes.Buffer
		fmt.Fprintf(&want, `{"format":"kaivo.kms-export.v1","service":%q,"public":[`, svc)
		for i, s := range spec.Services[svc].Signing {
			if i != 0 {
				want.WriteByte(',')
			}
			fmt.Fprintf(&want, `{"kid":%q,"key":%q,"registry":%q,`, s.KID, s.Key, s.Registry)
			if s.PEM != "" {
				fmt.Fprintf(&want, `"pem":%q,`, s.PEM)
			}
			jwks, err := signing.MarshalJWKS(publicKeys{s.KID: job.public[s.Key].(*ecdsa.PublicKey)})
			if err != nil {
				t.Fatal(err)
			}
			want.WriteString(`"jwks":`)
			if err := json.Compact(&want, jwks); err != nil {
				t.Fatal(err)
			}
			want.WriteByte('}')
		}
		want.WriteString(`],"sealing":[`)
		for i, s := range spec.Services[svc].Sealing {
			if i != 0 {
				want.WriteByte(',')
			}
			opaque := sha256.Sum256(job.plainByKEK[s.KEK])
			content := fmt.Sprintf(`{"format":"kaivo.sealing.v1","service":%q,"purpose":%q,"current":1,"keys":[{"version":1,"wrapped":%q}]}`,
				svc, s.Purpose, base64.StdEncoding.EncodeToString(opaque[:]))
			fmt.Fprintf(&want, `{"purpose":%q,"kek":%q,"file":%q,"content":%q}`, s.Purpose, s.KEK, s.File, content)
			if strings.Contains(data, base64.StdEncoding.EncodeToString(job.plainByKEK[s.KEK])) {
				t.Fatal("plaintext in export")
			}
		}
		want.WriteString("]}\n")
		if data != want.String() {
			t.Fatal("unexpected export fields, order or content")
		}
	}
	entries := spec.Services["iam"].Sealing
	if job.impersonations != 2 || !slices.Equal(job.decrypts, []string{entries[0].KEK, entries[1].KEK}) {
		t.Fatal("expected one credential exchange per Job and one unwrap per file")
	}
	job.failDecrypt = true
	expectFailure(t, "kms-export", "iam")
	left, err := os.ReadDir(tmp)
	if err != nil || len(left) != 0 {
		t.Fatal("temporary wrapped file left behind")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	job.public[spec.Services["ledger"].Signing[0].Key] = &key.PublicKey
	expectFailure(t, "kms-export", "ledger")
	expectFailure(t, "kms-export", "secret-in-service")
	expectFailure(t, "kms-export")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	expectFailure(t, "kms-export", "iam")
}

func exportedDir(t *testing.T) (string, *fakeKMS) {
	t.Helper()
	dir := t.TempDir()
	job := setupKMSJob(t, dir)
	if err := os.Mkdir(filepath.Join(dir, "exports"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, svc := range []string{"iam", "ledger"} {
		writeTestFile(t, filepath.Join(dir, "exports", svc+".json"), jobOutput(t, svc))
	}
	// Offline import must work with no usable credentials.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "missing-file")
	t.Setenv("KAIVO_STAGING_KMS_DIR", dir)
	return dir, job
}

func cloneCluster(c cluster) cluster {
	clone := maps.Clone(c)
	for id, obj := range clone {
		obj.Data = maps.Clone(obj.Data)
		clone[id] = obj
	}
	return clone
}

func TestKMSBootstrapAndReplay(t *testing.T) {
	setupKubectl(t)
	dev := generate(t, nil, testTime)
	dir, job := exportedDir(t)
	fresh := generate(t, nil, testTime)
	if !reflect.DeepEqual(fresh, generate(t, fresh, testTime.Add(time.Hour))) {
		t.Fatal("fresh KMS seed changed on replay")
	}
	got := generate(t, dev, testTime)
	spec := testSpec()
	for _, tc := range []struct {
		file string
		kids []string
	}{
		{"iam.jwks", []string{"iam-dev", "iam-event-v1"}},
		{"iam-assertion.jwks", []string{"iam-assertion-v1"}},
		{"ledger.jwks", []string{"ledger-dev", "ledger-event-v1", "ledger-checkpoint-v1"}},
		{"ledger-report.jwks", []string{"ledger-report-dev", "ledger-report-v1"}},
	} {
		for _, id := range registries {
			set, err := signing.ParseJWKS([]byte(got[id].Data[tc.file]))
			if err != nil || set.Len() != len(tc.kids) {
				t.Fatal("wrong registry size", tc.file)
			}
			for _, kid := range tc.kids {
				if _, ok := set.Lookup(kid); !ok {
					t.Fatal("missing kid", kid)
				}
			}
			if got[id].Data[tc.file] != got[registries[0]].Data[tc.file] {
				t.Fatal("namespace disagreement")
			}
		}
	}
	for _, svc := range spec.Services {
		for _, entry := range svc.Signing {
			set, _ := signing.ParseJWKS([]byte(got[registries[0]].Data[entry.Registry]))
			pub, ok := set.Lookup(entry.KID)
			if !ok || !pub.Equal(job.public[entry.Key]) {
				t.Fatal("wrong KMS public key")
			}
		}
	}
	reportKey := job.public[spec.Services["ledger"].Signing[2].Key].(*ecdsa.PublicKey)
	want := cloneCluster(dev)
	for _, id := range registries {
		der := pemDER(got[id].Data[reportPEM], "PUBLIC KEY")
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil || !reportKey.Equal(pub) {
			t.Fatal("wrong report PEM")
		}
		set, _ := signing.ParseJWKS([]byte(got[id].Data[reportRegistry]))
		historical, ok := set.Lookup("ledger-report-dev")
		if !ok {
			t.Fatal("missing historical report key")
		}
		legacyPub, err := x509.ParsePKIXPublicKey(pemDER(dev[id].Data[reportPEM], "PUBLIC KEY"))
		if err != nil || !historical.Equal(legacyPub) {
			t.Fatal("wrong historical report key")
		}
		for _, name := range []string{"iam.jwks", "iam-assertion.jwks", "ledger.jwks", reportRegistry, reportPEM} {
			want[id].Data[name] = got[id].Data[name]
		}
	}
	var exp kmsExport
	if err := readKMSJSON(filepath.Join(dir, "exports", "iam.json"), &exp); err != nil {
		t.Fatal(err)
	}
	for _, s := range exp.Sealing {
		want[iamInputs].Data[s.File] = s.Content
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("unexpected changes outside KMS registries and IAM wrapped files")
	}
	if !reflect.DeepEqual(got, generate(t, got, testTime.Add(time.Hour))) {
		t.Fatal("KMS replay changed materials")
	}
	// One namespace has migrated, one is still legacy and one has only a KMS checkpoint.
	partial := cloneCluster(dev)
	partial[registries[0]] = got[registries[0]]
	checkpoint := spec.Services["ledger"].Signing[1]
	subset, err := signing.MarshalJWKS(publicKeys{checkpoint.KID: job.public[checkpoint.Key].(*ecdsa.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	partial[registries[2]].Data["ledger.jwks"] = string(subset)
	partial[registries[2]].Data["iam-assertion.jwks"] = `{"keys":[]}`
	if !reflect.DeepEqual(got, generate(t, partial, testTime)) {
		t.Fatal("partial KMS apply not recoverable")
	}

	for _, tc := range []struct {
		name   string
		change func(cluster)
	}{
		{"unknown kid alongside allowed", func(c cluster) {
			c[registries[1]].Data["ledger.jwks"] = strings.Replace(c[registries[1]].Data["ledger.jwks"], "ledger-event-v1", "other-v1", 1)
		}},
		{"unexpected dev assertion", func(c cluster) { c[registries[1]].Data["iam-assertion.jwks"] = dev[registries[1]].Data["iam.jwks"] }},
		{"ambiguous registry", func(c cluster) {
			data := c[registries[0]].Data
			data["iam.jwks"] = strings.Replace(data["iam.jwks"], `"keys":`, `"keys":[],"keys":`, 1)
		}},
		{"malformed empty set", func(c cluster) { c[registries[0]].Data["ledger.jwks"] = `{"keys":null}` }},
		{"empty development registry", func(c cluster) { c[registries[0]].Data["payment.jwks"] = `{"keys":[]}` }},
		{"same kid different key", func(c cluster) {
			c[registries[2]].Data["ledger.jwks"] = strings.Replace(string(subset), checkpoint.KID, "ledger-event-v1", 1)
		}},
		{"report PEM changed", func(c cluster) { c[registries[0]].Data[reportPEM] = dev[registries[0]].Data["platform-public.pem"] }},
		{"report PEM reverted", func(c cluster) { c[registries[2]].Data[reportPEM] = dev[registries[2]].Data[reportPEM] }},
		{"wrapped file replaced", func(c cluster) { c[iamInputs].Data["data-keys.json"] = c[iamInputs].Data["epay-keys.json"] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cloneCluster(got)
			tc.change(c)
			serve(t, c, false)
			expectFailure(t)
		})
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(dir, "adc.json"))
	replacement := jobOutput(t, "iam")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "missing-file")
	writeTestFile(t, filepath.Join(dir, "exports", "iam.json"), replacement)
	serve(t, got, false)
	expectFailure(t) // even a valid second Job result would replace the data keys
}

func TestKMSImportRejectsInvalidExports(t *testing.T) {
	setupKubectl(t)
	serve(t, nil, false)
	dir, _ := exportedDir(t)
	path := filepath.Join(dir, "exports", "iam.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := decoded[kmsExport](t, string(data))
	spec := testSpec()
	for _, tc := range []struct {
		name   string
		change func(*kmsExport)
	}{
		{"format", func(e *kmsExport) { e.Format = specFormat }},
		{"service", func(e *kmsExport) { e.Service = "ledger" }},
		{"missing signer", func(e *kmsExport) { e.Public = e.Public[:1] }},
		{"extra sealing", func(e *kmsExport) { e.Sealing = append(e.Sealing, e.Sealing[0]) }},
		{"signing order", func(e *kmsExport) { slices.Reverse(e.Public) }},
		{"kid", func(e *kmsExport) { e.Public[0].KID = "wrong" }},
		{"resource", func(e *kmsExport) { e.Public[0].Key = spec.Services["iam"].Signing[1].Key }},
		{"registry", func(e *kmsExport) { e.Public[0].Registry = "iam-assertion.jwks" }},
		{"pem", func(e *kmsExport) { e.Public[0].PEM = reportPEM }},
		{"purpose", func(e *kmsExport) { e.Sealing[0].Purpose = "epay" }},
		{"kek", func(e *kmsExport) { e.Sealing[0].KEK = e.Sealing[1].KEK }},
		{"file", func(e *kmsExport) { e.Sealing[0].File = "epay-keys.json" }},
		{"missing jwks kid", func(e *kmsExport) { e.Public[0].JWKS = original.Public[1].JWKS }},
		{"multiple keys", func(e *kmsExport) {
			first := decoded[map[string][]json.RawMessage](t, string(e.Public[0].JWKS))
			second := decoded[map[string][]json.RawMessage](t, string(e.Public[1].JWKS))
			first["keys"] = append(first["keys"], second["keys"]...)
			e.Public[0].JWKS = json.RawMessage(jsonFile(first))
		}},
		{"private jwk", func(e *kmsExport) {
			e.Public[0].JWKS = []byte(strings.Replace(string(e.Public[0].JWKS), `"kid":`, `"d":"secret-in-key","kid":`, 1))
		}},
		{"wrong curve", func(e *kmsExport) {
			e.Public[0].JWKS = []byte(strings.Replace(string(e.Public[0].JWKS), "P-256", "P-384", 1))
		}},
		{"envelope format", func(e *kmsExport) {
			e.Sealing[0].Content = strings.Replace(e.Sealing[0].Content, "kaivo.sealing.v1", "wrong", 1)
		}},
		{"envelope purpose", func(e *kmsExport) { e.Sealing[0].Content = e.Sealing[1].Content }},
		{"envelope service", func(e *kmsExport) { e.Sealing[0].Content = strings.Replace(e.Sealing[0].Content, "iam", "ledger", 1) }},
		{"envelope base64", func(e *kmsExport) {
			e.Sealing[0].Content = strings.Replace(e.Sealing[0].Content, `"wrapped":"`, `"wrapped":"!`, 1)
		}},
		{"envelope missing current", func(e *kmsExport) {
			e.Sealing[0].Content = strings.Replace(e.Sealing[0].Content, `"current":1`, `"current":2`, 1)
		}},
		{"envelope extra field", func(e *kmsExport) {
			e.Sealing[0].Content = strings.Replace(e.Sealing[0].Content, `"keys":`, `"plaintext":"secret-in-key","keys":`, 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := decoded[kmsExport](t, string(data))
			tc.change(&e)
			writeTestFile(t, path, jsonFile(e))
			expectFailure(t)
		})
	}
	writeTestFile(t, path, string(data))
	if _, err := loadKMSDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "exports", "ledger.json")); err != nil {
		t.Fatal(err)
	}
	expectFailure(t)
}
