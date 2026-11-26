// kaivo-stagingseed streams development materials to staging-bootstrap's server-side apply.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	business  = "kaivo-business"
	ledger    = "kaivo-ledger"
	recon     = "kaivo-reconciliation"
	sim       = "kaivo-sim"
	secret    = "Secret"
	configMap = "ConfigMap"
	managedBy = "app.kubernetes.io/managed-by"
	manager   = "kaivo-stagingseed"
)

func namespace(logical string) string {
	if actual := os.Getenv("AIPAY_DEMO_NS_" + strings.ToUpper(strings.TrimPrefix(logical, "kaivo-"))); actual != "" {
		return actual
	}
	return logical
}

type objectID struct{ namespace, kind, name string }

var (
	backendPrivate    = objectID{business, secret, "backend-private"}
	iamPrivate        = objectID{business, secret, "iam-private"}
	paymentPrivate    = objectID{business, secret, "payment-private"}
	ledgerPrivate     = objectID{ledger, secret, "ledger-private"}
	reconPrivate      = objectID{recon, secret, "reconciliation-private"}
	collectionPrivate = objectID{sim, secret, "collection-private"}
	fixturePrivate    = objectID{sim, secret, "demo-fixtures-private"}
	simPrivate        = objectID{sim, secret, "upstream-sim-private"}
	handoff           = objectID{recon, secret, "reconciliation-handoff"}
	bootstrapDataset  = objectID{sim, configMap, "deposit-dataset"}
	backendInputs     = objectID{business, configMap, "backend-inputs"}
	iamInputs         = objectID{business, configMap, "iam-inputs"}
	paymentInputs     = objectID{business, configMap, "payment-inputs"}
	notifierInputs    = objectID{business, configMap, "notifier-inputs"}
	ledgerInputs      = objectID{ledger, configMap, "ledger-inputs"}
	reconInputs       = objectID{recon, configMap, "reconciliation-inputs"}
	registries        = []objectID{
		{business, configMap, "kaivo-signing-public"},
		{ledger, configMap, "kaivo-signing-public"},
		{recon, configMap, "kaivo-signing-public"},
	}
	// Publish private sources before the derived registries. Every applied prefix is recoverable.
	allObjects = append([]objectID{backendPrivate, iamPrivate, paymentPrivate, ledgerPrivate, reconPrivate,
		simPrivate, collectionPrivate, fixturePrivate, bootstrapDataset, handoff, backendInputs, iamInputs, notifierInputs, ledgerInputs, reconInputs, paymentInputs}, registries...)
	marketObjects = []objectID{ledgerInputs, reconInputs, paymentInputs}
)

type metadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
}

type manifest struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metadata          `json:"metadata"`
	Data       map[string]string `json:"data"`
	Type       string            `json:"type,omitempty"`
}

type fields = map[string]string

// Values in memory are the file bytes, including binary Secret fields.
type materials map[objectID]fields

func newMaterials(ids []objectID) materials {
	m := materials{}
	for _, id := range ids {
		m[id] = fields{}
	}
	return m
}

type kubectl []string

func (k kubectl) get(namespace string, args ...string) ([]byte, error) {
	argv := append(slices.Clone(k[1:]), "-n", namespace, "get")
	cmd := exec.Command(k[0], append(argv, args...)...)
	// kubectl and wrapper errors may quote the server response or command environment.
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get failed in %s", namespace)
	}
	return out, nil
}

func readExisting(k kubectl, ids []objectID, marketOnly bool) (materials, map[objectID]string, error) {
	existing := materials{}
	versions := map[objectID]string{}
	for _, ns := range []string{business, ledger, recon, sim} {
		var wanted []objectID
		for _, id := range ids {
			if id.namespace == ns {
				wanted = append(wanted, id)
			}
		}
		if len(wanted) == 0 {
			continue
		}
		args := []string{"secret,configmap", "-l", managedBy + "=" + manager, "-o", "json"}
		if marketOnly {
			args[0] = "configmap"
			args = append(args, "--field-selector", "metadata.name="+wanted[0].name)
		}
		out, err := k.get(namespace(ns), args...)
		if err != nil {
			return nil, nil, err
		}
		var list struct {
			Items []manifest `json:"items"`
		}
		if json.Unmarshal(out, &list) != nil || list.Items == nil {
			return nil, nil, fmt.Errorf("invalid kubectl object list in %s", ns)
		}
		for _, item := range list.Items {
			id := objectID{ns, item.Kind, item.Metadata.Name}
			if !slices.Contains(wanted, id) {
				continue
			}
			if item.Metadata.Namespace != namespace(ns) || item.Metadata.Labels[managedBy] != manager || existing[id] != nil {
				return nil, nil, fmt.Errorf("unexpected metadata for %s/%s", ns, id.name)
			}
			if id.kind == secret && item.Type != "" && item.Type != "Opaque" {
				return nil, nil, fmt.Errorf("unexpected Secret type for %s/%s", ns, id.name)
			}
			data := fields{}
			for key, value := range item.Data {
				if id.kind == secret {
					raw, err := base64.StdEncoding.DecodeString(value)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid Secret data in %s/%s", ns, id.name)
					}
					value = string(raw)
				}
				data[key] = value
			}
			existing[id] = data
			versions[id] = item.Metadata.ResourceVersion
		}
		// A label selector hides an unmanaged namesake. Check names only before creating anything.
		var missing []string
		for _, id := range wanted {
			if existing[id] == nil {
				missing = append(missing, strings.ToLower(id.kind)+"/"+id.name)
			}
		}
		if len(missing) > 0 {
			names, err := k.get(namespace(ns), append(missing, "--ignore-not-found", "-o", "name")...)
			if err != nil {
				return nil, nil, err
			}
			if len(bytes.TrimSpace(names)) > 0 {
				return nil, nil, fmt.Errorf("seed object name already in use in %s", ns)
			}
		}
	}
	return existing, versions, nil
}

func emit(out io.Writer, ids []objectID, m materials, versions map[objectID]string) error {
	var stream bytes.Buffer
	for _, id := range ids {
		data := m[id]
		if id.kind == secret {
			data = fields{}
			for key, value := range m[id] {
				data[key] = base64.StdEncoding.EncodeToString([]byte(value))
			}
		}
		obj := manifest{APIVersion: "v1", Kind: id.kind, Metadata: metadata{id.name, namespace(id.namespace), fields{managedBy: manager}, versions[id]}, Data: data}
		if id.kind == secret {
			obj.Type = "Opaque"
		}
		// JSON flow mappings are YAML. Start even the first document with a YAML marker
		// so kubectl selects its multi-document YAML decoder.
		stream.WriteString("---\n")
		if err := json.NewEncoder(&stream).Encode(obj); err != nil {
			return errors.New("encode manifests failed")
		}
	}
	if _, err := stream.WriteTo(out); err != nil {
		return errors.New("write manifest stream failed")
	}
	return nil
}

func run(args []string, out io.Writer, now time.Time) error {
	if len(args) == 2 && args[0] == "kms-export" {
		return exportKMS(context.Background(), args[1], out)
	}
	marketOnly := slices.Equal(args, []string{"market"})
	if !marketOnly && len(args) != 0 {
		return errors.New("usage: kaivo-stagingseed [market | kms-export <service>]")
	}
	command := strings.Fields(os.Getenv("KUBECTL"))
	if len(command) == 0 {
		command = []string{"kubectl"}
	}
	ids := allObjects
	var kms *kmsMaterials
	if marketOnly {
		ids = marketObjects
	} else if dir := os.Getenv("KAIVO_STAGING_KMS_DIR"); dir != "" {
		var err error
		kms, err = loadKMSDir(dir)
		if err != nil {
			return err
		}
	}
	existing, versions, err := readExisting(command, ids, marketOnly)
	if err != nil {
		return err
	}
	result := newMaterials(ids)
	if !marketOnly {
		if err := seedKeys(existing, result, kms); err != nil {
			return err
		}
		if err := seedInputs(existing, result, now); err != nil {
			return err
		}
		if kms != nil {
			if err := kms.seedWrappedFiles(existing, result); err != nil {
				return err
			}
		}
	}
	if err := marketInputs(existing, result, now, marketOnly); err != nil {
		return err
	}
	return emit(out, ids, result, versions)
}

func cli(args []string, stdout, stderr io.Writer, now time.Time) int {
	if err := run(args, stdout, now); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}
