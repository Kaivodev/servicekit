package main

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/Kaivodev/servicekit/kms/gcp"
	"github.com/Kaivodev/servicekit/signing"
)

const (
	specFormat     = "kaivo.kms-spec.v1"
	exportFormat   = "kaivo.kms-export.v1"
	reportRegistry = "ledger-report.jwks"
	reportPEM      = "ledger-report-public.pem"
)

type kmsSpec struct {
	Format   string                 `json:"format"`
	Services map[string]serviceSpec `json:"services"`
}

type serviceSpec struct {
	Signing []signingSpec `json:"signing"`
	Sealing []sealingSpec `json:"sealing,omitempty"`
}

type signingSpec struct {
	KID      string  `json:"kid"`
	Key      string  `json:"key"`
	Registry string  `json:"registry"`
	PEM      pemFile `json:"pem,omitempty"`
}

// The field is optional, but when present it must name the report PEM.
type pemFile string

func (p *pemFile) UnmarshalJSON(data []byte) error {
	var name string
	if json.Unmarshal(data, &name) != nil || name != reportPEM {
		return errors.New("invalid KMS PEM filename")
	}
	*p = pemFile(name)
	return nil
}

type sealingSpec struct {
	Purpose string `json:"purpose"`
	KEK     string `json:"kek"`
	File    string `json:"file"`
}

func readKMSJSON(path string, dest any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("cannot read JSON file")
	}
	if err := json.Unmarshal(data, dest, json.RejectUnknownMembers(true)); err != nil {
		return errors.New("invalid JSON structure")
	}
	return nil
}

var sealingPurpose = regexp.MustCompile(`^[a-z]{1,32}$`)

func readKMSSpec(path string) (*kmsSpec, error) {
	var spec kmsSpec
	if err := readKMSJSON(path, &spec); err != nil {
		return nil, fmt.Errorf("KMS spec: %w", err)
	}
	if spec.Format != specFormat || len(spec.Services) == 0 {
		return nil, errors.New("invalid KMS spec format or services")
	}
	kids := map[string]bool{"epay-dev": true}
	for _, key := range devSigningKeys {
		kids[key.kid] = true
	}
	// Binding a resource name only checks its syntax; no client credentials or I/O.
	var names gcp.Client
	for service, entries := range spec.Services {
		var extraRegistry string
		switch service {
		case "iam":
			extraRegistry = "iam-assertion.jwks"
		case "ledger":
			extraRegistry = reportRegistry
		default:
			return nil, errors.New("unsupported KMS service")
		}
		if entries.Signing == nil && entries.Sealing == nil {
			return nil, fmt.Errorf("missing KMS %s key lists", service)
		}
		pemAssigned := false
		for i, entry := range entries.Signing {
			_, err := names.SigningKey(entry.Key)
			if err != nil || !signing.ValidKeyID(entry.KID) || kids[entry.KID] {
				return nil, fmt.Errorf("invalid KMS %s signing[%d] key or kid", service, i)
			}
			if entry.Registry != service+".jwks" && entry.Registry != extraRegistry {
				return nil, fmt.Errorf("invalid KMS %s signing[%d] registry", service, i)
			}
			if entry.PEM != "" {
				if entry.Registry != reportRegistry || pemAssigned {
					return nil, errors.New("conflicting KMS report PEM assignment")
				}
				pemAssigned = true
			}
			kids[entry.KID] = true
		}
		purposes, files := map[string]bool{}, map[string]bool{}
		for i, entry := range entries.Sealing {
			_, err := names.SymmetricKey(entry.KEK)
			if err != nil || service != "iam" || !sealingPurpose.MatchString(entry.Purpose) || purposes[entry.Purpose] ||
				(entry.File != "data-keys.json" && entry.File != "epay-keys.json") || files[entry.File] {
				return nil, fmt.Errorf("invalid KMS %s sealing[%d] assignment", service, i)
			}
			purposes[entry.Purpose], files[entry.File] = true, true
		}
	}
	return &spec, nil
}
