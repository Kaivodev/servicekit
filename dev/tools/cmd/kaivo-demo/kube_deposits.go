package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	datasetName = "deposit-dataset"
	reviewsKey  = "seller-reviews.json"
	depositDir  = "/run/kaivo/deposits"
)

type kubeConfigMap struct {
	Metadata struct{ ResourceVersion string }
	Data     map[string]string
}

// Patch only the requested keys. A version conflict (or a lost response) must
// re-read the entire reviews array / first published dataset before retrying.
func (k *kubeEnvironment) updateConfigMap(ns, name string, update func(map[string]string) map[string]string) map[string]string {
	for range 4 {
		out := k.kubectl(nil, ns, "get", "configmap", name, "--ignore-not-found", "-o", "json")
		var cm kubeConfigMap
		exists := len(bytes.TrimSpace(out)) != 0
		if exists {
			decode(out, &cm)
			require(cm.Metadata.ResourceVersion != "", "missing ConfigMap resourceVersion: "+name)
		}
		changes := update(cm.Data)
		if changes == nil {
			return cm.Data
		}
		var err error
		if exists {
			patch := object{"metadata": object{"resourceVersion": cm.Metadata.ResourceVersion}, "data": changes}
			_, err = k.invoke(k.ctx, encoded(patch), "-n", ns, "patch", "configmap", name, "--type=merge", "--patch-file=/dev/stdin")
		} else {
			meta := object{"namespace": ns, "name": name}
			if name == datasetName {
				meta["labels"] = object{"app.kubernetes.io/managed-by": "kaivo-stagingseed"}
			}
			manifest := object{"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta, "data": changes}
			_, err = k.invoke(k.ctx, encoded(manifest), "-n", ns, "create", "-f", "-")
		}
		if err == nil {
			return changes
		}
	}
	stop("could not update ConfigMap %s/%s", ns, name)
	return nil
}

func (k *kubeEnvironment) requireDevelopment(service string) {
	require(k.env(service)["AIPAY_ENVIRONMENT"] == "development", service+" requires AIPAY_ENVIRONMENT=development for demo inputs")
}

func (k *kubeEnvironment) sellerReview(seller, owner, email string) {
	k.requireDevelopment("payment")
	k.updateConfigMap(k.namespaces["business"], "payment-inputs", func(data map[string]string) map[string]string {
		out, changed := mergeSellerReview([]byte(data[reviewsKey]), seller, owner, email, time.Now())
		if !changed {
			return nil
		}
		return map[string]string{reviewsKey: string(out)}
	})
	// Also wait on resume: an earlier patch could have reached the API just before interruption.
	k.waitProjection()
}

func (k *kubeEnvironment) generateDeposits(repo, seller string) map[string]string {
	tmp, err := os.MkdirTemp(k.dir, "dataset-")
	check(err)
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "deposits")
	command(repo, os.Environ(), "python3", "-B", filepath.Join(repo, "dev/deposit_scenario.py"), "--out", out, "--seller-account-id", seller,
		"--rpc-url", "http://devchain."+k.namespaces["sim"]+".svc.cluster.local:8545", "--bindings-file", depositDir+"/bindings.json")
	data := map[string]string{}
	for _, name := range []string{"chain.json", "scenario.json", "bindings.json", "reconciliation.env"} {
		data[name] = string(file(filepath.Join(out, name)))
	}
	return data
}

func (k *kubeEnvironment) prepareDeposits(repo, seller string) {
	k.requireDevelopment("ledger")
	k.requireDevelopment("reconciliation")
	sim := k.namespaces["sim"]
	data := k.updateConfigMap(sim, datasetName, func(current map[string]string) map[string]string {
		if scenario, ok := current["scenario.json"]; ok {
			var spec object
			decode([]byte(scenario), &spec)
			require(spec["account_id"] == seller, "deposit dataset belongs to another seller")
			require(current["chain.json"] != "" && current["bindings.json"] != "" && current["reconciliation.env"] != "", "incomplete deposit dataset")
			return nil
		}
		return k.generateDeposits(repo, seller)
	})
	recon := map[string]string{"bindings.json": data["bindings.json"], "AIPAY_RECON_DEPOSITS": "on"}
	for line := range strings.SplitSeq(strings.TrimSpace(data["reconciliation.env"]), "\n") {
		key, value, ok := strings.Cut(line, "=")
		require(ok && strings.HasPrefix(key, "AIPAY_RECON_") && value != "", "invalid reconciliation deposit settings")
		recon[key] = value
	}
	k.updateConfigMap(k.namespaces["reconciliation"], "reconciliation-deposits", func(current map[string]string) map[string]string {
		for key, value := range recon {
			if current[key] != value {
				return recon
			}
		}
		return nil
	})
	k.waitProjection()
	for _, service := range []string{"devchain", "devcollection", "reconciliation"} {
		ns := k.namespaces[k.domain(service)]
		deployment := "deployment/" + service
		k.kubectl(nil, ns, "rollout", "restart", deployment)
		// Allow the rollout to outlive the ordinary 30-second kubectl request limit.
		ctx, cancel := context.WithTimeout(k.ctx, 190*time.Second)
		err := k.bin(ctx, "-n", ns, "rollout", "status", deployment, "--timeout=180s").Run()
		cancel()
		require(err == nil, "rollout did not become ready: "+ns+"/"+service)
	}
}
