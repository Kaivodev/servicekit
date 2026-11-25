package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func adminLabel(service string) string {
	if service == "devcollection" {
		return "collection-admin"
	}
	return service + "-admin"
}

func (k *kubeEnvironment) owner(service, dbvar string, args ...string) []byte {
	ns := k.namespaces[k.domain(service)]
	var deployment object
	decode(k.kubectl(nil, ns, "get", "deployment", service, "-o", "json"), &deployment)
	name := adminLabel(service) + "-" + id()
	pod := ownerPod(deployment, ns, name, service, dbvar, k.dir, args)
	// Register cleanup before create. The API may commit a create whose reply is lost.
	defer func() {
		_, err := k.invoke(context.Background(), nil, "-n", ns, "delete", "pod", name, "--ignore-not-found", "--wait=true", "--timeout=20s")
		require(err == nil, "failed to delete owner Pod "+name)
	}()
	k.kubectl(encoded(pod), ns, "create", "-f", "-")
	var phase string
	waitFor("owner Pod "+name, 4*time.Minute, func() bool {
		phase = strings.TrimSpace(string(k.kubectl(nil, ns, "get", "pod", name, "-o", "jsonpath={.status.phase}")))
		return phase == "Succeeded" || phase == "Failed"
	})
	logs := k.kubectl(nil, ns, "logs", name, "-c", service)
	require(phase == "Succeeded", service+" owner command failed")
	return logs
}

// Declarations contain identities, public keys and evidence digests. Preserve
// their exact bytes (IAM hashes the manifest) using a downward API file.
func ownerPod(deployment object, ns, name, service, dbvar, dir string, args []string) object {
	spec := obj(obj(obj(deployment["spec"])["template"])["spec"])
	delete(spec, "serviceAccount") // The API may return the deprecated alias as well.
	spec["serviceAccountName"] = service + "-migrate"
	secret := "pg-" + service
	if service == "devcollection" {
		spec["serviceAccountName"] = "collection"
		secret = "pg-collection-dev"
	}
	spec["automountServiceAccountToken"] = false
	spec["restartPolicy"] = "Never"
	spec["activeDeadlineSeconds"] = 240
	// A service's ReadWriteOnce data PVC can be mounted by another Pod on
	// the same node. Keep the admin Pod with that service on multi-node clusters.
	volumes, _ := spec["volumes"].([]any)
	for _, v := range volumes {
		volume := obj(v)
		if projected, ok := volume["projected"].(object); ok {
			sources, _ := projected["sources"].([]any)
			keep := slices.DeleteFunc(sources, func(src any) bool { return obj(src)["serviceAccountToken"] != nil })
			if len(keep) == 0 {
				delete(volume, "projected")
				volume["emptyDir"] = object{"medium": "Memory"}
			} else {
				projected["sources"] = keep
			}
		}
	}
	for _, v := range volumes {
		if obj(v)["persistentVolumeClaim"] == nil {
			continue
		}
		affinity, _ := spec["affinity"].(object)
		if affinity == nil {
			affinity = object{}
			spec["affinity"] = affinity
		}
		pods, _ := affinity["podAffinity"].(object)
		if pods == nil {
			pods = object{}
			affinity["podAffinity"] = pods
		}
		const required = "requiredDuringSchedulingIgnoredDuringExecution"
		terms, _ := pods[required].([]any)
		pods[required] = append(terms, object{"topologyKey": "kubernetes.io/hostname", "labelSelector": object{"matchLabels": object{"app.kubernetes.io/name": service}}})
		break
	}
	labels := object{"app.kubernetes.io/name": adminLabel(service)}
	meta := object{"name": name, "namespace": ns, "labels": labels}
	containers, _ := spec["containers"].([]any)
	require(len(containers) == 1, "expected a single owner service container")
	c := obj(containers[0])
	require(c["name"] == service, "owner Deployment container differs from service")
	for _, key := range []string{"ports", "startupProbe", "readinessProbe", "livenessProbe", "lifecycle"} {
		delete(c, key)
	}
	// Preserve the image entrypoint (and any explicit Deployment command).
	ref := object{"secretKeyRef": object{"name": secret, "key": "uri"}}
	env, _ := c["env"].([]any)
	var filtered []any
	for _, v := range env {
		n := obj(v)["name"]
		if n != "AIPAY_DATABASE_URL" && n != dbvar {
			filtered = append(filtered, v)
		}
	}
	for _, n := range slices.Compact([]string{"AIPAY_DATABASE_URL", dbvar}) {
		filtered = append(filtered, object{"name": n, "valueFrom": ref})
	}
	c["env"] = filtered
	argv := append([]string(nil), args...)
	for i, arg := range argv {
		if filepath.Dir(arg) != filepath.Join(dir, "declarations") {
			continue
		}
		const key = "kaivo.dev/declaration"
		require(meta["annotations"] == nil, "multiple owner declarations")
		data := file(arg)
		require(json.Valid(data), "invalid owner declaration")
		meta["annotations"] = map[string]string{key: string(data)}
		volumes, _ := spec["volumes"].([]any)
		spec["volumes"] = append(volumes, object{"name": "declaration", "downwardAPI": object{"items": []object{{"path": "input.json", "fieldRef": object{"fieldPath": "metadata.annotations['" + key + "']"}}}}})
		mounts, _ := c["volumeMounts"].([]any)
		c["volumeMounts"] = append(mounts, object{"name": "declaration", "mountPath": "/run/kaivo/declaration", "readOnly": true})
		argv[i] = "/run/kaivo/declaration/input.json"
	}
	c["args"] = argv
	return object{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}
}
