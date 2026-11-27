package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArchiveWorkRetriesOnlyTheLeaseConflict(t *testing.T) {
	for _, tc := range []struct {
		message string
		retry   bool
	}{
		{"order work unavailable: retry if it is executing", true},
		{"order work is already complete", false},
	} {
		root := t.TempDir()
		env := nativeEnvironment{root: root, dir: root}
		check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_ENVIRONMENT=development\n")))
		check(atomic(filepath.Join(root, "env/payment-migrate.env"), []byte("AIPAY_DATABASE_URL=owner-db\n")))
		check(atomic(filepath.Join(root, "error-message"), []byte(tc.message)))
		const script = `#!/bin/sh
echo attempt >> attempts
if [ ! -e attempted ]; then
    touch attempted
    cat error-message >&2
    exit 1
fi
echo "$4"
`
		bin := filepath.Join(root, "bin/payment")
		check(atomic(bin, []byte(script)))
		check(os.Chmod(bin, 0700))
		call := func() {
			got := env.owner("payment", "AIPAY_DATABASE_URL", "dev", "archive-work", "--order", "original")
			if string(got) != "original\n" {
				t.Fatal("lost the owner response or order argument")
			}
		}
		want := "attempt\n"
		if tc.retry {
			call()
			want += "attempt\n"
		} else {
			if reason := failureText(call); reason != "payment dev archive-work failed" {
				t.Fatalf("unexpected public owner error: %q", reason)
			}
		}
		if got := string(file(filepath.Join(root, "attempts"))); got != want {
			t.Fatalf("unexpected owner attempts for %q: %q", tc.message, got)
		}
	}
}

func TestArchivedCancellationEvidence(t *testing.T) {
	event := object{"action": "order.ledger_cancelled"}
	archive := object{"action": "order.dev_work_archived", "actor_id": "payment/dev"}
	work := object{"archived_at": "archived", "completed_at": nil}
	checkArchivedCancellation([]object{archive, event}, work)
	for _, rows := range [][]object{
		{archive}, {event}, {archive, event, event}, {archive, archive, event},
		{archive, event, {"action": "order.ledger_verified"}},
		{event, {"action": "order.dev_work_archived", "actor_id": "other"}},
	} {
		expectFailure(t, func() { checkArchivedCancellation(rows, work) })
	}
	for _, row := range []object{{"archived_at": nil}, {"archived_at": "archived", "completed_at": "finished"}} {
		expectFailure(t, func() { checkArchivedCancellation([]object{archive, event}, row) })
	}
}

func TestQueryPauseSurvivesDriverRestart(t *testing.T) {
	root := t.TempDir()
	d := newDriver(root, "", kQueryTransient)
	check(atomic(filepath.Join(root, "env/payment.env"), []byte("AIPAY_UPSTREAM_GATEWAY_ADDRESS=trade\n")))
	check(atomic(filepath.Join(root, "env/reconciliation.env"), []byte("AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS=verify\n")))
	check(atomic(filepath.Join(root, "inputs/upstream-sim/config.json"), []byte(`{"environment":"test","control_token":"test"}`)))
	now := time.Now().UTC()
	pause := listenerPause{StartedAt: now, ResumeAt: now.Add(time.Minute)}
	d.put(queryPauseKey, pause)

	probes := 0
	client := localHTTP
	t.Cleanup(func() { localHTTP = client })
	localHTTP = &http.Client{Transport: startWebhook(func(*http.Request) (*http.Response, error) {
		probes++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}
	resumed := newDriver(root, "", kQueryTransient)
	resumed.checkA144Environment(kQueryTransient)
	if probes != 0 {
		t.Fatal("probed the simulator during its saved pause")
	}
	var saved listenerPause
	if !resumed.read(queryPauseKey, &saved) || saved != pause {
		t.Fatal("the resumed driver changed the listener pause")
	}
	saved.requireActive()
	saved.ResumeAt = now.Add(-2 * listenerResumeMargin)
	expectFailure(t, saved.requireActive)
	resumed.put(queryPauseKey, saved)
	resumed.checkA144Environment(kQueryTransient)
	if probes != 1 {
		t.Fatal("missing control probe after the listener recovered")
	}
}
