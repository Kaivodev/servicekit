package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMergeSellerReview(t *testing.T) {
	now := time.Date(2026, 11, 26, 13, 0, 0, 0, time.UTC)
	refused := func(name string, f func()) {
		t.Helper()
		defer func() {
			if _, ok := recover().(failure); !ok {
				t.Fatal(name, "accepted")
			}
		}()
		f()
	}
	out, changed := mergeSellerReview([]byte("[]"), "s1", "u1", "a@example.test", now)
	var rows []map[string]any
	if !changed || json.Unmarshal(out, &rows) != nil || len(rows) != 1 || rows[0]["reviewed_by"] != developmentReviewer || rows[0]["valid_until"] != "2026-12-03T13:00:00Z" || len(rows[0]["review_sha256"].(string)) != 64 {
		t.Fatalf("new review %s", out)
	}
	if again, changed := mergeSellerReview(out, "s1", "u1", "a@example.test", now.Add(time.Hour)); changed || again != nil {
		t.Fatal("active review rewritten")
	}
	renewed, changed := mergeSellerReview(out, "s1", "u1", "a@example.test", now.Add(8*24*time.Hour))
	if !changed || json.Unmarshal(renewed, &rows) != nil || len(rows) != 1 || rows[0]["valid_until"] != "2026-12-11T13:00:00Z" {
		t.Fatalf("expired development review not renewed %s", renewed)
	}
	refused("changed enrollment", func() { mergeSellerReview(out, "s1", "u1", "b@example.test", now) })
	other := []byte(`[{"seller_account_id":"s1","review_sha256":"x","reviewed_by":"auditor","valid_until":"2026-11-01T00:00:00Z"}]`)
	refused("expired foreign review", func() { mergeSellerReview(other, "s1", "u1", "a@example.test", now) })
	both, _ := mergeSellerReview([]byte(`[{"seller_account_id":"s0","review_sha256":"y","reviewed_by":"auditor","valid_until":"2027-01-01T00:00:00Z"}]`), "s1", "u1", "a@example.test", now)
	if json.Unmarshal(both, &rows) != nil || len(rows) != 2 {
		t.Fatal("other sellers' reviews dropped")
	}
}
