package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

const developmentReviewer = "kaivo-demo-development"

// sellerReviewer writes the development seller review that payment reads from
// AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE (native) or its ConfigMap (Kubernetes).
type sellerReviewer interface {
	sellerReview(seller, owner, email string)
}

// mergeSellerReview binds the development review to the actual IAM enrollment.
// It keeps an active row, refuses a changed enrollment for the development
// reviewer and an expired review by anyone else, and otherwise appends or
// replaces the seller's row with a 7-day review.
func mergeSellerReview(raw []byte, seller, owner, email string, now time.Time) ([]byte, bool) {
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded(object{"seller_account_id": seller, "user_id": owner, "email": email})))
	var rows []json.RawMessage
	require(json.Unmarshal(raw, &rows) == nil && rows != nil, "invalid payment seller reviews")
	index := -1
	active := false
	for i, r := range rows {
		var row struct {
			Seller   string    `json:"seller_account_id"`
			Reviewer string    `json:"reviewed_by"`
			Digest   string    `json:"review_sha256"`
			Until    time.Time `json:"valid_until"`
		}
		decode(r, &row)
		if row.Seller != seller {
			continue
		}
		require(index == -1, "duplicate review for seller")
		index = i
		if row.Reviewer == developmentReviewer {
			require(row.Digest == digest, "development seller enrollment changed")
		}
		active = row.Until.After(now)
		require(active || row.Reviewer == developmentReviewer, "existing seller review has expired")
	}
	if active {
		return nil, false
	}
	row := encoded(object{"seller_account_id": seller, "review_sha256": digest, "reviewed_by": developmentReviewer, "valid_until": now.UTC().Add(7 * 24 * time.Hour).Truncate(time.Second)})
	if index >= 0 {
		rows[index] = row
	} else {
		rows = append(rows, row)
	}
	return encoded(rows), true
}

// payment re-reads the file on every review lookup; no restart is needed.
func (d nativeEnvironment) sellerReview(seller, owner, email string) {
	env := d.env("payment")
	require(env["AIPAY_ENVIRONMENT"] == "development", "payment requires AIPAY_ENVIRONMENT=development for demo inputs")
	path := env["AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE"]
	require(path != "", "payment has no development seller reviews file")
	if out, changed := mergeSellerReview(file(path), seller, owner, email, time.Now()); changed {
		check(atomic(path, out))
	}
}
