package main

import (
	"slices"
	"strings"
	"testing"
)

func idleAccountBalances() accountBalances {
	return accountBalances{
		seller: object{
			"available_usdt_micro":        "999298616",
			"risk_held_usdt_micro":        "0",
			"order_escrow_usdt_micro":     "0",
			"refund_reserved_usdt_micro":  "0",
			"payout_in_flight_usdt_micro": "0",
		},
		merchant: `账户 merchant
账户余额（USDT）
可用 0.550000
订单担保冻结 0.000000
风控冻结 0.000000
退款预留 0.000000
出款在途 0.000000
待释放 0.000000（0 笔）`,
	}
}

func TestNonzeroHolds(t *testing.T) {
	if got := idleAccountBalances().nonzeroHolds(); len(got) != 0 {
		t.Fatalf("idle balances reported %v", got)
	}
	for _, key := range []string{"risk_held_usdt_micro", "order_escrow_usdt_micro", "refund_reserved_usdt_micro", "payout_in_flight_usdt_micro"} {
		b := idleAccountBalances()
		b.seller[key] = "140277"
		if got := b.nonzeroHolds(); !slices.Equal(got, []string{"卖方 " + key + "=140277"}) {
			t.Errorf("%s: %v", key, got)
		}
	}
	for _, field := range []string{"订单担保冻结", "风控冻结", "退款预留", "出款在途"} {
		b := idleAccountBalances()
		b.merchant = strings.Replace(b.merchant, field+" 0.000000", field+" 0.000001", 1)
		if got := b.nonzeroHolds(); !slices.Equal(got, []string{"商户 " + field + " 0.000001 USDT"}) {
			t.Errorf("%s: %v", field, got)
		}
	}
	b := idleAccountBalances()
	b.merchant = strings.Replace(b.merchant, "（0 笔）", "（1 笔）", 1)
	if got := b.nonzeroHolds(); !slices.Equal(got, []string{"商户 待释放 0.000000（1 笔）"}) {
		t.Fatalf("pending order count: %v", got)
	}
	b.seller["risk_held_usdt_micro"] = "140277"
	if got := b.nonzeroHolds(); !slices.Equal(got, []string{"卖方 risk_held_usdt_micro=140277", "商户 待释放 0.000000（1 笔）"}) {
		t.Errorf("simultaneous holds: %v", got)
	}
}

func TestNonzeroHoldsRequiresValidFields(t *testing.T) {
	for _, value := range []any{nil, 0, "", "0.0", "invalid"} {
		b := idleAccountBalances()
		if value == nil {
			delete(b.seller, "refund_reserved_usdt_micro")
		} else {
			b.seller["refund_reserved_usdt_micro"] = value
		}
		expectFailure(t, func() { b.nonzeroHolds() })
	}
	for _, tc := range []struct{ old, replacement string }{
		{"订单担保冻结 0.000000\n", ""},
		{"风控冻结 0.000000", "风控冻结 0.0"},
		{"退款预留 0.000000", "退款预留 0.000000x"},
		{"待释放 0.000000（0 笔）", ""},
		{"待释放 0.000000", "待释放 0.00x000"},
		{"（0 笔）", ""},
		{"（0 笔）", "（x 笔）"},
	} {
		t.Run(tc.old+" -> "+tc.replacement, func(t *testing.T) {
			b := idleAccountBalances()
			b.seller["risk_held_usdt_micro"] = "1"
			b.merchant = strings.Replace(b.merchant, tc.old, tc.replacement, 1)
			expectFailure(t, func() { b.nonzeroHolds() })
		})
	}
}
