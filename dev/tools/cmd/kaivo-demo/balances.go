package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type accountBalances struct {
	seller   object
	merchant string
}

func (d *driver) readAccountBalances(label string) accountBalances {
	b := d.bot("snap/"+label+"/balance", "/balance")
	require(strings.HasPrefix(b, "账户 "+d.required("merchant-account")+"\n"), "merchant scope mismatch")
	return accountBalances{seller: d.sellerBalance(), merchant: b}
}

const usdtAmount = `[0-9]+\.[0-9]{6}`

var pendingReleaseLine = regexp.MustCompile(`(?m)^待释放 (` + usdtAmount + `)（([0-9]+) 笔）$`)

func (b accountBalances) nonzeroHolds() []string {
	return append(sellerHolds(b.seller), b.merchantHolds()...)
}

func sellerHolds(seller object) []string {
	var holds []string
	for _, key := range []string{"risk_held_usdt_micro", "order_escrow_usdt_micro", "refund_reserved_usdt_micro", "payout_in_flight_usdt_micro"} {
		if n := units(seller, key); n != 0 {
			holds = append(holds, fmt.Sprintf("卖方 %s=%d", key, n))
		}
	}
	return holds
}

func (b accountBalances) merchantHolds() []string {
	var holds []string
	for _, field := range []string{"订单担保冻结", "风控冻结", "退款预留", "出款在途"} {
		amount := capture(`(?m)^`+field+` (`+usdtAmount+`)$`, b.merchant)
		if micro(amount) != 0 {
			holds = append(holds, "商户 "+field+" "+amount+" USDT")
		}
	}
	m := pendingReleaseLine.FindStringSubmatch(b.merchant)
	require(m != nil, "商户待释放金额或笔数格式错误")
	micro(m[1])
	count, err := strconv.ParseUint(m[2], 10, 64)
	require(err == nil, "商户待释放笔数格式错误")
	if count != 0 {
		holds = append(holds, "商户 "+m[0])
	}
	return holds
}

func (d *driver) waitForIdleBalances() accountBalances {
	var b accountBalances
	var holds []string
	if !pollUntil(2*time.Minute, func() bool {
		// Every bot poll is a new Telegram update kept in the driver state, so
		// poll the seller portal and ask the bot only once the seller side is idle.
		if holds = sellerHolds(d.sellerBalance()); len(holds) > 0 {
			return false
		}
		b = d.readAccountBalances("idle/" + id())
		holds = b.nonzeroHolds()
		return len(holds) == 0
	}) {
		d.evidence("nonzero_holds", holds)
		d.recordSellerHolds()
		stop("等待余额归零超时（2 分钟）：%s", strings.Join(holds, "，"))
	}
	return b
}

func (d *driver) recordSellerHolds() {
	// Keep the balance timeout and any pages already read if a diagnostic request fails.
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(failure); ok {
				d.evidence("seller_holds_error", f.reason)
			} else {
				panic(v)
			}
		}
	}()
	path := "/accounts/" + d.required("seller-account") + "/holds"
	items := []any{}
	seen := map[string]bool{}
	for cursor := ""; ; {
		query := url.Values{"limit": {"100"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		page := d.browser("seller").api("GET", path+"?"+query.Encode(), "", nil)
		rows, ok := page["items"].([]any)
		require(ok, "missing seller holds list")
		items = append(items, rows...)
		d.evidence("seller_holds", items)
		cursor, _ = page["next_cursor"].(string)
		if cursor == "" {
			return
		}
		require(!seen[cursor], "repeated seller holds cursor")
		seen[cursor] = true
	}
}

func (d *driver) balanceSnapshot(label string) object {
	return d.balanceSnapshotFrom(label, d.readAccountBalances(label))
}

func (d *driver) balanceSnapshotFrom(label string, b accountBalances) object {
	fees := d.rows("ledger", "ledger_balances (three fee accounts)", "SELECT COALESCE(sum(b.balance_units),0)::bigint AS units FROM ledger_accounts a JOIN ledger_balances b ON b.account_id=a.id WHERE a.code IN ('merchant_trade_fee_revenue:USDT','channel_trade_fee_revenue:USDT','trade_spread_revenue:USDT')")
	return object{
		"merchant_bot":        b.merchant,
		"merchant":            micro(capture(`(?m)^可用 (`+usdtAmount+`)$`, b.merchant)),
		"seller_portal":       b.seller,
		"seller":              units(b.seller, "available_usdt_micro"),
		"ledger_fee_accounts": num(fees[0], "units"),
		"orders_bot":          d.bot("snap/"+label+"/orders", "/orders"),
	}
}
