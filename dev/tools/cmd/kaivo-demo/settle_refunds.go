package main

// Save the IDs and the starting ledger sequence together before any writes.
// A confirming refund can post even while the driver is stopped.
type refundBatch struct {
	Before  object
	Refunds []object
}

func (d *driver) settleRefunds() {
	account := d.required("seller-account")
	key := "settle-refunds/batch/" + account
	for {
		var batch refundBatch
		d.liveStep("查找卖方待办退款", func() {
			d.login("seller")
			if !d.read(key, &batch) {
				batch.Refunds = d.rows("payment", "payment_refunds", `SELECT f.id AS refund_id,f.order_id,f.status,o.channel_code,f.out_refund_no
					FROM payment_refunds f JOIN payment_orders o ON o.id=f.order_id
					WHERE o.seller_account_id=$1 AND f.mode='manual' AND f.status IN (6,7,8) ORDER BY f.id`, account)
				batch.Before = d.sellerBalance()
				if len(batch.Refunds) > 0 {
					d.put(key, batch)
				}
			}
			d.evidence("refunds", batch.Refunds)
		})
		if len(batch.Refunds) == 0 {
			d.liveStep("核对未结退款占用", func() {
				holds := d.rows("ledger", "ledger_trade_reservations", `SELECT order_id FROM ledger_trade_reservations
					WHERE seller_account_id=$1 AND status='REFUND_PENDING' ORDER BY order_id`, account)
				d.evidence("refund_pending_orders", holds)
				d.evidence("seller_balance", batch.Before)
				require(len(holds) == 0 && units(batch.Before, "refund_reserved_usdt_micro") == 0, "seller still has a refund hold")
			})
			return
		}
		d.liveStep("刷新核销所需的开发行情与覆盖数据", d.refreshMarket)
		var credit int64
		for _, row := range batch.Refunds {
			t := tradeRun{d: d, order: str(row, "order_id")}
			posting := t.manualRefund(str(row, "refund_id"))
			if num(posting, "posting_seq") > num(batch.Before, "as_of_seq") {
				credit += num(posting, "seller_credit")
			}
		}
		d.liveStep("核对卖方退款余额", func() {
			after := d.sellerBalance()
			d.evidence("before", batch.Before)
			d.evidence("after", after)
			d.evidence("expected_seller_credit_usdt_micro", credit)
			checkSettledBalance(batch.Before, after, credit)
		})
		delete(d.data, key)
		d.save()
	}
}

func checkSettledBalance(before, after object, credit int64) {
	require(units(after, "refund_reserved_usdt_micro") == 0, "seller still has a refund hold")
	require(units(after, "available_usdt_micro")-units(before, "available_usdt_micro") == credit, "seller available balance was not restored by the expected Q")
}
