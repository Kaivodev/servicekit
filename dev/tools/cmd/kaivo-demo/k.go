package main

import (
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
)

const (
	queryPauseKey        = "listener-pause/" + kQueryTransient
	listenerResumeMargin = 5 * time.Second
)

type listenerPause struct {
	StartedAt time.Time `json:"started_at"`
	ResumeAt  time.Time `json:"resume_at"`
}

func (p listenerPause) requireActive() {
	require(time.Now().Before(p.ResumeAt), "inconclusive: the listener pause ended before the in-pause checks finished")
}

func (d *driver) requireSameCashier(original, repeated string) {
	require(d.resolveCashier(original) == d.resolveCashier(repeated), "repeating the merchant create returned a different simulator instruction")
}

func (d *driver) runKQueryTransient() {
	t := d.a145Order()
	t.baseline()
	create := func() object {
		return d.epay(t.proto, "/mapi.php", d.createParams(t.number, t.amount))
	}
	created := t.step("Create the EPay order and keep its cashier link", func() {
		reply := create()
		link := str(reply, "payurl")
		d.cashier(link, false)
		order, _, _, _ := t.readOrderRoute()
		d.put("cashier/"+t.number, link)
		d.put("trade-no/"+d.scope+"/"+t.name, str(reply, "trade_no"))
		d.evidence("order_id", order)
		d.evidence("out_trade_no", t.number)
	})
	t.order, t.link = str(created.Evidence, "order_id"), d.required("cashier/"+t.number)

	var pause listenerPause
	t.step("Pause the simulator listener for 60 seconds", func() {
		if !d.read(queryPauseKey, &pause) {
			const duration = time.Minute
			d.sim("POST", "/__test/listener/pause", object{"duration_ms": duration.Milliseconds()})
			pause.StartedAt = time.Now().UTC()
			pause.ResumeAt = pause.StartedAt.Add(duration)
			d.put(queryPauseKey, pause)
		}
		d.evidence("listener_pause", pause)
	})
	require(d.read(queryPauseKey, &pause), "missing listener pause times")
	t.step("Check the unpaid order after a failed query", func() {
		d.waitFor("an unavailable query during the listener pause", time.Until(pause.ResumeAt), func() bool {
			pause.requireActive()
			audits := d.facts("payment", "unavailable_queries", `SELECT id,occurred_at,changes#>>'{metadata,kind}' AS kind
				FROM payment_audit_logs WHERE target_type='order' AND target_id=$1 AND action='order.query_unavailable'
				AND occurred_at>$2 AND occurred_at<$3 ORDER BY occurred_at,id`, t.order, pause.StartedAt, pause.ResumeAt)
			for _, audit := range audits {
				switch audit["kind"] {
				case "not_sent", "unknown", "rejected":
				default:
					stop("unavailable query audit has an unexpected adapter error kind")
				}
			}
			return len(audits) > 0
		})
		order := oneFact(d.facts("payment", "unpaid_order", `SELECT status,data->'upstream_payment_status' AS upstream_payment_status,
			data ? 'payment_instruction' AS has_instruction FROM payment_orders WHERE id=$1`, t.order), "unpaid order")
		revocations := d.facts("payment", "instruction_revocations", `SELECT id,action,occurred_at FROM payment_audit_logs
			WHERE target_type='order' AND target_id=$1 AND changes#>>'{metadata,instruction_revoked_reason}' IS NOT NULL`, t.order)
		require(num(order, "status") == int64(pay.OrderStatus_ORDER_STATUS_AWAITING_PAYMENT) &&
			num(order, "upstream_payment_status") == int64(pay.UpstreamPaymentStatus_UPSTREAM_PAYMENT_STATUS_PENDING),
			"the order must still be awaiting payment with a pending upstream payment")
		require(order["has_instruction"] == true && len(revocations) == 0, "payment removed or revoked the instruction after a failed query")
		pause.requireActive()
	})
	t.step("Repeat the merchant create during the pause", func() {
		pause.requireActive()
		reply := create()
		d.requireSameCashier(t.link, str(reply, "payurl"))
		pause.requireActive()
		d.evidence("matching_payurl_at", time.Now().UTC())
	})
	t.step("Pay at the original cashier after the listener resumes", func() {
		if delay := time.Until(pause.ResumeAt.Add(listenerResumeMargin)); delay > 0 {
			d.sleep(delay)
		}
		t.payA145Cashier()
	})
	t.step("Confirm the callback and ledger payment", func() { t.observePaid(1) })
	t.notify()
	t.release()
}

func (t tradeRun) archiveCancellationWork(waitForRequest bool) {
	d := t.d
	d.step("Archive the order work before cancellation authorization", func() {
		if waitForRequest {
			d.waitFor("payment to request cancellation verification", 30*time.Second, func() bool {
				rows := d.facts("payment", "cancellation_request", `SELECT id,cancellation_version FROM payment_orders
					WHERE id=$1 AND cancellation_version>0`, t.order)
				return len(rows) == 1
			})
		}
		// Authorization can also win the race while the owner is retrying a lease.
		// Capture that evidence even if archive-work finds an already finished order.
		defer func() {
			rows := d.facts("reconciliation", "authorizations_at_archive", `SELECT authorization_id,issued_at FROM reconciliation_authorizations
				WHERE order_id=$1 AND event_type='TradeCancellationAuthorized'`, t.order)
			require(len(rows) == 0, "inconclusive: reconciliation had already authorized cancellation when the archive was checked")
		}()
		var receipt struct {
			OrderID    string    `json:"order_id"`
			ArchivedAt time.Time `json:"archived_at"`
		}
		key := "archive-work/" + t.order
		if !d.read(key, &receipt) {
			prior := d.facts("payment", "prior_archives", `SELECT id,occurred_at FROM payment_audit_logs
				WHERE target_type='order' AND target_id=$1 AND action='order.dev_work_archived'`, t.order)
			require(len(prior) == 0, "inconclusive: order work was archived without a saved owner receipt")
			decode(d.owner("payment", "AIPAY_DATABASE_URL", "dev", "archive-work", "--order", t.order), &receipt)
			require(receipt.OrderID == t.order && !receipt.ArchivedAt.IsZero(), "archive-work returned an invalid receipt for this order")
			d.put(key, receipt)
		}
		d.evidence("archive_receipt", receipt)
	})
}

func (t tradeRun) checkCancellationProjection() object {
	d := t.d
	t.awaitOrderStatus("cancelled")
	audits := d.facts("payment", "cancellation_audits", `SELECT id,action,actor_id,occurred_at,
		changes#>>'{metadata,dispute_id}' AS dispute_id, changes#>>'{metadata,ruling_id}' AS ruling_id,
		changes#>>'{metadata,authorization_id}' AS authorization_id FROM payment_audit_logs
		WHERE target_type='order' AND target_id=$1 AND action IN ('order.ledger_cancelled','order.ledger_verified','order.dev_work_archived')
		ORDER BY occurred_at,id`, t.order)
	work := oneFact(d.facts("payment", "archived_order_work", `SELECT object_id,archived_at,completed_at FROM payment_work
		WHERE kind='order' AND object_id=$1`, t.order), "order work")
	return checkArchivedCancellation(audits, work)
}

func checkArchivedCancellation(audits []object, work object) object {
	counts := map[string]int{}
	var cancellation object
	for _, row := range audits {
		action := str(row, "action")
		counts[action]++
		switch action {
		case "order.ledger_cancelled":
			cancellation = row
		case "order.dev_work_archived":
			require(row["actor_id"] == "payment/dev", "unexpected actor on the order work archive")
		}
	}
	require(counts["order.ledger_cancelled"] == 1 && counts["order.ledger_verified"] == 0, "expected a single cancellation from the ledger event and no work-path verification")
	require(counts["order.dev_work_archived"] == 1 && work["archived_at"] != nil && work["completed_at"] == nil, "expected one archive audit and unfinished archived order work")
	return cancellation
}
