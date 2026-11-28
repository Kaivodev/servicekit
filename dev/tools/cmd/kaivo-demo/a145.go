package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	pay "github.com/Kaivodev/protobuf/gen/go/aipay/payment/v1"
	"google.golang.org/protobuf/proto"
)

const (
	a145NeverSent     = "a145-never-sent"
	a145StaleBinding  = "a145-stale-binding"
	a145UnpaidBeforeT = "a145-unpaid-before-t"
	a145LatePayment   = "a145-late-payment"
	a145Refusals      = "a145-refusals"

	kQueryTransient    = "k-query-transient"
	kLedgerCancelEvent = "k-ledger-cancel-event"

	unboundClose    = pay.OrderCancellationBasis_ORDER_CANCELLATION_BASIS_OPERATOR_FORCED_CLOSE
	boundClose      = pay.OrderCancellationBasis_ORDER_CANCELLATION_BASIS_OPERATOR_FORCED_CLOSE_BOUND
	forcedReason    = "operator_forced_close"
	oldGatewayTag   = "v0.5.0"
	oldTradeVersion = "0.3.1"
)

func isA145Scenario(name string) bool {
	switch name {
	case a145NeverSent, a145StaleBinding, a145UnpaidBeforeT, a145LatePayment, a145Refusals:
		return true
	}
	return false
}

func (d *driver) a145Order() tradeRun {
	amount, channel := scenarioOrder(d.scope, true)
	return tradeRun{d: d, name: "EPay", proto: "v1", number: d.key(d.scope + "/EPay"), channel: channel, amount: amount}
}

// Keep the verification binding that was checked before this order was created.
func (t tradeRun) pluginPins() map[string]string {
	d := t.d
	key := "plugins/" + t.number
	var pins map[string]string
	if !d.read(key, &pins) || len(t.a144Orders()) == 0 {
		pins = d.a144Plugins()
		d.put(key, pins)
	}
	return pins
}

func (t *tradeRun) createA145(tradePlugin string) {
	d := t.d
	t.baseline()
	lost := d.scope == a145StaleBinding || d.scope == a145UnpaidBeforeT
	created := t.step("Create the order on its pinned trade account", func() {
		rows := t.a144Orders()
		if len(rows) == 0 {
			path := "/__test/accounts/" + simulatorAccount(t.channel) + "/next-create"
			switch {
			case lost:
				var armed object
				decode(d.sim("PUT", path, object{"create_fault": "lost"}), &armed)
				require(armed["create_fault"] == "lost", "simulator did not arm the lost create")
				d.evidence("create_fault", "lost")
			case d.scope == a145NeverSent:
				d.sim("POST", "/__test/listener/pause", object{"duration_ms": 60000})
				d.put("resume-after/"+t.number, time.Now().Add(time.Minute))
				d.evidence("pause_ms", 60000)
			}
			status, reply := d.signedEPay(t.proto, "/mapi.php", d.createParams(t.number, t.amount))
			d.evidence("merchant_response", object{"http_status": status, "code": reply["code"]})
			if !acceptedCreate(status, reply) {
				if lost && status < 500 {
					d.sim("DELETE", path, nil)
				}
				stop("merchant create failed with HTTP %d and EPay code %v", status, reply["code"])
			}
			rows = t.a144Orders()
		}
		row := oneFact(rows, "original merchant order")
		t.order, _, _ = t.checkOrderRoute(row)
		require(row["channel_account_id"] == d.required("uuid/"+channelKey(t.channel, "channel")) && row["plugin_version_id"] == tradePlugin, "order did not bind to the expected simulator account and package")
		d.evidence("order_id", t.order)
		d.evidence("plugin_version_id", tradePlugin)
		d.put("trade-no/"+d.scope+"/"+t.name, str(row, "trade_no"))
		hold := d.ledgerTrade(t.order)
		var before object
		require(hold["status"] == "RESERVED" && d.read("balances/"+d.scope+"/"+t.name, &before) && units(d.sellerBalance(), "available_usdt_micro") == num(before, "seller")-num(hold, "escrow_usdt"), "seller balance does not reflect the order reservation")
		d.evidence("reservation", hold)
	})
	t.order = str(created.Evidence, "order_id")
	if lost {
		t.step("Confirm that the create reached the gateway and lost its response", func() {
			rows := d.facts("payment", "lost_create", `SELECT exchange_id,category,requests,responses FROM payment_gateway_executions
                WHERE order_id=$1 AND operation='create_payment' AND requests>0`, t.order)
			create := oneFact(rows, "transmitted create")
			require(create["category"] == "unknown" && num(create, "responses") == 0, "expected one transmitted create with an unknown result")
		})
	}
	if d.scope == a145LatePayment || d.scope == a145Refusals {
		key := "cashier/" + t.number
		t.step("Keep the unpaid cashier link", func() {
			order := t.awaitOrderStatus("awaiting_payment")
			instruction := obj(order["payment_instruction"])
			link, _ := instruction["url"].(string)
			if link == "" {
				link = str(instruction, "qrcode")
			}
			d.cashier(link, false)
			d.put(key, link)
			d.evidence("upstream_order_id", str(order, "upstream_order_id"))
		})
		t.link = d.required(key)
	}
}

func (t tradeRun) view() object {
	d := t.d
	d.login("risk")
	view := d.browser("risk").api("GET", "/orders/"+t.order+"/forced-close", "", nil)
	require(view["order_id"] == t.order, "forced-close view belongs to another order")
	d.evidence("forced_close_view", view)
	return view
}

func approvalInView(view object) string {
	switch view["state"] {
	case "none":
		for _, field := range []string{"pending_approval_request_id", "approved_approval_request_id"} {
			require(view[field] == nil || view[field] == "", "unexpected approval ID on an order without a forced close")
		}
		return ""
	case "pending_approval":
		return str(view, "pending_approval_request_id")
	case "verifying", "cancelled", "paid", "fenced":
		return str(view, "approved_approval_request_id")
	default:
		stop("unknown forced-close state %v", view["state"])
		return ""
	}
}

func (t tradeRun) tooEarly() object {
	v := t.view()
	blockers, _ := v["blockers"].([]any)
	require(v["eligible"] == false && slices.Contains(blockers, any("too_early")) && v["upstream_bound"] == true, "expected a bound order before instruction expiry")
	deadline, err := time.Parse(time.RFC3339Nano, str(v, "eligible_at"))
	check(err)
	asOf, err := time.Parse(time.RFC3339Nano, str(v, "as_of"))
	check(err)
	require(deadline.After(asOf), "instruction deadline has already passed")
	return v
}

func (t tradeRun) backdateInstruction() {
	t.step("Move both instruction anchors past the TTL", func() {
		ttl := instructionTTL(t.d.env("payment")["AIPAY_PLUGIN_INSTRUCTION_TTL"])
		seconds := int64((ttl+time.Second-1)/time.Second) + 60
		require(seconds < t.unpaidSeconds(), "backdate would cross the channel unpaid timeout")
		t.d.evidence("instruction_ttl", ttl.String())
		t.d.evidence("backdate_seconds", seconds)
		t.backdateCreate(seconds, "backdate_audit")
	})
}

func (t tradeRun) unpaidSeconds() int64 {
	n, err := strconv.ParseInt(t.d.required(channelKey(t.channel, "unpaid-timeout")), 10, 64)
	check(err)
	return n
}

func (t tradeRun) submitPath() string { return "/orders/" + t.order + "/forced-close-requests" }
func assertionPath(id string) string  { return "/forced-closes/approvals/" + id + "/assertions" }

// Only a refusal of this exact write counts. A failed login, CSRF read,
// transport error or malformed reply must still fail the scenario.
func refusedWrite(path string, code int, write func()) bool {
	_, refused := portalRefusal(path, write, code)
	return refused
}

func requireRefusedWrite(path string, code int, message string, write func()) failure {
	f, refused := portalRefusal(path, write, code)
	require(refused, "portal accepted the write to "+path)
	require(f.httpStatus == 200 && f.message == message, fmt.Sprintf("expected HTTP 200 and %s on %s, got HTTP %d and %q", message, path, f.httpStatus, f.message))
	return f
}

func portalRefusal(path string, write func(), codes ...int) (failure, bool) {
	return portalMethodRefusal("POST", path, write, codes...)
}

func portalMethodRefusal(method, path string, call func(), codes ...int) (result failure, refused bool) {
	defer func() {
		if v := recover(); v != nil {
			f, ok := v.(failure)
			if !ok || f.method != method || f.path != path || !slices.Contains(codes, f.businessCode) || (f.httpStatus != 200 && f.httpStatus != f.businessCode) {
				panic(v)
			}
			result, refused = f, true
		}
	}()
	call()
	return failure{}, false
}

// The platform approval detail returns the owner request header, the
// canonical material as protobuf JSON and the recorded approvals.
func (t tradeRun) approvalDetail(id string) object {
	d := t.d
	person := approvers[0]
	d.login(person)
	r := d.browser(person).api("GET", "/approvals/payment/"+id, "", nil)
	require(r["owner_service"] == "payment" && obj(r["request"])["id"] == id && str(r, "canonical_material_json") != "", "approval detail returned a different request")
	var material object
	decode([]byte(str(r, "canonical_material_json")), &material)
	require(material["kind"] == "forced_close" && obj(material["forced_close"]) != nil, "approval detail lost the forced-close material")
	return r
}

func (t tradeRun) submitClose(view object, reason string, attempt int) object {
	d := t.d
	version := num(view, "control_version")
	aid := approvalInView(view)
	if aid == "" {
		require(view["eligible"] == true, "order is ineligible for forced close")
		d.evidence("submission_view", view)
	}
	// A resumed run replays the original submission through the same
	// idempotency key; payment returns the committed approval unchanged.
	r := d.browser("risk").write(fmt.Sprintf("risk/forced-close/%s/%d", t.order, attempt), t.submitPath(), func() object {
		return object{"expected_control_version": version, "reason": reason}
	})
	require(aid == "" || str(obj(r["approval_request"]), "id") == aid, "replayed submission differs from the recorded request")
	m := obj(r["material"])
	require(m["kind"] == "forced_close" && m["requested_by"] == d.required("user/risk"), "unexpected forced-close material or requester")
	op := obj(m["forced_close"])
	signedVersion, err := strconv.ParseInt(fmt.Sprint(op["expected_control_version"]), 10, 64)
	check(err)
	require(signedVersion > 0 && obj(op["trade"])["order_id"] == t.order && op["reason"] == reason && (aid != "" || signedVersion == version), "forced-close material differs from the proposal")
	d.evidence("requested_by", m["requested_by"])
	d.evidence("request_id", str(obj(r["approval_request"]), "id"))
	d.evidence("expected_control_version", signedVersion)
	return r
}

// An ambiguous write reuses the same attempt. Only a definitive eligibility
// conflict advances to a fresh idempotency key after checking the owner view.
func (t tradeRun) attemptForcedClose(reason string, wantBasis pay.OrderCancellationBasis, attempt int) string {
	d := t.d
	view := t.view()
	if approvalInView(view) == "" && view["eligible"] != true && d.scope == a145NeverSent {
		return "ineligible_view"
	}
	var r object
	if refusedWrite(t.submitPath(), 409, func() { r = t.submitClose(view, reason, attempt) }) {
		return "submission_409"
	}
	aid := str(obj(r["approval_request"]), "id")
	requester := d.required("user/risk")
	material := obj(obj(r["material"])["forced_close"])
	upstreamID, _ := material["upstream_order_id"].(string)
	neverSent, _ := material["never_sent"].(bool)
	require((upstreamID != "") == (wantBasis == boundClose) && neverSent == (d.scope == a145NeverSent), "signed order binding differs from the expected forced-close class")
	for _, person := range approvers {
		d.login(person)
		require(d.required("user/"+person) != requester, "requester cannot countersign a forced close")
	}
	if refusedWrite(assertionPath(aid), 409, func() {
		d.approveExisting(fmt.Sprintf("forced-close/%s/%d", aid, attempt), "payment", requester, "/forced-closes", r)
	}) {
		return "assertion_409"
	}

	current := t.view()
	// A completed cancellation may precede recovery of the second signature.
	// The immutable approval and matching outbox prove that handoff on resume.
	recovered := view["approved_approval_request_id"] == aid && current["state"] == "cancelled"
	require(current["approved_approval_request_id"] == aid && (current["state"] == "verifying" || recovered), "approved forced close did not enter verification")
	d.evidence("recovered_cancelled_view", recovered)
	return ""
}

func (t tradeRun) forcedClose(reason string, wantBasis pay.OrderCancellationBasis) string {
	d := t.d
	step := t.step("Submit and countersign the forced close", func() {
		key := "close-retries/" + t.order
		var conflicts []string
		d.read(key, &conflicts)
		for {
			d.evidence("retry_count", len(conflicts))
			d.evidence("retry_causes", conflicts)
			cause := t.attemptForcedClose(reason, wantBasis, len(conflicts))
			if cause == "" {
				return
			}
			d.evidence("last_conflict", cause)
			require(d.scope == a145NeverSent && len(conflicts) < 20, "forced-close eligibility conflict exceeded the retry budget")
			conflicts = append(conflicts, cause)
			d.put(key, conflicts)
			d.sleep(time.Second)
		}
	})
	aid := str(step.Evidence, "approval_id")
	t.step("Match the signed request to the payment outbox", func() {
		a := oneFact(d.facts("payment", "approved_order", `SELECT a.approved_at,o.close_reason,o.forced_close_request_id
			FROM payment_orders o JOIN payment_admin_requests a ON a.id=o.forced_close_request_id WHERE o.id=$1`, t.order), "approved close")
		require(a["close_reason"] == forcedReason && a["forced_close_request_id"] == aid && a["approved_at"] != nil, "order does not cite the approved close")
		var rows []object
		d.waitFor("sequenced cancellation request", 2*time.Minute, func() bool {
			rows = d.rows("payment", "payment_outbox", `SELECT event_id,sequence,cancellation_version,encode(payload,'hex') AS payload FROM payment_outbox
				WHERE order_id=$1 AND event_type='OrderCancellationVerificationRequested' AND schema_version=1 AND sequence IS NOT NULL`, t.order)
			return len(rows) > 0
		})
		row := oneFact(rows, "cancellation verification request")
		version := num(row, "cancellation_version")
		hold := d.ledgerTrade(t.order)
		checkCloseEvent(str(row, "payload"), t.order, str(hold, "escrow_reservation_id"), version, wantBasis)
		require(version == num(normalized(step.Evidence), "expected_control_version"), "outbox version differs from the approved proposal")
		d.evidence("cancellation_request", object{"event_id": row["event_id"], "sequence": row["sequence"], "version": version, "basis": wantBasis.String()})
		d.put("close-version/"+aid, version)
		d.put("close-event/"+aid, str(row, "event_id"))
		d.put("approved-at/"+aid, str(a, "approved_at"))
	})
	return aid
}

func checkCloseEvent(payload, order, escrow string, version int64, basis pay.OrderCancellationBasis) {
	var event pay.OrderCancellationVerificationRequested
	wire, err := hex.DecodeString(payload)
	check(err)
	check(proto.Unmarshal(wire, &event))
	require(event.OrderId == order && event.EscrowReservationId == escrow && escrow != "" && version > 0 && event.ControlVersion == uint64(version) && event.Basis == basis, "cancellation event differs from the approved order, reservation, version or basis")
}

func (t tradeRun) cancelled(approvalID, verifyPlugin, reason, outcome string) *result {
	d := t.d
	var version int64
	require(d.read("close-version/"+approvalID, &version), "missing cancellation version")
	t.step("Match the reconciliation request to the payment event", func() {
		d.waitFor("reconciliation cancellation request", 2*time.Minute, func() bool {
			rows := d.facts("reconciliation", "verification_request", `SELECT r.event_id,coalesce(to_jsonb(r)->>'cancellation_basis', to_jsonb(r)->>'basis') AS basis
                FROM reconciliation_verification_requests r WHERE r.event_id=$1`, d.required("close-event/"+approvalID))
			if len(rows) == 0 {
				return false
			}
			row := oneFact(rows, "verification request")
			require(row["basis"] == reason, "reconciliation received a different order or cancellation basis")
			return true
		})
	})
	authorization := t.cancellationEvidence(verifyPlugin, version, reason, outcome, "Verify both observations cited by the cancellation authorization")
	return t.step("Confirm the ledger posting and returned funds", func() {
		hold := t.terminal("CANCELLED")
		order := t.awaitOrderStatus("cancelled")
		require(order["escrow_status"] == "cancelled" && units(hold, "held_usdt_micro") == 0, "original escrow is still held")
		post := oneFact(d.facts("ledger", "cancellation_posting", `SELECT source_event_id,posting_seq FROM ledger_trade_authorizations WHERE order_id=$1 AND event_type='TradeCancellationAuthorized'`, t.order), "cancellation posting")
		require(post["source_event_id"] == authorization && post["posting_seq"] == hold["latest_seq"], "ledger posting does not match the cancellation authorization")
		d.evidence("cancelled_seq", hold["latest_seq"])
		d.evidence("cancelled_version", hold["control_version"])
		t.finish(false)
	})
}

func (d *driver) runA145NeverSent() {
	t := d.a145Order()
	pins := t.pluginPins()
	t.createA145(pins[t.channel])
	t.step("Wait for an unsent create eligible for forced close", func() {
		d.waitFor("retry_create after a dispatch that sent no request", time.Minute, func() bool {
			rows := d.facts("payment", "unsent_dispatch", `SELECT a.id,a.occurred_at,o.stage FROM payment_orders o JOIN payment_audit_logs a
				ON a.target_id=o.id::text AND a.target_type='order' AND a.action='order.dispatch_not_sent' WHERE o.id=$1 AND o.stage='retry_create'`, t.order)
			if len(rows) == 0 {
				return false
			}
			view := t.view()
			return view["never_sent"] == true && view["eligible"] == true && view["upstream_bound"] == false
		})
	})
	aid := t.forcedClose("Close the order whose create never reached the simulator.", unboundClose)
	t.step("Check dispatch fencing after the listener resumes", func() {
		var after time.Time
		require(d.read("resume-after/"+t.number, &after), "missing listener resume time")
		// The simulator answers the pause before closing its listener, so it
		// reopens slightly after the recorded time. Leave a margin.
		if delay := time.Until(after) + listenerResumeMargin; delay > 0 {
			d.sleep(delay)
		}
		var next object
		decode(d.sim("GET", "/__test/accounts/"+simulatorAccount(t.channel)+"/next-create", nil), &next)
		require(len(next) == 0, "unexpected pending create fault after listener recovery")
		d.evidence("listener_resumed_at", time.Now().UTC())
	})
	t.cancelled(aid, pins[t.channel+"_verify"], forcedReason, "not_found_unpaid")
	t.step("Exclude later retry grants and transmitted creates", func() {
		grants := d.facts("payment", "retry_grants_after_approval", `SELECT id,occurred_at FROM payment_audit_logs
			WHERE target_type='order' AND target_id=$1 AND action='order.retry_claimed' AND occurred_at>$2::text::timestamptz`, t.order, d.required("approved-at/"+aid))
		sent := d.facts("payment", "transmitted_creates", `SELECT exchange_id,requests FROM payment_gateway_executions WHERE order_id=$1 AND operation='create_payment' AND requests>0`, t.order)
		require(len(grants) == 0 && len(sent) == 0, "payment retried after approval or sent a create to the upstream")
	})
}

func (p a144Plugin) newestPublished(d *driver) object {
	var latest object
	version := p.minimum
	for row := range p.versions(d) {
		candidate := str(row, p.versionField)
		if row[p.statusField] == "executed" && row["emergency_disabled"] == false && versionAtLeast(candidate, version) {
			version, latest = candidate, row
		}
	}
	require(latest != nil, "missing a compatible published trade package to restore")
	return latest
}

func (trade a144Plugin) restoreNewest(d *driver) {
	var latest object
	d.liveStep("Select the newest published trade version for restoration", func() {
		d.login("operations")
		latest = trade.newestPublished(d)
		d.evidence("restore_version", latest[trade.versionField])
		d.evidence("restore_plugin_id", latest["plugin_version_id"])
	})
	restoreID := str(latest, "plugin_version_id")
	restoreDigest := hex.EncodeToString(raw(str(latest, "package_sha256")))
	trade.enable(d, restoreID, restoreDigest)
	d.liveStep("Confirm restoration of the newest published trade package", func() {
		current := trade.enabled(d)
		d.evidence("restored_trade_package", current)
		require(current["plugin_version_id"] == restoreID && current["version"] == latest[trade.versionField] && current["package_sha256"] == restoreDigest, "trade account did not return to the newest published version")
	})
}

func (d *driver) runA145StaleBinding() {
	t := d.a145Order()
	trade := d.a144PluginAccounts()[0]
	marker := "restore-trade/" + t.number
	var restore bool
	d.read(marker, &restore)
	defer func() {
		if restore {
			trade.restoreNewest(d)
			d.put(marker, false)
		}
	}()
	var pins map[string]string
	if restore {
		// A previous process already checked both accounts and started the
		// temporary binding. Keep its verification pin while recovering.
		require(d.read("plugins/"+t.number, &pins), "missing original plugin bindings")
	} else {
		pins = t.pluginPins()
	}
	key := "stale-plugin/" + t.number
	if len(t.a144Orders()) == 0 {
		d.buildGatewayPackages("", oldGatewayTag, trade.code)
		var manifest object
		decode(file(filepath.Join(d.required("package/"+packageKey(trade.code, oldGatewayTag)), "manifest.json")), &manifest)
		require(manifest["version"] == oldTradeVersion, "historical gateway tag contains the wrong trade plugin version")
		restore = true
		d.put(marker, true)
		oldID := trade.upgrade(d, oldTradeVersion, oldGatewayTag)
		d.put(key, oldID)
		d.liveStep("Refresh the quote after the historical package build", d.refreshMarket)
	}
	// Even a resumed terminal order must finish with a live binding check.
	restore = true
	t.createA145(d.required(key))
	t.step("Observe payment's stale query classification", func() {
		d.waitFor("unavailable order query from the historical trade package", 2*time.Minute, func() bool {
			rows := d.facts("payment", "unavailable_queries", `SELECT a.id,a.occurred_at,q.exchange_id,q.category,q.upstream_code
				FROM payment_audit_logs a JOIN payment_gateway_executions q ON q.order_id=$1::uuid AND q.operation='query_payment'
				WHERE a.target_type='order' AND a.target_id=($1::uuid)::text AND a.action='order.query_unavailable'
				AND q.category='rejected' AND q.upstream_code='epay_code_-1' AND q.responses>0`, t.order)
			return len(rows) > 0
		})
	})
	t.backdateInstruction()
	aid := t.forcedClose("Close the lost order pinned to the historical EPay package.", unboundClose)
	t.cancelled(aid, pins[t.channel+"_verify"], forcedReason, "not_found_unpaid")
	t.step("Check the order work after cancellation", func() {
		work := d.facts("payment", "archived_order_work", `SELECT object_id,archived_at FROM payment_work WHERE kind='order' AND object_id=$1 AND archived_at IS NOT NULL`, t.order)
		require(len(work) == 0, "payment archived the order work")
	})
}

func (d *driver) runA145UnpaidBeforeT() {
	t := d.a145Order()
	pins := t.pluginPins()
	t.createA145(pins[t.channel])
	t.step("Observe payment waiting after a missing order query", func() {
		d.waitFor("not-found query with waiting outcome", 2*time.Minute, func() bool {
			rows := d.facts("payment", "waiting_query", `SELECT a.id,a.occurred_at,a.changes#>>'{metadata,outcome}' AS outcome,q.exchange_id,q.upstream_code
				FROM payment_audit_logs a JOIN payment_gateway_executions q ON q.order_id=$1::uuid AND encode(q.evidence_sha256,'hex')=a.changes#>>'{metadata,query_evidence_sha256}'
				WHERE a.target_type='order' AND a.target_id=($1::uuid)::text AND a.action='order.query_not_found' AND a.changes#>>'{metadata,outcome}'='waiting'
				AND q.operation='query_payment' AND q.category='rejected' AND q.upstream_code='not_found' AND q.responses>0`, t.order)
			return len(rows) > 0
		})
	})
	t.backdateInstruction()
	aid := t.forcedClose("Close the missing unpaid order before the channel timeout.", unboundClose)
	t.cancelled(aid, pins[t.channel+"_verify"], forcedReason, "not_found_unpaid")
	t.step("Distinguish the operator approval from timeout inference", func() {
		row := oneFact(d.facts("payment", "unpaid_deadline", `SELECT o.last_create_at,a.approved_at,
			o.last_create_at + make_interval(secs => $3) AS unpaid_deadline, a.approved_at < o.last_create_at + make_interval(secs => $3) AS before_timeout
			FROM payment_orders o JOIN payment_admin_requests a ON a.id=o.forced_close_request_id WHERE o.id=$1 AND a.id=$2`, t.order, aid, float64(t.unpaidSeconds())), "unpaid deadline")
		require(row["before_timeout"] == true, "approval occurred after the channel unpaid timeout")
		rows := d.facts("payment", "inferred_close_intents", `SELECT id,occurred_at FROM payment_audit_logs WHERE target_type='order' AND target_id=$1
			AND action='order.system_close_requested' AND changes#>>'{metadata,reason}'=$2`, t.order, a144Reason)
		require(len(rows) == 0, "payment also requested an inferred close")
	})
}

func (d *driver) runA145LatePayment() {
	t := d.a145Order()
	pins := t.pluginPins()
	t.createA145(pins[t.channel])
	t.step("Check the instruction deadline", func() { t.tooEarly() })
	t.backdateInstruction()
	aid := t.forcedClose("Close the unpaid order with a known upstream binding.", boundClose)
	t.step("Make the simulator report the bound order closed", func() {
		fields := object{"query_addtime_backdate_seconds": t.unpaidSeconds() + 120}
		t.setScenario(fields)
		d.evidence("simulator_scenario", fields)
	})
	cancelled := t.cancelled(aid, pins[t.channel+"_verify"], forcedReason+"_bound", "closed_unpaid")
	t.completeLatePayment(cancelled, aid)
}

func (t tradeRun) checkLateForcedClose(id, approval string) {
	t.step("Trace the late payment to the forced-close approval", func() {
		d := t.d
		row := oneFact(d.facts("payment", "late_payment_origin", `SELECT id,forced_close_request_id FROM payment_late_payments WHERE order_id=$1 AND id=$2`, t.order, id), "late payment")
		require(row["forced_close_request_id"] == approval, "late payment cites a different forced close")
		d.login("operations")
		view := d.browser("operations").api("GET", "/late-payments/"+id, "", nil)
		// The platform view carries the order in its trade snapshot.
		require(view["forced_close_approval_request_id"] == approval && obj(view["trade"])["order_id"] == t.order, "platform late-payment view lost the forced-close origin")
		d.evidence("forced_close_approval_request_id", approval)
		rows := d.facts("payment", "late_payment_audit", `SELECT id,changes#>>'{metadata,close_reason}' AS close_reason FROM payment_audit_logs
			WHERE target_type='order' AND target_id=$1 AND action='order.late_payment_detected'`, t.order)
		require(oneFact(rows, "late-payment detection")["close_reason"] == forcedReason, "late-payment audit lost the close reason")
	})
}

// Both A145 cashier scenarios have a single unpaid simulator order. A callback
// delivery for it recovers a committed payment after losing the cashier reply.
func (t tradeRun) payA145Cashier() {
	var deliveries []object
	decode(t.d.sim("GET", "/__test/deliveries", nil), &deliveries)
	for _, delivery := range deliveries {
		if delivery["account_id"] == simulatorAccount(t.channel) && delivery["order_id"] == t.order {
			t.d.evidence("existing_cashier_payment", str(delivery, "event_id"))
			return
		}
	}
	t.d.cashier(t.link, true)
	t.d.evidence("cashier_payment", "accepted")
}

func (t tradeRun) refuseSubmission(view object, label string) {
	d := t.d
	version := num(view, "control_version")
	require(refusedWrite(t.submitPath(), 409, func() {
		d.browser("risk").write(label+"/"+t.order, t.submitPath(), func() object {
			return object{"expected_control_version": version, "reason": label}
		})
	}), "ineligible forced-close submission was accepted")
	d.evidence("refused_submission", object{"business_code": 409, "control_version": version})
}

func (t tradeRun) refuseSignature(person, aid string, code int, digest []byte) {
	d := t.d
	d.login(person)
	path := assertionPath(aid)
	require(refusedWrite(path, code, func() {
		d.browser(person).write("refusal/"+aid+"/"+person, path, func() object { return object{"assertion": d.assert(person, digest)} })
	}), "unexpected forced-close assertion acceptance")
	r := t.approvalDetail(aid)
	records, present := r["approvals"]
	votes, ok := records.([]any)
	require(present && (records == nil || ok && len(votes) == 0), "expected an empty approval record list after the refused signature")
	stored := d.facts("payment", "approval_signatures", `SELECT approver_id FROM payment_admin_approvals WHERE request_id=$1`, aid)
	require(len(stored) == 0, "payment recorded a signature for the refused assertion")
	d.evidence("refused_assertion", object{"request_id": aid, "persona": person, "business_code": code, "approvals": 0})
}

func (d *driver) runA145Refusals() {
	t := d.a145Order()
	pins := t.pluginPins()
	t.createA145(pins[t.channel])
	t.step("Refuse submission before the instruction deadline", func() {
		t.refuseSubmission(t.tooEarly(), "Submit before instruction expiry")
		require(approvalInView(t.view()) == "", "early submission created an approval")
		rows := d.facts("payment", "early_approval_requests", `SELECT id,requested_at FROM payment_admin_requests
            WHERE kind='forced_close' AND position(convert_to($1,'UTF8') in request_bytes)>0`, t.order)
		require(len(rows) == 0, "payment stored an approval for the early submission")
	})
	t.backdateInstruction()
	submit := t.step("Submit as risk after instruction expiry", func() {
		r := t.submitClose(t.view(), "Test the payment fence between proposal and approval.", 0)
		d.evidence("digest", b64.EncodeToString(challenge("payment", d.required("user/risk"), r)))
	})
	aid, digest := str(submit.Evidence, "request_id"), raw(str(submit.Evidence, "digest"))
	t.step("Refuse the requester's own credential", func() {
		d.evidence("credential_source", "risk IAM WebAuthn enrollment")
		t.refuseSignature("risk", aid, 403, digest)
	})
	t.step("Pay the order while the approval is pending", t.payA145Cashier)
	t.step("Refuse the first approver after payment evidence", func() {
		d.waitFor("payment owner to report payment", 2*time.Minute, func() bool {
			v := t.view()
			blockers, _ := v["blockers"].([]any)
			if slices.Contains(blockers, any("payment_reported")) {
				return true
			}
			o := d.browser("operations").api("GET", "/orders/"+t.order, "", nil)
			d.evidence("payment_order_status", o["status"])
			return slices.Contains([]string{"risk_held", "releasing", "completed"}, str(o, "status"))
		})
		t.refuseSignature(approvers[0], aid, 409, digest)
	})
	t.step("Confirm the callback and ledger payment", func() { t.observePaid(1) })
	t.step("Refuse a fresh submission on the paid order", func() {
		t.refuseSubmission(t.view(), "Submit on a paid order")
	})
	t.notify()
	t.release()
	t.step("Exclude any cancellation verification request", func() {
		rows := d.facts("payment", "cancellation_requests", `SELECT event_id,sequence FROM payment_outbox WHERE order_id=$1 AND event_type='OrderCancellationVerificationRequested'`, t.order)
		require(len(rows) == 0, "payment emitted a cancellation request for a refused close")
	})
}
