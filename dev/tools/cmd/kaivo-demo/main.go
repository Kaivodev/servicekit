package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
)

func execute(args []string) error { return executeContext(context.Background(), args) }
func executeContext(ctx context.Context, args []string) (err error) {
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(failure); ok {
				err = fmt.Errorf("%s", f.reason)
				return
			}
			panic(v)
		}
	}()
	if len(args) > 0 {
		switch args[0] {
		case "serve-k8s":
			serveKubeFixtures(ctx, fixtureDir(args[1:]))
			return nil
		case "fixture-config":
			installFixtureConfig(fixtureDir(args[1:]), os.Stdin)
			return nil
		}
	}
	var output string
	if len(args) >= 5 && (args[2] == "setup" || args[2] == "run") && args[len(args)-2] == "-o" {
		output = args[len(args)-1]
		require(output != "", "-o requires a report filename")
		args = args[:len(args)-2]
	}
	require(len(args) >= 3 && (len(args) <= 4 || args[2] == "invite"), "usage: kaivo-demo STATE SERVICEKIT serve|setup [phase] [-o FILE]|run SCENARIO [-o FILE]|invite platform EMAIL ROLE...|invite seller EMAIL\nNative ledger scenarios: ledger-read-only-exit, ledger-carryover, ledger-adjustment, ledger-approvals-inbox")
	root, e := filepath.Abs(args[0])
	check(e)
	repo, e := filepath.Abs(args[1])
	check(e)
	action := args[2]
	mode := setting("AIPAY_DEMO_TARGET", "native")
	require(mode == "native" || mode == "k8s", "unknown AIPAY_DEMO_TARGET")
	var invitation invitationRequest
	if action == "invite" {
		require(mode == "native", "demo invite requires the native target")
		invitation = parseInvitation(args[3:])
		_, err := os.Stat(filepath.Join(root, "stack.env"))
		require(os.IsNotExist(err), "demo invite requires the native process stack")
	}
	target := ""
	if len(args) == 4 {
		target = args[3]
	}
	funding := mode == "k8s" && (target == "deposits" || target == "deposit")
	scope := action
	if action == "run" {
		require(scenarios[target] != nil || funding || mode == "k8s" && localCapability(target), "unknown scenario")
		scope = target
	} else if action == "setup" && target == liveOffPhase {
		scope = liveOffPhase
	}
	dir := filepath.Join(root, "demo")
	if mode == "k8s" {
		dir = filepath.Join(root, "demo-k8s")
	}
	check(os.MkdirAll(dir, 0700))
	lockname := "driver.lock"
	if action == "serve" {
		lockname = "fixtures.lock"
	}
	f := roleLock(dir, lockname)
	defer f.Close()
	if action == "serve" {
		require(target == "", "serve takes no target")
		require(mode == "native", "K8s 夹具使用 serve-k8s")
		d := driver{demoEnvironment: nativeEnvironment{root, repo, dir}, root: root, dir: dir}
		d.requireGateways()
		d.serve()
		return nil
	}
	if mode == "k8s" && !localCapability(target) {
		// Same rule as the native driver: checkpoints live in a private directory.
		// A tmpfs mount is recommended (see dev/README.md) but not required.
		require(privateDir(dir), "K8s demo STATE must be a directory owned by you with mode 0700")
	}
	d := driverAt(root, repo, scope, dir)
	d.ctx = ctx
	d.output = output
	d.liveEPay = target == livePhase && (action == "run" || action == "setup") || scope == liveOffPhase
	if d.liveEPay {
		d.trimSavedLiveLinks()
		d.liveStep("测试上游运行条件", func() {
			require(mode == "native", "epay-live requires the native stack")
			if scope == liveOffPhase {
				d.requireGateways()
			} else {
				d.checkLivePrerequisites(action)
			}
		})
	}
	var kube *kubeEnvironment
	if mode == "k8s" {
		kube = newKubeEnvironment(ctx, dir, d.traceForward)
		d.demoEnvironment = kube
		defer kube.closeForwards()
		d.history.Logs = "kubectl logs（各服务所在命名空间）"
	}
	startForwards := func() {
		if kube != nil && len(kube.forwards) == 0 {
			kube.startForwards()
		}
	}
	loadOrigins := sync.OnceFunc(func() { d.origins = readPortalOrigins(d.env("backend")) })
	start := sync.OnceFunc(func() {
		d.requireGateways()
		startForwards()
		loadOrigins()
		d.syncMerchantKeys()
	})
	switch action {
	case "invite":
		loadOrigins()
		fmt.Println(d.exportInvitation(invitation, d.invitationMailID))
		return nil
	case "run":
		switch target {
		case disputePaidRelease, disputePaidRefund, disputePaidRace:
			d.history.Checks, d.history.SourceNotes = disputePaidPlan(target)
		case disputeReturn:
			d.history.Checks, d.history.SourceNotes = disputeReturnPlan()
		case "dispute-refund-before-release", "dispute-refund-after-release", disputeReturnPaid:
			d.history.Checks, d.history.SourceNotes = disputeRefundPlan(target == "dispute-refund-after-release")
			if target == disputeReturnPaid {
				d.history.Checks = slices.Insert(d.history.Checks, 1, "Refuse the return on the disputed paid order with HTTP 200, business code 409 and "+rulingOutcomeDenied+". Check zero ruling requests and the unchanged ledger control version.")
			}
		default:
			d.history.Checks, d.history.SourceNotes = round11Plan(target)
		}
		d.report()
		d.stepGroup(target, func() {
			if isLedgerScenario(target) {
				require(d.native(), target+" requires the native development stack")
				_, err := os.Stat(filepath.Join(d.root, "stack.env"))
				require(os.IsNotExist(err), target+" requires the native process stack")
				require(d.env("ledger")["AIPAY_ENVIRONMENT"] == "development", target+" requires AIPAY_ENVIRONMENT=development for ledger")
			}
			if target == a144NotSent || target == a144NotFound || isA145Scenario(target) || target == kQueryTransient || target == kLedgerCancelEvent || target == disputeReturn || isDisputePaidScenario(target) {
				d.checkA144Environment(target, startForwards)
			}
			if localCapability(target) {
				d.requireNative(target + "（重复回执或 ledger 本机控制）")
			}
			start()
			if funding {
				d.deposits()
				return
			}
			d.run(target)
		})
	case "setup":
		if localCapability(target) {
			d.stepGroup(target, func() { d.requireNative(target) })
		}
		type phase struct {
			name string
			run  func()
		}
		phases := []phase{{"iam", d.identities}, {"registry", d.registration}, {"packages", d.packages}, {"seller", d.seller}, {"channels", d.channels}, {"merchant", d.merchant}}
		if target == livePhase {
			phases = append(phases, phase{livePhase, d.setupLiveEPay})
		} else if target == liveOffPhase {
			phases = append(phases, phase{liveOffPhase, d.disableLiveEPay})
		}
		if funding {
			phases = append(phases, phase{target, d.deposits})
		}
		found := false
		for _, p := range phases {
			if target == "" || target == p.name {
				found = true
				d.stepGroup(p.name, func() {
					if p.name == "packages" {
						loadOrigins()
					} else {
						start()
					}
					p.run()
				})
			}
		}
		require(found, "unknown setup phase")
	default:
		stop("unknown command")
	}
	if output == "" {
		output = filepath.Join(d.dir, "reports", scope+".md")
	}
	fmt.Println(output)
	return nil
}

func localCapability(name string) bool {
	switch name {
	case "duplicates", "ledger-reader", "ledger-matches":
		return true
	}
	return false
}
func roleLock(dir, name string) *os.File {
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0600)
	check(e)
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		stop("another demo process holds this role")
	}
	return f
}

// Record prerequisites that fail before an individual phase step starts.
func (d *driver) stepGroup(name string, run func()) {
	d.active = nil
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(failure); ok && (d.active == nil || d.active.Status != "failed" && d.active.Status != "缺样本") {
				d.history.Steps = append(d.history.Steps, &result{Name: name, Status: "failed", Error: f.reason})
				d.report()
			}
			panic(v)
		}
	}()
	run()
}
func main() {
	ctx := context.Background()
	if os.Getenv("AIPAY_DEMO_TARGET") == "k8s" || len(os.Args) > 1 && os.Args[1] == "serve-k8s" ||
		len(os.Args) > 4 && os.Args[3] == "run" && os.Args[4] == disputePaidRace {
		var cancel context.CancelFunc
		ctx, cancel = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
	}
	if e := executeContext(ctx, os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
