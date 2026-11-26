package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	require(len(args) == 3 || len(args) == 4, "usage: kaivo-demo STATE SERVICEKIT serve|setup [phase]|run SCENARIO [-o FILE]")
	root, e := filepath.Abs(args[0])
	check(e)
	repo, e := filepath.Abs(args[1])
	check(e)
	action := args[2]
	mode := setting("AIPAY_DEMO_TARGET", "native")
	require(mode == "native" || mode == "k8s", "unknown AIPAY_DEMO_TARGET")
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
		(&driver{demoEnvironment: nativeEnvironment{root, repo, dir}, root: root, dir: dir}).serve()
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
			require(mode == "native", "epay-live requires gateway mode")
			if scope == liveOffPhase {
				require(d.gatewayMode(), "epay-live requires gateway mode")
			} else {
				d.checkLivePrerequisites(action)
			}
		})
	}
	var kube *kubeEnvironment
	if mode == "k8s" {
		kube = newKubeEnvironment(ctx, dir)
		d.demoEnvironment = kube
		defer kube.closeForwards()
		d.history.Logs = "kubectl logs（各服务所在命名空间）"
	}
	start := func() {
		if kube != nil && len(kube.forwards) == 0 {
			kube.startForwards()
			kube.syncMerchantKeys()
		}
	}
	switch action {
	case "run":
		d.history.Checks, d.history.SourceNotes = round11Plan(target)
		if target == "dispute-refund-before-release" || target == "dispute-refund-after-release" {
			d.history.Checks, d.history.SourceNotes = disputeRefundPlan(target == "dispute-refund-after-release")
		}
		d.report()
		d.stepGroup(target, func() {
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
					if p.name != "packages" {
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
	if os.Getenv("AIPAY_DEMO_TARGET") == "k8s" || len(os.Args) > 1 && os.Args[1] == "serve-k8s" {
		var cancel context.CancelFunc
		ctx, cancel = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
	}
	if e := executeContext(ctx, os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
