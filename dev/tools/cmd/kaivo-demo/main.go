package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func execute(args []string) (err error) {
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(failure); ok {
				err = fmt.Errorf("%s", f.reason)
				return
			}
			panic(v)
		}
	}()
	var output string
	if len(args) == 6 && args[2] == "run" && args[4] == "-o" {
		output = args[5]
		require(output != "", "-o requires a report filename")
		args = args[:4]
	}
	require(len(args) == 3 || len(args) == 4, "usage: kaivo-demo STATE SERVICEKIT serve|setup [phase]|run SCENARIO [-o FILE]")
	root, repo, action := args[0], args[1], args[2]
	target := ""
	if len(args) == 4 {
		target = args[3]
	}
	scope := action
	if action == "run" {
		require(scenarios[target] != nil, "unknown scenario")
		scope = target
	}
	dir := filepath.Join(root, "demo")
	check(os.MkdirAll(dir, 0700))
	lockname := "driver.lock"
	if action == "serve" {
		lockname = "fixtures.lock"
	}
	f, e := os.OpenFile(filepath.Join(dir, lockname), os.O_CREATE|os.O_RDWR, 0600)
	check(e)
	defer f.Close()
	require(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil, "another demo process holds this role")
	if action == "serve" {
		require(target == "", "serve takes no target")
		(&driver{root: root, dir: dir}).serve()
		return nil
	}
	d := newDriver(root, repo, scope)
	switch action {
	case "run":
		d.output = output
		if target == "dispute-refund-before-release" || target == "dispute-refund-after-release" {
			d.history.Checks, d.history.SourceNotes = disputeRefundPlan(target == "dispute-refund-after-release")
		}
		d.report()
		d.run(target)
	case "setup":
		phases := []struct {
			name string
			run  func()
		}{{"iam", d.identities}, {"registry", d.registration}, {"packages", d.packages}, {"seller", d.seller}, {"channels", d.channels}, {"merchant", d.merchant}}
		found := false
		for _, p := range phases {
			if target == "" || target == p.name {
				found = true
				d.stepGroup(p.name, p.run)
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

// Record prerequisites that fail before an individual phase step starts.
func (d *driver) stepGroup(name string, run func()) {
	d.active = nil
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(failure); ok && (d.active == nil || d.active.Status != "failed") {
				d.history.Steps = append(d.history.Steps, &result{Name: name, Status: "failed", Error: f.reason})
				d.report()
			}
			panic(v)
		}
	}()
	run()
}
func main() {
	if e := execute(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
