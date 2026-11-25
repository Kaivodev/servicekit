package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type forward struct {
	cmd  *exec.Cmd
	done chan struct{}
}

// dbForward remembers how a CNPG forward was started so it can be restarted:
// kubectl port-forward exits ("lost connection to pod") when PostgreSQL resets
// a closed connection, which happens after ordinary short-lived queries.
type dbForward struct {
	ns, service string
	mappings    []string
	current     *forward
}

func (f *forward) exited() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// ensureDatabaseForward restarts the domain's database forward if it exited.
func (k *kubeEnvironment) ensureDatabaseForward(domain string) {
	if f := k.dbForwards[domain]; f != nil && f.current.exited() {
		f.current = k.forward(f.ns, f.service, f.mappings)
	}
}

func (k *kubeEnvironment) startForwards() {
	for _, s := range []struct {
		domain, service string
		mappings        []string
	}{
		{"business", "backend", []string{fmt.Sprintf("%d:8080", k.base), fmt.Sprintf("%d:8081", k.base+1), fmt.Sprintf("%d:8082", k.base+2)}},
		{"sim", "upstream-sim", []string{"9080:9080"}},
		{"sim", "mailpit", []string{fmt.Sprintf("%d:8025", k.base+3)}},
		{"sim", fixtureService, []string{fmt.Sprintf("%d:8088", k.base+4)}},
		{"business", "business-pg-rw", []string{fmt.Sprintf("%d:5432", k.base+5)}},
		{"ledger", "ledger-pg-rw", []string{fmt.Sprintf("%d:5432", k.base+6)}},
		{"reconciliation", "reconciliation-pg-rw", []string{fmt.Sprintf("%d:5432", k.base+7)}},
	} {
		f := k.forward(k.namespaces[s.domain], s.service, s.mappings)
		if strings.HasSuffix(s.service, "-pg-rw") {
			k.dbForwards[s.domain] = &dbForward{k.namespaces[s.domain], s.service, s.mappings, f}
		}
	}
}

func (k *kubeEnvironment) forward(ns, service string, mappings []string) *forward {
	for _, mapping := range mappings {
		local, _, _ := strings.Cut(mapping, ":")
		// After a forward exits, a VM wrapper (such as Lima) releases the host
		// port asynchronously; wait briefly before reporting a real conflict.
		deadline := time.Now().Add(10 * time.Second)
		for {
			l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", local))
			if e == nil {
				l.Close()
				break
			}
			require(time.Now().Before(deadline), "local port "+local+" already in use")
			time.Sleep(250 * time.Millisecond)
		}
	}
	args := append([]string{"-n", ns, "port-forward", "--address", "127.0.0.1", "service/" + service}, mappings...)
	// Own the wrapper's process group as well as kubectl itself.
	cmd := k.bin(k.ctx, args...)
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = io.Discard
	out, e := cmd.StdoutPipe()
	check(e)
	require(cmd.Start() == nil, "could not start port-forward for "+service)
	f := &forward{cmd, make(chan struct{})}
	k.forwards = append(k.forwards, f)
	ready := make(chan struct{})
	go func() {
		pending := map[string]bool{}
		for _, mapping := range mappings {
			local, remote, _ := strings.Cut(mapping, ":")
			pending["Forwarding from 127.0.0.1:"+local+" -> "+remote] = true
		}
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			if pending[scanner.Text()] {
				delete(pending, scanner.Text())
				if len(pending) == 0 {
					close(ready)
				}
			}
		}
		cmd.Wait()
		close(f.done)
	}()
	ctx, cancel := context.WithTimeout(k.ctx, 25*time.Second)
	defer cancel()
	select {
	case <-ready:
	case <-f.done:
		stop("port-forward for %s exited before binding %s", service, strings.Join(mappings, ","))
	case <-ctx.Done():
		stop("port-forward for %s did not become ready", service)
	}
	// A multi-word wrapper may have bound inside a VM. Confirm the driver can reach it.
	for _, mapping := range mappings {
		local, _, _ := strings.Cut(mapping, ":")
		addr := net.JoinHostPort("127.0.0.1", local)
		for {
			c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err == nil {
				c.Close()
				break
			}
			select {
			case <-ctx.Done():
				stop("port-forward for %s is unreachable on local port %s", service, local)
			case <-f.done:
				stop("port-forward for %s exited", service)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return f
}
func (k *kubeEnvironment) closeForwards() {
	for _, f := range k.forwards {
		select {
		case <-f.done:
		default:
			syscall.Kill(-f.cmd.Process.Pid, syscall.SIGTERM)
		}
	}
	for _, f := range k.forwards {
		select {
		case <-f.done:
		case <-time.After(2 * time.Second):
			syscall.Kill(-f.cmd.Process.Pid, syscall.SIGKILL)
			<-f.done
		}
	}
	k.forwards = nil
}
