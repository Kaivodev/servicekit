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

type serviceForward struct {
	ns       string
	mappings []string
	current  *forward
}

func (f *forward) exited() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

func (k *kubeEnvironment) ensureForward(ctx context.Context, service string) (bool, error) {
	f := k.forwards[service]
	if f == nil || !f.current.exited() {
		return false, nil
	}
	current, err := k.launchForward(ctx, f.ns, service, f.mappings)
	if err != nil {
		return false, err
	}
	f.current = current
	k.trace("Restarted port-forward for " + service)
	return true, nil
}

func (k *kubeEnvironment) startForwards() {
	for _, s := range []struct {
		domain, service string
		mappings        []string
	}{
		{"business", "backend", []string{fmt.Sprintf("%d:8080", k.base), fmt.Sprintf("%d:8081", k.base+1), fmt.Sprintf("%d:8082", k.base+2)}},
		{"sim", "upstream-sim", []string{fmt.Sprintf("%d:9080", k.simPort)}},
		{"sim", "mailpit", []string{fmt.Sprintf("%d:8025", k.base+3)}},
		{"sim", fixtureService, []string{fmt.Sprintf("%d:8088", k.base+4)}},
		{"business", "business-pg-rw", []string{fmt.Sprintf("%d:5432", k.base+5)}},
		{"ledger", "ledger-pg-rw", []string{fmt.Sprintf("%d:5432", k.base+6)}},
		{"reconciliation", "reconciliation-pg-rw", []string{fmt.Sprintf("%d:5432", k.base+7)}},
	} {
		ns := k.namespaces[s.domain]
		current, err := k.launchForward(k.ctx, ns, s.service, s.mappings)
		check(err)
		k.forwards[s.service] = &serviceForward{ns, s.mappings, current}
		for _, mapping := range s.mappings {
			port, _, _ := strings.Cut(mapping, ":")
			k.serviceByAddress[net.JoinHostPort("127.0.0.1", port)] = s.service
		}
		if s.service == "backend" {
			k.lastBackend = time.Now()
		}
	}
}

func (k *kubeEnvironment) forward(parent context.Context, ns, service string, mappings []string) (*forward, error) {
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
			if !time.Now().Before(deadline) {
				return nil, fmt.Errorf("local port %s already in use", local)
			}
			select {
			case <-parent.Done():
				return nil, parent.Err()
			case <-time.After(250 * time.Millisecond):
			}
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
	if e != nil {
		return nil, e
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start port-forward for %s", service)
	}
	f := &forward{cmd, make(chan struct{})}
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
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	select {
	case <-ready:
	case <-f.done:
		return nil, fmt.Errorf("port-forward for %s exited before binding %s", service, strings.Join(mappings, ","))
	case <-ctx.Done():
		f.close()
		return nil, fmt.Errorf("port-forward for %s did not become ready", service)
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
				f.close()
				return nil, fmt.Errorf("port-forward for %s is unreachable on local port %s", service, local)
			case <-f.done:
				return nil, fmt.Errorf("port-forward for %s exited", service)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return f, nil
}

func (f *forward) close() {
	if f.exited() {
		return
	}
	syscall.Kill(-f.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		syscall.Kill(-f.cmd.Process.Pid, syscall.SIGKILL)
		<-f.done
	}
}

func (k *kubeEnvironment) closeForwards() {
	for _, f := range k.forwards {
		f.current.close()
	}
	clear(k.forwards)
	clear(k.serviceByAddress)
	k.lastBackend = time.Time{}
}
