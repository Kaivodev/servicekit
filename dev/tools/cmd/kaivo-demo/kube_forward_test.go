package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func forwardTestDriver(t *testing.T) (*driver, *kubeEnvironment) {
	t.Helper()
	k := fakeKube(t)
	// The advertised cashier port belongs to backend in this run.
	k.base, k.simPort = 9080, 19080
	d := &driver{ctx: t.Context(), demoEnvironment: k, active: &result{}, browsers: map[string]*browser{}}
	k.trace = d.traceForward
	k.launchForward = func(context.Context, string, string, []string) (*forward, error) {
		return &forward{done: make(chan struct{})}, nil
	}
	k.startForwards()
	return d, k
}

func fakeForwardHTTP(t *testing.T, send startWebhook) {
	t.Helper()
	saved := localHTTP
	localHTTP = &http.Client{Transport: send, CheckRedirect: saved.CheckRedirect, Timeout: saved.Timeout}
	t.Cleanup(func() { localHTTP = saved })
}

func forwardResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestHTTPForwardRestartBeforeDispatch(t *testing.T) {
	for _, tc := range []struct {
		name, service string
		send          func(*driver)
	}{
		{"public", "backend", func(d *driver) { d.browser("merchant").http("GET", "/", "/", "", nil, nil) }},
		{"admin", "backend", func(d *driver) { d.browser("admin").http("GET", "/", "/", "", nil, nil) }},
		{"seller", "backend", func(d *driver) { d.browser("seller").http("GET", "/", "/", "", nil, nil) }},
		{"webhook", "backend", func(d *driver) { d.postTelegram(nil, delivery{Command: "/balance"}, nil) }},
		{"tracked webhook", "backend", func(d *driver) {
			d.postTelegram(nil, delivery{Command: "/balance"}, func() error { return nil })
		}},
		{"simulator", "upstream-sim", func(d *driver) { d.sim("GET", "/__test/deliveries", nil) }},
		{"cashier", "upstream-sim", func(d *driver) { d.cashier(d.addresses().cashier+"/cashier/sample", true) }},
		{"fixtures", fixtureService, func(d *driver) { d.messages() }},
		{"mail", "mailpit", func(d *driver) { d.mailBody("recipient", "subject") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, k := forwardTestDriver(t)
			k.materials["inputs/upstream-sim/config.json"] = encoded(object{"control_token": "test-only"})
			f := k.forwards[tc.service]
			close(f.current.done)
			var services []string
			launch := k.launchForward
			k.launchForward = func(ctx context.Context, ns, service string, mappings []string) (*forward, error) {
				services = append(services, service)
				if ns != f.ns || !slices.Equal(mappings, f.mappings) {
					t.Fatal("restart lost the original namespace or port mappings")
				}
				return launch(ctx, ns, service, mappings)
			}
			calls := 0
			fakeForwardHTTP(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if f.current.exited() || k.serviceByAddress[r.URL.Host] != tc.service {
					t.Fatal("request dispatched without its live forward")
				}
				if tc.name == "cashier" && r.Host != "127.0.0.1:9080" {
					t.Fatal("cashier lost the advertised host")
				}
				if tc.name == "fixtures" {
					return forwardResponse(200, "[]"), nil
				}
				return forwardResponse(200, "{}"), nil
			})
			tc.send(d)
			tc.send(d)
			trace := "Restarted port-forward for " + tc.service
			if calls < 2 || !slices.Equal(services, []string{tc.service}) || len(d.active.Requests) == 0 || d.active.Requests[0] != trace ||
				strings.Count(strings.Join(d.active.Requests, "\n"), trace) != 1 {
				t.Fatalf("requests %d, launches %v, trace %v", calls, services, d.active.Requests)
			}
		})
	}
}

func TestBackendKeepAliveDuringFixtureWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, k := forwardTestDriver(t)
		start := time.Now()
		var probes []time.Duration
		fakeForwardHTTP(t, func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/messages.json":
				if time.Since(start) >= 95*time.Second {
					return forwardResponse(200, `[{"Deleted":true}]`), nil
				}
				return forwardResponse(200, "[]"), nil
			case "/health/live":
				if r.Method != http.MethodGet || r.URL.Host != k.local(0) || len(r.Header) != 0 || k.forwards["backend"].current.exited() {
					t.Fatal("invalid backend keep-alive")
				}
				probes = append(probes, time.Since(start))
				if len(probes) == 1 {
					return nil, errors.New("private transport detail")
				}
				return forwardResponse(503, "private response detail"), nil
			default:
				t.Fatalf("unexpected request %s", r.URL.Path)
				return nil, nil
			}
		})
		close(k.forwards["backend"].current.done)
		d.waitFor("backend deleteMessage for KEY", 6*time.Minute, func() bool {
			msgs := d.messages()
			return len(msgs) == 1 && msgs[0].Deleted
		})
		if !slices.Equal(probes, []time.Duration{30 * time.Second, 60 * time.Second, 90 * time.Second}) {
			t.Fatalf("probe times %v", probes)
		}
		if !slices.Equal(d.active.Requests, []string{"Restarted port-forward for backend", "Backend keep-alive failed",
			"Backend keep-alive failed (HTTP 503)", "Backend keep-alive failed (HTTP 503)"}) {
			t.Fatalf("unexpected trace %v", d.active.Requests)
		}
	})
}

func TestBackendKeepAliveRetriesFailedRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, k := forwardTestDriver(t)
		start := time.Now()
		close(k.forwards["backend"].current.done)
		launch := k.launchForward
		var attempts, probes []time.Duration
		k.launchForward = func(ctx context.Context, ns, service string, mappings []string) (*forward, error) {
			attempts = append(attempts, time.Since(start))
			if len(attempts) == 1 {
				return nil, errors.New("private launcher detail")
			}
			return launch(ctx, ns, service, mappings)
		}
		fakeForwardHTTP(t, func(r *http.Request) (*http.Response, error) {
			probes = append(probes, time.Since(start))
			return forwardResponse(200, "{}"), nil
		})
		d.sleep(65 * time.Second)
		if !slices.Equal(attempts, []time.Duration{30 * time.Second, 60 * time.Second}) ||
			!slices.Equal(probes, []time.Duration{60 * time.Second}) ||
			!slices.Equal(d.active.Requests, []string{"Backend keep-alive failed", "Restarted port-forward for backend"}) {
			t.Fatalf("launches %v, probes %v, trace %v", attempts, probes, d.active.Requests)
		}
	})
}

func TestBackendActivityDefersKeepAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, _ := forwardTestDriver(t)
		start := time.Now()
		var probes []time.Duration
		fakeForwardHTTP(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/health/live" {
				probes = append(probes, time.Since(start))
			}
			return forwardResponse(200, "{}"), nil
		})
		d.sleep(29 * time.Second)
		d.browser("seller").http("GET", "/sample", "/sample", "", nil, nil)
		d.sleep(35 * time.Second)
		if !slices.Equal(probes, []time.Duration{59 * time.Second}) {
			t.Fatalf("probe times %v", probes)
		}
	})
}

func TestNativeHTTPAndWaitSkipForwards(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &driver{ctx: t.Context(), demoEnvironment: nativeEnvironment{}, active: &result{}, browsers: map[string]*browser{}}
		var paths []string
		fakeForwardHTTP(t, func(r *http.Request) (*http.Response, error) {
			paths = append(paths, r.URL.Path)
			return forwardResponse(200, "{}"), nil
		})
		d.browser("merchant").http("GET", "/sample", "/sample", "", nil, nil)
		start := time.Now()
		d.waitFor("native condition", 2*time.Minute, func() bool { return time.Since(start) >= 65*time.Second })
		if !slices.Equal(paths, []string{"/sample"}) || len(d.active.Requests) != 1 {
			t.Fatalf("requests %v, trace %v", paths, d.active.Requests)
		}
	})
}
