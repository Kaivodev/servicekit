package marketdata

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockClock(start time.Time) clock {
	origin := time.Now()
	now := func() time.Time { return start.Add(time.Since(origin)) }
	return clock{now: now, jitter: func() time.Duration { return 9 * time.Second }, waitUntil: func(ctx context.Context, t time.Time) bool {
		timer := time.NewTimer(t.Sub(now()))
		defer timer.Stop()
		select {
		case <-timer.C:
			return ctx.Err() == nil
		case <-ctx.Done():
			return false
		}
	}}
}

func TestRunAlignedStartup(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		source                    Source
		offset, delay, wantMinute time.Duration
	}{
		{"early", OKX, time.Second, 8 * time.Second, 0},
		{"after-jitter", OKX, 39 * time.Second, 0, 0},
		{"at-cutoff", OKX, 40 * time.Second, 29 * time.Second, time.Minute},
		{"five-eligible", Kraken, 5*time.Minute + 10*time.Second, 0, 5 * time.Minute},
		{"five-ineligible", Kraken, time.Minute, 4*time.Minute + 9*time.Second, 5 * time.Minute},
		{"five-cutoff", Kraken, 40 * time.Second, 4*time.Minute + 29*time.Second, 5 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fixture(t, tc.source)
			synctest.Test(t, func(t *testing.T) {
				s := &records{}
				c := newCollector(t, testConfig(t), single(tc.source), s, nil, io.Discard)
				c.clock = mockClock(testMinute.Add(tc.offset))
				c.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
				})
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- c.Run(ctx) }()
				synctest.Wait()
				if tc.delay > 0 {
					time.Sleep(tc.delay - time.Nanosecond)
					synctest.Wait()
					if len(s.all()) != 0 {
						t.Fatal("fetched early")
					}
					time.Sleep(time.Nanosecond)
					synctest.Wait()
				}
				rs := s.all()
				if len(rs) != 1 || !rs[0].Minute.Equal(testMinute.Add(tc.wantMinute)) || rs[0].Minute.Location() != time.UTC || rs[0].Outcome != OK {
					t.Fatal(rs)
				}
				every := single(tc.source).Every
				time.Sleep(testMinute.Add(tc.wantMinute + every + 9*time.Second).Sub(c.clock.now()))
				synctest.Wait()
				rs = s.all()
				if len(rs) != 2 || rs[1].Minute.Sub(rs[0].Minute) != every {
					t.Fatal(rs)
				}
				cancel()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestOverlappingMinutes(t *testing.T) {
	bodies := map[string][]byte{"www.okx.com": fixture(t, OKX), "p2p.binance.com": fixture(t, Binance)}
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		seen := map[time.Time]map[Source]int{}
		gate := make(chan struct{})
		s := sinkFunc(func(_ context.Context, r Result) error {
			mu.Lock()
			if seen[r.Minute] == nil {
				seen[r.Minute] = map[Source]int{}
			}
			seen[r.Minute][r.Source]++
			mu.Unlock()
			if r.Minute.Equal(testMinute) && r.Source == OKX {
				<-gate
			}
			return nil
		})
		c := newCollector(t, testConfig(t), Schedule{Sources: []Source{OKX, Binance}, Pair: [2]Source{OKX, Binance}, Every: time.Minute}, s, nil, io.Discard)
		c.clock = mockClock(testMinute)
		c.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(bodies[r.URL.Host]))}, nil
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if err := c.Run(ctx); err == nil {
			t.Fatal("second Run allowed")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		for _, m := range []time.Time{testMinute, testMinute.Add(time.Minute)} {
			for _, source := range []Source{OKX, Binance} {
				if seen[m][source] != 1 {
					t.Fatalf("%s %s calls=%d", m, source, seen[m][source])
				}
			}
		}
		close(gate)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestJitterBounds(t *testing.T) {
	c := realClock()
	for range 1000 {
		d := c.jitter()
		if d < 5*time.Second || d > 15*time.Second {
			t.Fatal(d)
		}
	}
}

func TestRequestDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testConfig(t)
		cfg.RequestTimeout = time.Second
		c := newCollector(t, cfg, single(OKX), &records{}, nil, io.Discard)
		c.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		start := time.Now()
		r := c.fetch(t.Context(), OKX, start.UTC().Truncate(time.Minute), 1)
		if r.Outcome != TransportError || r.Raw != nil || time.Since(start) != time.Second {
			t.Fatal(r, time.Since(start))
		}
	})
}
