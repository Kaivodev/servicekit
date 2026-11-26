// Package gcp adapts Cloud KMS REST v1 keys to servicekit signing and sealing.
// New uses Application Default Credentials, including external account files
// with service account impersonation. Signing keys pin a version. Symmetric
// keys follow the primary version for encryption.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	scope       = "https://www.googleapis.com/auth/cloudkms"
	maxResponse = 64 << 10
	authTimeout = 10 * time.Second
)

type settings struct {
	http     *http.Client
	endpoint string
	timeout  time.Duration
	attempts int
}

// Option configures a KMS client.
type Option func(*settings)

// WithHTTPClient supplies an already authenticated client and skips ADC.
func WithHTTPClient(client *http.Client) Option {
	if client == nil {
		return nil
	}
	return func(s *settings) { s.http = client }
}

// WithEndpoint overrides the HTTPS API root.
func WithEndpoint(endpoint string) Option { return func(s *settings) { s.endpoint = endpoint } }

// WithTimeout sets the deadline for each KMS attempt. Token exchanges use at
// least ten seconds per request and are shared across attempts.
func WithTimeout(timeout time.Duration) Option { return func(s *settings) { s.timeout = timeout } }

// WithMaxAttempts sets the total number of attempts per operation.
func WithMaxAttempts(n int) Option { return func(s *settings) { s.attempts = n } }

// Client is safe for concurrent use.
type Client struct {
	settings
	auth *credentials
}

// New opens the REST client. Calls default to four attempts of two seconds.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	s := settings{endpoint: "https://cloudkms.googleapis.com/", timeout: 2 * time.Second, attempts: 4}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("invalid KMS option")
		}
		opt(&s)
	}
	base, err := url.Parse(s.endpoint)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return nil, errors.New("invalid KMS HTTPS endpoint")
	}
	if s.timeout <= 0 || s.attempts < 1 {
		return nil, errors.New("invalid KMS retry configuration")
	}
	s.endpoint = strings.TrimRight(base.String(), "/") + "/v1/"
	c := &Client{settings: s}
	if c.http == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// ADC retains this context for future STS and impersonation requests.
		// Bound those exchanges independently of the constructing caller. A
		// refresh makes two sequential HTTPS exchanges, so it gets a longer limit
		// than one KMS attempt; attempts keep waiting on the shared refresh.
		base, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
		if base == nil {
			base = &http.Client{Transport: newTransport()}
		}
		authHTTP := &http.Client{Transport: base.Transport, Timeout: max(s.timeout, authTimeout), CheckRedirect: rejectRedirect}
		authCtx := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, authHTTP)
		adc, err := google.FindDefaultCredentials(authCtx, scope)
		if err != nil {
			return nil, errors.New("load KMS credentials failed")
		}
		c.auth = &credentials{source: adc.TokenSource}
		c.http = base
	}
	// A redirect could forward the request body to a different host or scheme.
	c.http = &http.Client{
		Transport:     c.http.Transport,
		Timeout:       c.http.Timeout,
		Jar:           c.http.Jar,
		CheckRedirect: rejectRedirect,
	}
	return c, nil
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// newTransport keeps KMS connections in their own pool. A proxy or NAT can
// drop an idle connection without a reset, and a call on it then waits for its
// whole attempt deadline. HTTP/2 pings every 15 s keep middleboxes from
// expiring a warm connection and close one that stopped answering. A warm
// connection matters on request paths with small budgets (IAM signs each
// assertion), so idle connections stay pooled for five minutes.
func newTransport() http.RoundTripper {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport // A process that replaced the default keeps it.
	}
	t = t.Clone()
	t.IdleConnTimeout = 5 * time.Minute
	t.HTTP2 = &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 5 * time.Second}
	return t
}

// TokenSource has no per-call context. Share a single refresh while allowing
// individual KMS attempts to stop waiting at their deadline.
type credentials struct {
	mu      sync.Mutex
	source  oauth2.TokenSource
	token   *oauth2.Token
	pending *refresh
}

type refresh struct {
	done  chan struct{}
	token *oauth2.Token
	err   error
}

func (c *credentials) get(ctx context.Context) (*oauth2.Token, error) {
	c.mu.Lock()
	if c.token.Valid() {
		token := c.token
		c.mu.Unlock()
		return token, nil
	}
	r := c.pending
	if r == nil {
		r = &refresh{done: make(chan struct{})}
		c.pending = r
		go func() {
			token, err := c.source.Token()
			c.mu.Lock()
			defer c.mu.Unlock()
			r.token, r.err = token, err
			if err == nil {
				c.token = token
			}
			c.pending = nil
			close(r.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.done:
		return r.token, r.err
	}
}

type callError struct {
	op     string
	status int
	cause  error
}

func (e callError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("KMS %s failed (HTTP %d)", e.op, e.status)
	}
	return "KMS " + e.op + " failed"
}
func (e callError) Unwrap() error { return e.cause }

func (c *Client) call(ctx context.Context, op, path string, input, output any) error {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return callError{op: op}
		}
	}
	delay := 200 * time.Millisecond
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return callError{op: op, cause: err}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, c.timeout)
		retry, err := c.attempt(attemptCtx, op, path, body, output)
		cancel()
		if ctx.Err() != nil {
			return callError{op: op, cause: ctx.Err()}
		}
		if !retry || attempt >= c.attempts {
			return err
		}
		// A timed-out or broken request can leave its connection pooled. The
		// retry must not wait on the same connection, so dial a fresh one.
		c.http.CloseIdleConnections()
		// Equal jitter keeps retries apart while capping the delay at 1 s.
		wait := time.NewTimer(delay/2 + rand.N(delay/2))
		select {
		case <-ctx.Done():
			wait.Stop()
			return callError{op: op, cause: ctx.Err()}
		case <-wait.C:
		}
		delay = min(2*delay, time.Second)
	}
}

func (c *Client) attempt(ctx context.Context, op, path string, body []byte, output any) (bool, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return false, callError{op: op}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.auth != nil {
		token, err := c.auth.get(ctx)
		if err != nil || !token.Valid() {
			failure := callError{op: op, cause: ctx.Err()}
			var retrieval *oauth2.RetrieveError
			if errors.As(err, &retrieval) && retrieval.Response != nil {
				failure.status = retrieval.Response.StatusCode
				return retryStatus(failure.status), failure
			}
			var network net.Error
			return errors.As(err, &network), failure
		}
		token.SetAuthHeader(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return true, callError{op: op, cause: ctx.Err()}
	}
	defer resp.Body.Close()
	failure := callError{op: op, status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		return retryStatus(resp.StatusCode), failure
	}
	if resp.ContentLength > maxResponse {
		return false, failure
	}
	reader := &io.LimitedReader{R: resp.Body, N: maxResponse}
	data, err := io.ReadAll(reader)
	defer clear(data)
	if err != nil {
		failure.cause = ctx.Err()
		return true, failure
	}
	// An unframed body reaching the limit has no proven end within the budget.
	if reader.N == 0 && resp.ContentLength != maxResponse {
		return false, failure
	}
	if json.Unmarshal(data, output) != nil {
		return false, failure
	}
	return false, nil
}

func retryStatus(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}
