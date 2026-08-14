// Package httpclient is the one and only place requests actually go out.
// Every engine goes through here, which means scope checks, rate limiting,
// concurrency caps and body size limits all live in one spot instead of
// being reimplemented (or forgotten) per engine.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config controls safety and behavior of the client. Zero values are safe
// (no rate limit, no concurrency cap) but callers should always set explicit
// limits when targeting anything other than DEV.
type Config struct {
	Timeout            time.Duration
	MaxRedirects       int // 0 = use http default (10); negative = no redirects followed
	Retries            int
	RetryBackoff       time.Duration
	RequestsPerSecond  float64 // 0 = unlimited
	MaxConcurrency     int     // 0 = unlimited
	MaxResponseBytes   int64   // 0 = default 2MiB
	UserAgent          string
	InsecureSkipVerify bool
	AllowedHosts       []string // if non-empty, only these hosts (suffix match) may be requested
	DeniedHosts        []string // always denied, checked after allowlist

	// ClientCertFile and ClientKeyFile are paths to PEM-encoded files for
	// mutual TLS. Both must be set together; if either is empty no client
	// cert is presented (plain TLS, no mTLS).
	ClientCertFile string
	ClientKeyFile  string
}

func (c Config) withDefaults() Config {
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = 2 << 20 // 2MiB
	}
	if c.UserAgent == "" {
		c.UserAgent = "Mantis/0.1 (+https://github.com/mantis-scanner/mantis)"
	}
	return c
}

// ErrOutOfScope is returned when a request targets a host not permitted by
// the configured allow/deny lists.
type ErrOutOfScope struct{ Host string }

func (e ErrOutOfScope) Error() string { return fmt.Sprintf("host %q is out of scope", e.Host) }

// Request is a single HTTP request to execute.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// Response captures the executed request alongside the response, unredacted.
// Callers building evidence for reports must call Redact before persisting.
type Response struct {
	Request    Request
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
	Truncated  bool
}

type Client struct {
	cfg    Config
	hc     *http.Client
	sem    chan struct{}
	rlMu   sync.Mutex
	nextAt time.Time
}

func New(cfg Config) (*Client, error) {
	cfg = cfg.withDefaults()

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("httpclient: creating cookie jar: %w", err)
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("httpclient: loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	hc := &http.Client{
		Timeout:   cfg.Timeout,
		Jar:       jar,
		Transport: transport,
	}

	switch {
	case cfg.MaxRedirects < 0:
		hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	case cfg.MaxRedirects > 0:
		hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", cfg.MaxRedirects)
			}
			return nil
		}
	}

	var sem chan struct{}
	if cfg.MaxConcurrency > 0 {
		sem = make(chan struct{}, cfg.MaxConcurrency)
	}

	return &Client{cfg: cfg, hc: hc, sem: sem}, nil
}

// InScope reports whether host is permitted by the configured allow/deny lists.
func (c *Client) InScope(host string) bool {
	host = strings.ToLower(host)
	if len(c.cfg.AllowedHosts) > 0 {
		ok := false
		for _, h := range c.cfg.AllowedHosts {
			if hostMatch(host, h) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, h := range c.cfg.DeniedHosts {
		if hostMatch(host, h) {
			return false
		}
	}
	return true
}

func hostMatch(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimPrefix(pattern, "*."))
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

func (c *Client) throttle() {
	if c.cfg.RequestsPerSecond <= 0 {
		return
	}
	interval := time.Duration(float64(time.Second) / c.cfg.RequestsPerSecond)
	c.rlMu.Lock()
	now := time.Now()
	if c.nextAt.Before(now) {
		c.nextAt = now
	}
	wait := c.nextAt.Sub(now)
	c.nextAt = c.nextAt.Add(interval)
	c.rlMu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// Do executes req with scope enforcement, rate limiting, concurrency capping
// and retry-with-backoff, and returns the captured (unredacted) response.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("httpclient: invalid URL %q: %w", req.URL, err)
	}
	if !c.InScope(u.Hostname()) {
		return nil, ErrOutOfScope{Host: u.Hostname()}
	}

	if c.sem != nil {
		c.sem <- struct{}{}
		defer func() { <-c.sem }()
	}

	var lastErr error
	attempts := c.cfg.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			backoff := c.cfg.RetryBackoff
			if backoff <= 0 {
				backoff = 500 * time.Millisecond
			}
			time.Sleep(backoff * time.Duration(attempt))
		}
		c.throttle()

		resp, err := c.doOnce(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, req Request) (*Response, error) {
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("httpclient: building request: %w", err)
	}
	httpReq.Header.Set("User-Agent", c.cfg.UserAgent)
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	start := time.Now()
	httpResp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: request failed: %w", err)
	}
	defer httpResp.Body.Close()

	limited := io.LimitReader(httpResp.Body, c.cfg.MaxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("httpclient: reading response body: %w", err)
	}
	truncated := false
	if int64(len(body)) > c.cfg.MaxResponseBytes {
		body = body[:c.cfg.MaxResponseBytes]
		truncated = true
	}

	return &Response{
		Request:    req,
		StatusCode: httpResp.StatusCode,
		Headers:    httpResp.Header,
		Body:       body,
		Duration:   time.Since(start),
		Truncated:  truncated,
	}, nil
}
