// Package gateway implements the single-binary reverse proxy that load
// balances the API instances. Requests and responses are buffered so a
// connection failure or a 502/503/504 from one instance can be transparently
// retried against another before any bytes reach the client. POST
// idempotency is additionally enforced server-side via requestId/commandId,
// so replaying an accepted-but-interrupted request is always safe.
package gateway

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// maxBufferedBody caps how much request/response body the proxy buffers for a
// retry attempt (the API enforces a 4 MiB request limit by default).
const maxBufferedBody = 8 << 20

// Proxy round-robins across several upstream base URLs.
type Proxy struct {
	targets []*url.URL
	next    uint64
	log     *slog.Logger
	client  *http.Client
}

// New parses "http://a:8080,http://b:8080" style upstream lists.
func New(upstreamCSV string, log *slog.Logger) (*Proxy, error) {
	parts := strings.Split(upstreamCSV, ",")
	targets := make([]*url.URL, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		u, err := url.Parse(p)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, errors.New("invalid upstream URL: " + p)
		}
		targets = append(targets, u)
	}
	if len(targets) == 0 {
		return nil, errors.New("gateway requires at least one upstream URL")
	}
	return &Proxy{
		targets: targets,
		log:     log,
		client: &http.Client{
			// No global timeout: long-poll /wait may legitimately block for
			// up to 30s. Per-request context (client disconnect) bounds it.
			Timeout: 0,
			Transport: &http.Transport{
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 40 * time.Second,
			},
		},
	}, nil
}

// Handler returns the proxying http.Handler.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","role":"gateway"}`))
			return
		}

		var reqBody []byte
		if r.Body != nil {
			b, err := io.ReadAll(io.LimitReader(r.Body, maxBufferedBody+1))
			if err != nil {
				http.Error(w, `{"error":{"code":"request_body_too_large"}}`, http.StatusRequestEntityTooLarge)
				return
			}
			if len(b) > maxBufferedBody {
				http.Error(w, `{"error":{"code":"request_body_too_large"}}`, http.StatusRequestEntityTooLarge)
				return
			}
			reqBody = b
		}

		var lastErr error
		for attempt := 0; attempt < len(p.targets); attempt++ {
			if r.Context().Err() != nil {
				return
			}
			idx := (atomic.AddUint64(&p.next, 1) - 1) % uint64(len(p.targets))
			target := p.targets[idx]

			upReq, err := http.NewRequestWithContext(r.Context(), r.Method,
				target.String()+strings.TrimPrefix(r.URL.RequestURI(), ""), bytes.NewReader(reqBody))
			if err != nil {
				lastErr = err
				continue
			}
			copyHeaders(upReq.Header, r.Header)
			upReq.Host = r.Host

			resp, err := p.client.Do(upReq)
			if err != nil {
				p.log.Warn("upstream request failed, retrying",
					"upstream", target.String(), "attempt", attempt, "error", err)
				lastErr = err
				continue
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxBufferedBody+1))
			_ = resp.Body.Close()
			if err != nil {
				lastErr = err
				continue
			}
			if len(body) > maxBufferedBody {
				http.Error(w, `{"error":{"code":"response_body_too_large"}}`, http.StatusBadGateway)
				return
			}
			if resp.StatusCode == http.StatusBadGateway ||
				resp.StatusCode == http.StatusServiceUnavailable ||
				resp.StatusCode == http.StatusGatewayTimeout {
				p.log.Warn("upstream returned retryable status",
					"upstream", target.String(), "status", resp.StatusCode, "attempt", attempt)
				lastErr = errors.New("upstream status " + http.StatusText(resp.StatusCode))
				continue
			}

			for k, vs := range resp.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			return
		}
		p.log.Error("all upstreams failed", "error", lastErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"code":"all_upstreams_unavailable","message":"no API instance could serve the request"}}`))
	})
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		// Host is carried separately; Connection hop-by-hop is managed by the
		// transport.
		if strings.EqualFold(k, "Connection") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

var _ = time.Second
