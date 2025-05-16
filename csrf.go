package csrf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
)

// Protection implements [Cross-Site Request Forgery (CSRF)] protections by
// rejecting non-safe browser requests initiated from a different origin.
//
// Cross-origin requests are detected with the [Sec-Fetch-Site] header,
// available in all browsers since 2023, or by comparing the hostname of the
// [Origin] header with the Host header.
//
// The GET, HEAD, and OPTIONS methods are [safe methods] and are always allowed.
// It's important that applications do not perform any state changing actions
// due to requests with safe methods.
//
// Requests without Sec-Fetch-Site or Origin headers are assumed to be either
// same-origin or non-browser requests, and are allowed.
//
// [Sec-Fetch-Site]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
// [Origin]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
// [Cross-Site Request Forgery (CSRF)]: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF
// [safe methods]: https://developer.mozilla.org/en-US/docs/Glossary/Safe/HTTP
type Protection struct {
	bypass    *http.ServeMux
	trustedMu sync.RWMutex
	trusted   map[string]bool
}

// New returns a new [Protection] value.
func New() *Protection {
	return &Protection{
		bypass:  http.NewServeMux(),
		trusted: make(map[string]bool),
	}
}

// AddTrustedOrigin allows all requests with an [Origin] header
// which exactly matches the given value.
//
// Origin header values are of the form "scheme://host[:port]".
//
// [Origin]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
func (c *Protection) AddTrustedOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin %q: %w", origin, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("invalid origin %q: scheme is required", origin)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid origin %q: host is required", origin)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid origin %q: path, query, and fragment are not allowed", origin)
	}
	c.trustedMu.Lock()
	defer c.trustedMu.Unlock()
	c.trusted[origin] = true
	return nil
}

var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

// AddUnsafeBypassPattern permits all requests that match the given pattern.
// The pattern syntax and precedence rules are the same as [ServeMux].
func (c *Protection) AddUnsafeBypassPattern(pattern string) {
	c.bypass.Handle(pattern, noopHandler)
}

// Check applies cross-origin checks to a request.
// It returns an error if the request should be rejected.
func (c *Protection) Check(req *http.Request) error {
	switch req.Method {
	case "GET", "HEAD", "OPTIONS":
		// Safe methods are always allowed.
		return nil
	}

	switch req.Header.Get("Sec-Fetch-Site") {
	case "":
		// No Sec-Fetch-Site header is present.
		// Fallthrough to check the Origin header.
	case "same-origin", "none":
		return nil
	default:
		if c.isRequestExempt(req) {
			return nil
		}
		return errors.New("cross-origin request detected from Sec-Fetch-Site header")
	}

	origin := req.Header.Get("Origin")
	if origin == "" {
		// Neither Sec-Fetch-Site nor Origin headers are present.
		// Either the request is same-origin or not a browser request.
		return nil
	}

	if o, err := url.Parse(origin); err == nil && o.Host == req.Host {
		// The Origin header matches the Host header.
		return nil
	}

	if c.isRequestExempt(req) {
		return nil
	}
	return fmt.Errorf("cross-origin request detected, or browser is out of date: "+
		"Sec-Fetch-Site is missing, and Origin %q does not match Host %q", origin, req.Host)
}

// isRequestExempt checks the bypasses which require taking a lock, and should
// be deferred until the last moment.
func (c *Protection) isRequestExempt(req *http.Request) bool {
	if req.Context().Value(bypassContextKey{}) != nil {
		// UnsafeBypassRequest disabled CSRF protection for this request.
		return true
	}

	if _, pattern := c.bypass.Handler(req); pattern != "" {
		// The request matches a bypass pattern.
		return true
	}

	c.trustedMu.RLock()
	defer c.trustedMu.RUnlock()
	origin := req.Header.Get("Origin")
	// The request matches a trusted origin.
	return origin != "" && c.trusted[origin]
}

// Handler returns a handler that applies cross-origin checks
// before invoking the handler h.
//
// If a request fails cross-origin checks, the request is rejected
// with a 403 Forbidden status.
func (c *Protection) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := c.Check(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// HandlerWithFailHandler returns a handler that applies cross-origin checks
// before invoking the handler h.
//
// If a request fails cross-origin checks, the request is handled with the given
// failure handler.
func (c *Protection) HandlerWithFailHandler(h http.Handler, fail http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := c.Check(r); err != nil {
			fail.ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

type bypassContextKey struct{}

// UnsafeBypassRequest disables CSRF protection for the request.
// It is generally only useful when implementing single sign-on (SSO) flows.
func UnsafeBypassRequest(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), bypassContextKey{}, true))
}
