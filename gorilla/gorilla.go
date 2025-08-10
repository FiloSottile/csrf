// Package csrf is a drop-in replacement for github.com/gorilla/csrf.
//
//	 import (
//	+    csrf "filippo.io/csrf/gorilla"
//	-    "github.com/gorilla/csrf"
//	 )
//
// Instead of tokens and cookies, this package uses Fetch metadata headers
// provided by modern browsers, like [the CSRF protection introduced in the
// standard library with Go 1.25].
//
// Note that tokens are completely ignored. If github.com/gorilla/csrf was
// (mis)used for security goals beyond Cross-Site Request Forgery protection,
// such as for authentication, this might be unexpected. In particular, all
// non-browser requests (those missing both Sec-Fetch-Site and Origin headers)
// are allowed, since CSRF is fundamentally a browser issue.
//
// ## Same-origin vs tokens
//
// github.com/gorilla/csrf v1.7.2 and older allowed any request as long as it
// had a valid token. v1.7.3 switched to additionally enforcing same-origin
// requests to fix [CVE-2025-24358].
//
// This package exclusively enforces same-origin requests. This means it is
// stricter than v1.7.2 (and not vulnerable to CVE-2025-24358), but more
// compatible than v1.7.3.
//
// For example, it works [with reverse-proxies], [with localhost], and with
// same-origin HTTP requests without having to use [TrustedOrigins] or
// [PlaintextHTTPRequest] (introduced in v1.7.3, and ignored by this package).
//
// ## API compatibility
//
// All github.com/gorilla/csrf v1.7.3 exported APIs are also exported by this
// package, for drop-in compatibility, but many are replaced with stubs.
//
// [Token] returns a random value which is ignored by this package.
// [TemplateField] returns an input HTML tag, which likewise is ignored by this
// package. Both are provided in case other parts of the application rely on a
// random value being present.
//
// [TrustedOrigins] accepts a list of origins, including their schema (e.g.
// "https://example.com"). For compatibility with github.com/gorilla/csrf,
// schema-less hosts (e.g. "example.com") are implicitly prefixed with
// "https://".
//
// [the CSRF protection introduced in the standard library with Go 1.25]: https://go.dev/issues/73626
// [CVE-2025-24358]: https://github.com/advisories/GHSA-rq77-p4h8-4crw
// [with reverse-proxies]: https://github.com/gorilla/csrf/issues/187
// [with localhost]: https://github.com/gorilla/csrf/issues/188
package csrf

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"filippo.io/csrf"
)

type contextKey string

const (
	fieldNameKey contextKey = "FieldName"
	errorKey     contextKey = "Error"
	skipCheckKey contextKey = "SkipCheck"
)

// Protect is an HTTP middleware that provides Cross-Site Request Forgery
// protection. See [csrf.Protection] for details.
//
// authKey is ignored and can be nil. Any options except [ErrorHandler] and
// [TrustedOrigins] are also ignored.
func Protect(authKey []byte, opts ...Option) func(http.Handler) http.Handler {
	o := &options{FieldName: "gorilla.csrf.Token"}
	for _, opt := range opts {
		opt(o)
	}
	c := csrf.New()
	for _, origin := range o.TrustedOrigins {
		if !strings.Contains(origin, "://") {
			origin = "https://" + origin
		}
		c.AddTrustedOrigin(origin)
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), fieldNameKey, o.FieldName))

			if r.Context().Value(skipCheckKey) != nil {
				h.ServeHTTP(w, r)
				return
			}

			if err := c.Check(r); err != nil {
				r = r.WithContext(context.WithValue(r.Context(), errorKey, err))
				if o.ErrorHandler != nil {
					o.ErrorHandler.ServeHTTP(w, r)
				} else {
					// Emulate gorilla's unauthorizedHandler.
					http.Error(w, fmt.Sprintf("%s - %s",
						http.StatusText(http.StatusForbidden), FailureReason(r)),
						http.StatusForbidden)
				}
				return
			}

			h.ServeHTTP(w, r)
		})
	}
}

// UnsafeSkipCheck disables CSRF protections for the request. It must be called
// before the CSRF middleware.
func UnsafeSkipCheck(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), skipCheckKey, true))
}

// FailureReason extracts the [csrf.Protection.Check] return value from the
// request context.
func FailureReason(r *http.Request) error {
	if val := r.Context().Value(errorKey); val != nil {
		return val.(error)
	}
	return nil
}

type Option func(*options)

type options struct {
	ErrorHandler   http.Handler
	TrustedOrigins []string
	FieldName      string
}

// ErrorHandler allows you to change the handler called when CSRF request
// processing encounters an invalid token or request. A typical use would be to
// provide a handler that returns a static HTML file with a HTTP 403 status. By
// default a HTTP 403 status and a plain text CSRF failure reason are served.
//
// Note that a custom error handler can also access the csrf.FailureReason(r)
// function to retrieve the CSRF validation reason from the request context.
func ErrorHandler(h http.Handler) Option {
	return func(o *options) {
		o.ErrorHandler = h
	}
}

// TrustedOrigins configures a set of origins that bypass CSRF checks.
//
// For compatibility with github.com/gorilla/csrf, the origins may omit the
// schema, in which case it will be assumed to be "https". To allow an HTTP
// origin, explicitly list it with a schema (e.g. "http://example.com") but note
// that network attackers may cause requests to be initiated from plain HTTP
// origins.
func TrustedOrigins(origins []string) Option {
	return func(o *options) {
		o.TrustedOrigins = origins
	}
}
