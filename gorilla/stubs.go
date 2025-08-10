package csrf

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
)

// These errors are exported for drop-in compatibility with the
// github.com/gorilla/csrf API. They are not used in this package.
var (
	ErrNoReferer  = errors.New("referer not supplied")
	ErrBadOrigin  = errors.New("origin invalid")
	ErrBadReferer = errors.New("referer invalid")
	ErrNoToken    = errors.New("CSRF token not found in request")
	ErrBadToken   = errors.New("CSRF token invalid")
)

// PlaintextHTTPContextKey is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API. It is not used by this package.
//
// Deprecated: all uses of PlaintextHTTPContextKey can be removed. The system in
// this package does not primarily rely on Origin and Referer headers, so it
// doesn't need to be informed of what protocol the request came over.
const PlaintextHTTPContextKey contextKey = "plaintext"

// PlaintextHTTPRequest is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// It actually applies the [PlaintextHTTPContextKey] context to the request, in
// case the application somehow explicitly relies on it, but this package
// doesn't use it.
//
// Deprecated: all uses of PlaintextHTTPRequest can be removed. The system in
// this package does not primarily rely on Origin and Referer headers, so it
// doesn't need to be informed of what protocol the request came over.
func PlaintextHTTPRequest(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), PlaintextHTTPContextKey, true)
	return r.WithContext(ctx)
}

// TemplateTag is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API. It is not used by this package.
var TemplateTag = "csrfField"

// Token is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API. It returns a random string, in case applications
// somehow rely on it returning a random, hard to guess value.
//
// Deprecated: all uses of Token can be removed. The system in this package
// does not rely on tokens.
func Token(r *http.Request) string {
	return rand.Text()
}

// TemplateField is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API. It returns a hidden input field with a random
// value, in case applications somehow rely on it returning a random, hard to
// guess value, or in case the server expects a specific field name in the form.
//
// Note that unlike the original github.com/gorilla/csrf package, TemplateField
// HTML-escapes the field name.
//
// Deprecated: all uses of TemplateField can be removed. The system in this
// package does not rely on tokens and doesn't require HTML tags.
func TemplateField(r *http.Request) template.HTML {
	val := r.Context().Value(fieldNameKey)
	if name, ok := val.(string); ok {
		name = html.EscapeString(name)
		t := `<input type="hidden" name="%s" value="%s">`
		return template.HTML(fmt.Sprintf(t, name, Token(r)))
	}
	return template.HTML("")
}

// FieldName is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API. It still affects [TemplateField] in case the
// server expects a specific field name in the form.
//
// Deprecated: all uses of FieldName can be removed. The system in this package
// does not rely on tokens.
func FieldName(name string) Option {
	return func(opts *options) {
		opts.FieldName = name
	}
}

// MaxAge is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of MaxAge can be removed. The system in this package
// does not rely on cookies.
func MaxAge(age int) Option {
	return func(opts *options) {}
}

// Domain is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of Domain can be removed. The system in this package
// does not rely on cookies.
func Domain(domain string) Option {
	return func(opts *options) {}
}

// Path is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of Path can be removed. The system in this package
// does not rely on cookies.
func Path(p string) Option {
	return func(opts *options) {}
}

// Secure is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of Secure can be removed. The system in this package
// does not rely on cookies.
func Secure(s bool) Option {
	return func(opts *options) {}
}

// HttpOnly is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of HttpOnly can be removed. The system in this package
// does not rely on cookies.
func HttpOnly(h bool) Option {
	return func(opts *options) {}
}

// SameSiteMode is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of SameSiteMode can be removed. The system in this
// package does not rely on cookies.
type SameSiteMode int

const (
	SameSiteDefaultMode SameSiteMode = iota + 1
	SameSiteLaxMode
	SameSiteStrictMode
	SameSiteNoneMode
)

// SameSite is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of SameSite can be removed. The system in this package
// does not rely on cookies.
func SameSite(s SameSiteMode) Option {
	return func(opts *options) {}
}

// CookieName is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of CookieName can be removed. The system in this package
// does not rely on cookies.
func CookieName(name string) Option {
	return func(opts *options) {}
}

// RequestHeader is a stub, exported for drop-in compatibility with the
// github.com/gorilla/csrf API.
//
// Deprecated: all uses of RequestHeader can be removed. The system in this
// package does not rely on tokens. Any request without Sec-Fetch-Site or Origin
// headers is assumed not to be from a browser, and is allowed.
func RequestHeader(header string) Option {
	return func(opts *options) {}
}
