package csrf_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/csrf"
)

// httptestNewRequest works around https://go.dev/issue/73151.
func httptestNewRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.URL.Scheme = ""
	req.URL.Host = ""
	return req
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestSecFetchSite(t *testing.T) {
	protection := csrf.New()
	handler := protection.Handler(okHandler)

	tests := []struct {
		name           string
		method         string
		secFetchSite   string
		origin         string
		expectedStatus int
	}{
		{"same-origin allowed", "POST", "same-origin", "", http.StatusOK},
		{"none allowed", "POST", "none", "", http.StatusOK},
		{"cross-site blocked", "POST", "cross-site", "", http.StatusForbidden},
		{"same-site blocked", "POST", "same-site", "", http.StatusForbidden},

		{"no header with no origin", "POST", "", "", http.StatusOK},
		{"no header with matching origin", "POST", "", "https://example.com", http.StatusOK},
		{"no header with mismatched origin", "POST", "", "https://attacker.example", http.StatusForbidden},
		{"no header with null origin", "POST", "", "null", http.StatusForbidden},

		{"GET allowed", "GET", "cross-site", "", http.StatusOK},
		{"HEAD allowed", "HEAD", "cross-site", "", http.StatusOK},
		{"OPTIONS allowed", "OPTIONS", "cross-site", "", http.StatusOK},
		{"PUT blocked", "PUT", "cross-site", "", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptestNewRequest(tc.method, "https://example.com/")
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("got status %d, want %d", w.Code, tc.expectedStatus)
			}
		})
	}
}

func TestTrustedOriginBypass(t *testing.T) {
	protection := csrf.New()
	err := protection.AddTrustedOrigin("https://trusted.example")
	if err != nil {
		t.Fatalf("AddTrustedOrigin: %v", err)
	}
	handler := protection.Handler(okHandler)

	tests := []struct {
		name           string
		origin         string
		secFetchSite   string
		expectedStatus int
	}{
		{"trusted origin without sec-fetch-site", "https://trusted.example", "", http.StatusOK},
		{"trusted origin with cross-site", "https://trusted.example", "cross-site", http.StatusOK},
		{"untrusted origin without sec-fetch-site", "https://attacker.example", "", http.StatusForbidden},
		{"untrusted origin with cross-site", "https://attacker.example", "cross-site", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptestNewRequest("POST", "https://example.com/")
			req.Header.Set("Origin", tc.origin)
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("got status %d, want %d", w.Code, tc.expectedStatus)
			}
		})
	}
}

func TestPatternBypass(t *testing.T) {
	protection := csrf.New()
	protection.AddUnsafeBypassPattern("/bypass/")
	protection.AddUnsafeBypassPattern("/only/{foo}")
	handler := protection.Handler(okHandler)

	tests := []struct {
		name           string
		path           string
		secFetchSite   string
		expectedStatus int
	}{
		{"bypass path without sec-fetch-site", "/bypass/", "", http.StatusOK},
		{"bypass path with cross-site", "/bypass/", "cross-site", http.StatusOK},
		{"non-bypass path without sec-fetch-site", "/api/", "", http.StatusForbidden},
		{"non-bypass path with cross-site", "/api/", "cross-site", http.StatusForbidden},

		{"redirect to bypass path without ..", "/foo/../bypass/bar", "", http.StatusOK},
		{"redirect to bypass path with trailing slash", "/bypass", "", http.StatusOK},
		{"redirect to non-bypass path with ..", "/foo/../api/bar", "", http.StatusForbidden},
		{"redirect to non-bypass path with trailing slash", "/api", "", http.StatusForbidden},

		{"wildcard bypass", "/only/123", "", http.StatusOK},
		{"non-wildcard", "/only/123/foo", "", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptestNewRequest("POST", "https://example.com"+tc.path)
			req.Header.Set("Origin", "https://attacker.example")
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("got status %d, want %d", w.Code, tc.expectedStatus)
			}
		})
	}
}

func TestUnsafeBypassRequest(t *testing.T) {
	protection := csrf.New()
	handler := protection.Handler(okHandler)

	tests := []struct {
		name           string
		bypass         bool
		secFetchSite   string
		expectedStatus int
	}{
		{"bypassed with cross-site", true, "cross-site", http.StatusOK},
		{"not bypassed with cross-site", false, "cross-site", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptestNewRequest("POST", "https://example.com/")
			req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)

			if tc.bypass {
				req = csrf.UnsafeBypassRequest(req)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("got status %d, want %d", w.Code, tc.expectedStatus)
			}
		})
	}
}

func TestHandlerWithError(t *testing.T) {
	protection := csrf.New()

	customErrHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "custom error")
	})

	handler := protection.HandlerWithFailHandler(okHandler, customErrHandler)

	req := httptestNewRequest("POST", "https://example.com/")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("got status %d, want %d", w.Code, http.StatusTeapot)
	}

	if !strings.Contains(w.Body.String(), "custom error") {
		t.Errorf("expected custom error message, got: %q", w.Body.String())
	}

	req = httptestNewRequest("GET", "https://example.com/")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestAddTrustedOriginErrors(t *testing.T) {
	protection := csrf.New()

	tests := []struct {
		name    string
		origin  string
		wantErr bool
	}{
		{"valid origin", "https://example.com", false},
		{"valid origin with port", "https://example.com:8080", false},
		{"http origin", "http://example.com", false},
		{"missing scheme", "example.com", true},
		{"missing host", "https://", true},
		{"trailing slash", "https://example.com/", true},
		{"with path", "https://example.com/path", true},
		{"with query", "https://example.com?query=value", true},
		{"with fragment", "https://example.com#fragment", true},
		{"invalid url", "https://ex ample.com", true},
		{"empty string", "", true},
		{"null", "null", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protection.AddTrustedOrigin(tc.origin)
			if (err != nil) != tc.wantErr {
				t.Errorf("AddTrustedOrigin(%q) error = %v, wantErr %v", tc.origin, err, tc.wantErr)
			}
		})
	}
}

func TestCantModifyAfterUse(t *testing.T) {
	protection := csrf.New()
	req := httptestNewRequest("POST", "https://example.com/")
	_ = protection.Check(req)
	if err := protection.AddTrustedOrigin("https://example.com/"); err == nil {
		t.Errorf("trusted origin added after use")
	}
	if err := protection.AddUnsafeBypassPattern("/api/"); err == nil {
		t.Errorf("bypass add after use")
	}
}
