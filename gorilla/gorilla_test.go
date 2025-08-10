package csrf_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	csrf "filippo.io/csrf/gorilla"
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

func TestProtectBasicFunctionality(t *testing.T) {
	middleware := csrf.Protect(nil)
	handler := middleware(okHandler)

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

func TestProtectWithTrustedOrigins(t *testing.T) {
	// Test TrustedOrigins option with automatic https:// prefix
	middleware := csrf.Protect(nil, csrf.TrustedOrigins([]string{
		"trusted.example",
		"https://explicit.example",
		"port.example:8000",
		"http://plaintext.example",
	}))
	handler := middleware(okHandler)

	tests := []struct {
		name           string
		origin         string
		secFetchSite   string
		expectedStatus int
	}{
		{"trusted origin without scheme", "https://trusted.example", "", http.StatusOK},
		{"trusted origin with cross-site", "https://trusted.example", "cross-site", http.StatusOK},
		{"explicit https origin", "https://explicit.example", "cross-site", http.StatusOK},
		{"port origin with auto https", "https://port.example:8000", "cross-site", http.StatusOK},
		{"explicit http origin", "http://plaintext.example", "cross-site", http.StatusOK},
		{"untrusted origin", "https://attacker.example", "cross-site", http.StatusForbidden},
		// Test that http:// is rejected for origins that should get https:// prefix
		{"http rejected for trusted.example", "http://trusted.example", "cross-site", http.StatusForbidden},
		{"http rejected for explicit.example", "http://explicit.example", "cross-site", http.StatusForbidden},
		{"http rejected for port.example", "http://port.example:8000", "cross-site", http.StatusForbidden},
		{"https rejected for plaintext.example", "https://plaintext.example", "cross-site", http.StatusForbidden},
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

func TestProtectWithErrorHandler(t *testing.T) {
	customErrHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "custom error")
	})

	middleware := csrf.Protect(nil, csrf.ErrorHandler(customErrHandler))
	handler := middleware(okHandler)

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
}

func TestUnsafeSkipCheck(t *testing.T) {
	middleware := csrf.Protect(nil)
	handler := middleware(okHandler)

	tests := []struct {
		name           string
		skip           bool
		secFetchSite   string
		expectedStatus int
	}{
		{"skipped cross-site request", true, "cross-site", http.StatusOK},
		{"not skipped cross-site request", false, "cross-site", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptestNewRequest("POST", "https://example.com/")
			req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)

			if tc.skip {
				req = csrf.UnsafeSkipCheck(req)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("got status %d, want %d", w.Code, tc.expectedStatus)
			}
		})
	}
}

func TestFailureReason(t *testing.T) {
	middleware := csrf.Protect(nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for CSRF failure")
	}))

	req := httptestNewRequest("POST", "https://example.com/")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", w.Code, http.StatusForbidden)
	}

	customErrHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := csrf.FailureReason(r)
		if err == nil {
			t.Error("FailureReason should return an error")
			return
		}
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, err.Error())
	})

	middleware2 := csrf.Protect(nil, csrf.ErrorHandler(customErrHandler))
	handler2 := middleware2(okHandler)

	w2 := httptest.NewRecorder()
	handler2.ServeHTTP(w2, req)

	if w2.Code != http.StatusTeapot {
		t.Errorf("got status %d, want %d", w2.Code, http.StatusTeapot)
	}

	if w2.Body.String() == "" {
		t.Error("expected error message in response body")
	}

	reqOk := httptestNewRequest("GET", "https://example.com/")
	handlerOk := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := csrf.FailureReason(r)
		if err != nil {
			t.Errorf("FailureReason should return nil for successful request, got: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))

	w3 := httptest.NewRecorder()
	handlerOk.ServeHTTP(w3, reqOk)

	if w3.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w3.Code, http.StatusOK)
	}
}

func TestToken(t *testing.T) {
	req := httptestNewRequest("GET", "https://example.com/")
	token1 := csrf.Token(req)
	token2 := csrf.Token(req)

	if token1 == "" {
		t.Error("Token should return a non-empty string")
	}
	if token1 == token2 {
		t.Error("Token should return different values on subsequent calls")
	}
}

func TestTemplateField(t *testing.T) {
	// Test with default field name
	middleware := csrf.Protect(nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		field := csrf.TemplateField(r)
		fieldStr := string(field)

		if fieldStr == "" {
			t.Error("TemplateField should return a non-empty HTML string")
			return
		}

		// Should contain an input tag
		if !strings.Contains(fieldStr, "<input") {
			t.Errorf("TemplateField should contain input tag, got: %s", fieldStr)
			return
		}

		// Should contain the default field name
		if !strings.Contains(fieldStr, "gorilla.csrf.Token") {
			t.Errorf("TemplateField should contain default field name, got: %s", fieldStr)
			return
		}

		// Should have type="hidden"
		if !strings.Contains(fieldStr, `type="hidden"`) {
			t.Errorf("TemplateField should have hidden type, got: %s", fieldStr)
			return
		}

		// Should have a value attribute with some content
		if !strings.Contains(fieldStr, `value="`) {
			t.Errorf("TemplateField should have value attribute, got: %s", fieldStr)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	req := httptestNewRequest("GET", "https://example.com/")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestTemplateFieldWithCustomFieldName(t *testing.T) {
	// Test with custom field name
	customFieldName := "my-custom-token"
	middleware := csrf.Protect(nil, csrf.FieldName(customFieldName))
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		field := csrf.TemplateField(r)
		fieldStr := string(field)

		if fieldStr == "" {
			t.Error("TemplateField should return a non-empty HTML string")
			return
		}

		// Should contain the custom field name
		if !strings.Contains(fieldStr, customFieldName) {
			t.Errorf("TemplateField should contain custom field name %q, got: %s", customFieldName, fieldStr)
			return
		}

		// Should NOT contain the default field name
		if strings.Contains(fieldStr, "gorilla.csrf.Token") {
			t.Errorf("TemplateField should not contain default field name when custom is set, got: %s", fieldStr)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	req := httptestNewRequest("GET", "https://example.com/")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestTemplateFieldHTMLEscaping(t *testing.T) {
	// Test that field name is properly HTML escaped
	maliciousFieldName := `">'><script>alert('xss')</script>`
	middleware := csrf.Protect(nil, csrf.FieldName(maliciousFieldName))
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		field := csrf.TemplateField(r)
		fieldStr := string(field)

		// Should escape the malicious content
		if strings.Contains(fieldStr, "<script>") {
			t.Errorf("TemplateField should HTML-escape field name, got: %s", fieldStr)
			return
		}

		// Should contain escaped version
		if !strings.Contains(fieldStr, "&gt;") {
			t.Errorf("TemplateField should contain HTML-escaped content, got: %s", fieldStr)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	req := httptestNewRequest("GET", "https://example.com/")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestTemplateFieldWithoutMiddleware(t *testing.T) {
	// Test TemplateField when called outside of middleware context
	req := httptestNewRequest("GET", "https://example.com/")
	field := csrf.TemplateField(req)
	fieldStr := string(field)

	// Should return empty HTML when no context is set
	if fieldStr != "" {
		t.Errorf("TemplateField should return empty string when called outside middleware context, got: %s", fieldStr)
	}
}

func TestAllIgnoredOptions(t *testing.T) {
	// Test that all the stub options are indeed ignored and don't affect behavior.
	middleware := csrf.Protect([]byte("some-key-that-should-be-ignored"),
		// All these options should be ignored:
		csrf.MaxAge(3600),
		csrf.Domain("example.com"),
		csrf.Path("/some/path"),
		csrf.Secure(true),
		csrf.HttpOnly(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.CookieName("custom-csrf-cookie"),
		csrf.RequestHeader("X-CSRF-Token"),
		// These should still work:
		csrf.TrustedOrigins([]string{"trusted.example"}),
	)
	handler := middleware(okHandler)

	tests := []struct {
		name           string
		method         string
		secFetchSite   string
		origin         string
		expectedStatus int
	}{
		// Basic functionality should still work despite ignored options
		{"cross-site blocked despite ignored options", "POST", "cross-site", "", http.StatusForbidden},
		{"same-origin allowed despite ignored options", "POST", "same-origin", "", http.StatusOK},
		{"trusted origin works despite ignored options", "POST", "cross-site", "https://trusted.example", http.StatusOK},
		{"safe methods work despite ignored options", "GET", "cross-site", "", http.StatusOK},
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

	// Test that FieldName option still affects TemplateField even with other ignored options
	middleware2 := csrf.Protect(nil,
		csrf.FieldName("custom-field"),
		// These should be ignored:
		csrf.MaxAge(7200),
		csrf.CookieName("ignored-cookie"),
	)
	handler2 := middleware2(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		field := csrf.TemplateField(r)
		fieldStr := string(field)

		if !strings.Contains(fieldStr, "custom-field") {
			t.Errorf("FieldName should still work with ignored options, got: %s", fieldStr)
		}

		w.WriteHeader(http.StatusOK)
	}))

	req := httptestNewRequest("GET", "https://example.com/")
	w := httptest.NewRecorder()
	handler2.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
}
