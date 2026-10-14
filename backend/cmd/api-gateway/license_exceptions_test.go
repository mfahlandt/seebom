package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/rulesource"
)

func TestLicenseExceptionsHandler(t *testing.T) {
	const empty = `{"blanketExceptions":[],"exceptions":[]}`
	const full = `{"blanketExceptions":[],"exceptions":[{"id":"own-rule","package":"library","license":"MPL-2.0","status":"approved"}]}`
	for _, tt := range []struct {
		name, primary, fallback string
		status, rules           int
	}{
		{"missing", "", "", http.StatusOK, 0},
		{"empty primary overrides fallback", empty, full, http.StatusOK, 0},
		{"configured", full, "", http.StatusOK, 1},
		{"missing primary uses fallback", "", full, http.StatusOK, 1},
		{"invalid primary", `{`, full, http.StatusInternalServerError, 0},
		{"incorrect template keys", `{"blanket_exceptions":[],"exceptions":[]}`, full, http.StatusInternalServerError, 0},
		{"invalid fallback", "", `{`, http.StatusInternalServerError, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			paths := []string{filepath.Join(dir, "primary.json"), filepath.Join(dir, "fallback.json")}
			for i, content := range []string{tt.primary, tt.fallback} {
				if content != "" {
					if err := os.WriteFile(paths[i], []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			w := serveExceptions(t, rulesFromPaths(t, paths...))
			if w.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tt.status, w.Body.String())
			}
			if tt.status != http.StatusOK {
				return
			}
			var response map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if string(response["blanketExceptions"]) != "[]" {
				t.Fatalf("expected camelCase blanketExceptions array: %s", w.Body.String())
			}
			var rules []json.RawMessage
			if err := json.Unmarshal(response["exceptions"], &rules); err != nil {
				t.Fatal(err)
			}
			if len(rules) != tt.rules {
				t.Fatalf("got %d rules, want %d", len(rules), tt.rules)
			}
		})
	}
}

func rulesFromPaths(t *testing.T, paths ...string) *license.ExceptionsWatcher {
	t.Helper()
	rules, err := watchExceptions(context.Background(), rulesource.Options{Paths: paths}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func serveExceptions(t *testing.T, rules *license.ExceptionsWatcher) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	licenseExceptionsHandler(rules).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/license-exceptions", nil))
	return w
}

// A ConfigMap edit reaches a running gateway: no restart, no rollout.
func TestLicenseExceptionsHandlerFollowsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "license-exceptions.json")
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"blanketExceptions":[],"exceptions":[]}`)
	rules := rulesFromPaths(t, path)

	write(`{"blanketExceptions":[],"exceptions":[{"id":"new","package":"lib","license":"GPL-3.0-only","status":"approved"}]}`)
	if _, err := rules.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if body := serveExceptions(t, rules).Body.String(); !strings.Contains(body, `"new"`) {
		t.Fatalf("new exception not served: %s", body)
	}

	// A broken edit is reported, not silently replaced by the previous rules.
	write(`{`)
	_, _ = rules.Refresh(context.Background())
	if w := serveExceptions(t, rules); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestLicenseExceptionsHandlerRemoteSource(t *testing.T) {
	up := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{"blanketExceptions":[],"exceptions":[{"id":"remote","package":"lib","license":"GPL-3.0-only","status":"approved"}]}`)
	}))
	defer srv.Close()

	rules, err := watchExceptions(context.Background(), rulesource.Options{Source: srv.URL, HTTPClient: srv.Client()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if body := serveExceptions(t, rules).Body.String(); !strings.Contains(body, `"remote"`) {
		t.Fatalf("remote rules not served: %s", body)
	}

	// An outage keeps the last good rules.
	up = false
	if _, err := rules.Refresh(context.Background()); err == nil {
		t.Fatal("expected a fetch error")
	}
	if w := serveExceptions(t, rules); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"remote"`) {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestLicenseExceptionsHandlerRemoteNeverLoaded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	rules, err := watchExceptions(context.Background(), rulesource.Options{Source: srv.URL, HTTPClient: srv.Client()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if w := serveExceptions(t, rules); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d: a missing remote document must not read as 'no exceptions'", w.Code)
	}
}
