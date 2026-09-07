package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
			w := httptest.NewRecorder()
			licenseExceptionsHandler(paths...).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/license-exceptions", nil))
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
