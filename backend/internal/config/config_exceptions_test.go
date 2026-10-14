package config

import (
	"testing"
	"time"
)

func TestLoad_ExceptionsSourceDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExceptionsSource != "" || cfg.ExceptionsSourceToken != "" {
		t.Errorf("source = %q token set = %v, want both empty", cfg.ExceptionsSource, cfg.ExceptionsSourceToken != "")
	}
	if cfg.ExceptionsRefreshInterval != 60*time.Second {
		t.Errorf("interval = %v, want 60s", cfg.ExceptionsRefreshInterval)
	}
}

func TestLoad_ExceptionsSource(t *testing.T) {
	t.Setenv("EXCEPTIONS_SOURCE", "  https://example.com/license-exceptions.json ")
	t.Setenv("EXCEPTIONS_SOURCE_TOKEN", "s3cret")
	t.Setenv("EXCEPTIONS_REFRESH_INTERVAL", "5m")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExceptionsSource != "https://example.com/license-exceptions.json" {
		t.Errorf("source = %q", cfg.ExceptionsSource)
	}
	if cfg.ExceptionsSourceToken != "s3cret" {
		t.Error("token not read")
	}
	if cfg.ExceptionsRefreshInterval != 5*time.Minute {
		t.Errorf("interval = %v", cfg.ExceptionsRefreshInterval)
	}
}

func TestLoad_ExceptionsRefreshInterval(t *testing.T) {
	for raw, want := range map[string]time.Duration{"0": 0, "30s": 30 * time.Second} {
		t.Setenv("EXCEPTIONS_REFRESH_INTERVAL", raw)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if cfg.ExceptionsRefreshInterval != want {
			t.Errorf("%q: interval = %v, want %v", raw, cfg.ExceptionsRefreshInterval, want)
		}
	}
	for _, raw := range []string{"-1s", "60", "soon"} {
		t.Setenv("EXCEPTIONS_REFRESH_INTERVAL", raw)
		if _, err := Load(); err == nil {
			t.Errorf("%q: expected an error", raw)
		}
	}
}
