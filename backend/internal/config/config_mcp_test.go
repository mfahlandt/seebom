package config

import (
	"strings"
	"testing"
)

// mcpEnv clears every MCP-related variable and sets the given ones, so a test
// never inherits the developer's shell.
func mcpEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{
		"MCP_TRANSPORT", "MCP_HTTP_ADDR", "MCP_HTTP_TOKEN", "MCP_ALLOWED_ORIGINS",
		"MCP_API_BASE_URL", "MCP_API_KEY", "MCP_SERVICE_TOKEN", "MCP_REQUEST_TIMEOUT_SECONDS",
		"SERVICE_TOKEN", "API_KEYS", "AUTH_ENABLED",
	} {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

// stdio by default: an MCP server that listens on a port is a remote
// tool-execution surface, so it has to be asked for.
func TestMCPDefaultsToStdio(t *testing.T) {
	mcpEnv(t, nil)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCPTransport != MCPTransportStdio {
		t.Errorf("MCPTransport = %q, want %q", cfg.MCPTransport, MCPTransportStdio)
	}
	if cfg.MCPAPIBaseURL != "http://localhost:8080" {
		t.Errorf("MCPAPIBaseURL = %q", cfg.MCPAPIBaseURL)
	}
	if !strings.HasPrefix(cfg.MCPHTTPAddr, "127.0.0.1:") {
		t.Errorf("MCPHTTPAddr = %q, want a loopback default", cfg.MCPHTTPAddr)
	}
	if cfg.MCPRequestTimeout != 30 {
		t.Errorf("MCPRequestTimeout = %d, want 30", cfg.MCPRequestTimeout)
	}
	if len(cfg.MCPAllowedOrigins) != 0 {
		t.Errorf("MCPAllowedOrigins = %v, want empty", cfg.MCPAllowedOrigins)
	}
}

func TestMCPTransportIsValidated(t *testing.T) {
	mcpEnv(t, map[string]string{"MCP_TRANSPORT": "websocket"})

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted MCP_TRANSPORT=websocket")
	}
}

func TestMCPTransportIsCaseInsensitive(t *testing.T) {
	mcpEnv(t, map[string]string{"MCP_TRANSPORT": " HTTP "})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCPTransport != MCPTransportHTTP {
		t.Errorf("MCPTransport = %q, want %q", cfg.MCPTransport, MCPTransportHTTP)
	}
}

func TestMCPAllowedOriginsIsCommaSeparated(t *testing.T) {
	mcpEnv(t, map[string]string{"MCP_ALLOWED_ORIGINS": "https://a.example, https://b.example ,"})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"https://a.example", "https://b.example"}
	if len(cfg.MCPAllowedOrigins) != len(want) {
		t.Fatalf("MCPAllowedOrigins = %v, want %v", cfg.MCPAllowedOrigins, want)
	}
	for i := range want {
		if cfg.MCPAllowedOrigins[i] != want[i] {
			t.Errorf("MCPAllowedOrigins[%d] = %q, want %q", i, cfg.MCPAllowedOrigins[i], want[i])
		}
	}
}

// The chart mounts one secret for the whole release, so an operator who
// configured the gateway's auth should not have to repeat the same secret
// under a second name for the MCP server to get through it.
func TestMCPInheritsGatewayCredentials(t *testing.T) {
	mcpEnv(t, map[string]string{
		"AUTH_ENABLED":  "true",
		"SERVICE_TOKEN": "shared-token",
		"API_KEYS":      "key-one,key-two",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCPServiceToken != "shared-token" {
		t.Errorf("MCPServiceToken = %q, want the instance SERVICE_TOKEN", cfg.MCPServiceToken)
	}
	if cfg.MCPAPIKey != "key-one" {
		t.Errorf("MCPAPIKey = %q, want the first API_KEYS entry", cfg.MCPAPIKey)
	}
}

func TestMCPExplicitCredentialsWinOverInherited(t *testing.T) {
	mcpEnv(t, map[string]string{
		"SERVICE_TOKEN":     "shared-token",
		"API_KEYS":          "key-one",
		"MCP_SERVICE_TOKEN": "mcp-token",
		"MCP_API_KEY":       "mcp-key",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCPServiceToken != "mcp-token" || cfg.MCPAPIKey != "mcp-key" {
		t.Errorf("MCP credentials = %q/%q, want the explicit ones", cfg.MCPServiceToken, cfg.MCPAPIKey)
	}
}
