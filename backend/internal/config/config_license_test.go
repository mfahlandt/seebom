package config

import "testing"

// The env override is what Helm and Compose inject; a regression here means
// every deployment silently runs the policy-file/default mode instead.
func TestLoad_LicenseExpressionMode(t *testing.T) {
	t.Setenv("S3_BUCKETS", "")
	t.Setenv("S3_BUCKET", "")

	t.Setenv("LICENSE_EXPRESSION_MODE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LicenseExpressionMode != "" {
		t.Errorf("unset: got %q, want empty (defer to policy file)", cfg.LicenseExpressionMode)
	}

	t.Setenv("LICENSE_EXPRESSION_MODE", " Permissive-Wins ")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LicenseExpressionMode != "permissive-wins" {
		t.Errorf("got %q, want normalised permissive-wins", cfg.LicenseExpressionMode)
	}

	t.Setenv("LICENSE_EXPRESSION_MODE", "lenient")
	if _, err := Load(); err == nil {
		t.Error("expected error for invalid LICENSE_EXPRESSION_MODE")
	}
}
