package license

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/rulesource"
)

// WatchExceptions wires the rulesource watcher to the real exceptions parser:
// a valid file yields an index, an invalid one is ErrInvalid (not a silent
// empty set), a missing one is ready with a nil index, which every consumer
// treats as "no exceptions".
func TestWatchExceptions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license-exceptions.json")
	w, err := WatchExceptions(rulesource.Options{Paths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := w.Refresh(ctx); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if snap := w.Current(); snap.Present || !snap.Ready || snap.Value != nil {
		t.Fatalf("missing file must be ready, absent and nil: %+v", snap)
	}
	if ok, _ := w.Current().Value.IsExempt("example.org/lib", "MPL-2.0"); ok {
		t.Fatal("nil index must exempt nothing")
	}

	rules := `{"version":"1.0.0","blanketExceptions":[],"exceptions":[{"id":"x","package":"example.org/lib","license":"MPL-2.0","status":"approved"}]}`
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := w.Refresh(ctx)
	if err != nil || !changed {
		t.Fatalf("valid file: changed=%v err=%v", changed, err)
	}
	if ok, _ := w.Current().Value.IsExempt("example.org/lib", "MPL-2.0"); !ok {
		t.Fatal("approved rule must be active after reload")
	}
	if !w.Current().Present {
		t.Fatal("file present must be reported")
	}

	if err := os.WriteFile(path, []byte(`{"blanketExceptions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Refresh(ctx); !errors.Is(err, rulesource.ErrInvalid) {
		t.Fatalf("invalid file: err = %v, want ErrInvalid", err)
	}
	if ok, _ := w.Current().Value.IsExempt("example.org/lib", "MPL-2.0"); !ok {
		t.Fatal("invalid file must keep the last good rules")
	}
}

func TestWatchExceptionsRejectsBadOptions(t *testing.T) {
	if _, err := WatchExceptions(rulesource.Options{Source: "ftp://rules"}); err == nil {
		t.Fatal("ftp source must be rejected")
	}
}
