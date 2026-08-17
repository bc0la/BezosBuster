package secrets_scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
)

// fakeSink implements findings.Sink just enough for saveHitFile: RawDir returns
// a fixed temp directory.
type fakeSink struct{ dir string }

func (f fakeSink) Write(context.Context, findings.Finding) error { return nil }
func (f fakeSink) RawDir(module, accountID string) (string, error) {
	d := filepath.Join(f.dir, module, accountID)
	return d, os.MkdirAll(d, 0o755)
}
func (f fakeSink) LogEvent(context.Context, string, string, string, string) error { return nil }

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSaveHitFile_CollisionAndDedup(t *testing.T) {
	root := t.TempDir()
	sink := fakeSink{dir: root}
	tgt := creds.AccountTarget{AccountID: "111122223333"}
	src := "ecs_taskdef/web" // same source, mimicking two task-def revisions

	// Two different task-def revisions sharing the family must NOT clobber.
	a := saveHitFile(writeTemp(t, root, "revA.txt", "SECRET_A=1"), src, tgt, sink)
	b := saveHitFile(writeTemp(t, root, "revB.txt", "SECRET_B=2"), src, tgt, sink)
	if a == "" || b == "" {
		t.Fatalf("saveHitFile returned empty: a=%q b=%q", a, b)
	}
	if a == b {
		t.Fatalf("distinct content collided onto one path: %q", a)
	}
	if filepath.Base(a) != "web" || filepath.Base(b) != "web-2" {
		t.Errorf("unexpected names: a=%s b=%s (want web, web-2)", filepath.Base(a), filepath.Base(b))
	}

	// Re-hitting identical content reuses the same file (no web-3).
	c := saveHitFile(writeTemp(t, root, "revA_again.txt", "SECRET_A=1"), src, tgt, sink)
	if c != a {
		t.Errorf("identical content should reuse %q, got %q", a, c)
	}

	// Both files exist under hits/ecs_taskdef/.
	hitsDir := filepath.Join(root, "secrets_scan", "111122223333", "hits", "ecs_taskdef")
	entries, _ := os.ReadDir(hitsDir)
	if len(entries) != 2 {
		t.Errorf("want 2 saved files, got %d", len(entries))
	}
}
