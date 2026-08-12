package engagement

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetLogFiles verifies that the full log captures every level while the
// error log captures only warn/error, and that both are appended to disk.
func TestSetLogFiles(t *testing.T) {
	dir := t.TempDir()
	eng, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	allPath := filepath.Join(dir, "run.log")
	errPath := filepath.Join(dir, "errors.log")
	if err := eng.SetLogFiles(allPath, errPath); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_ = eng.LogEvent(ctx, "modA", "111122223333", "info", "starting up")
	_ = eng.LogEvent(ctx, "modA", "111122223333", "warn", "us-east-1: AccessDenied")
	_ = eng.LogEvent(ctx, "modB", "", "error", "hard failure")
	_ = eng.LogEvent(ctx, "modB", "", "debug", "chatty detail")

	all, err := os.ReadFile(allPath)
	if err != nil {
		t.Fatal(err)
	}
	allStr := string(all)
	for _, want := range []string{"starting up", "AccessDenied", "hard failure", "chatty detail"} {
		if !strings.Contains(allStr, want) {
			t.Errorf("full log missing %q\n%s", want, allStr)
		}
	}
	// Level tag is upper-cased and the empty account renders as "-".
	if !strings.Contains(allStr, "[INFO ]") || !strings.Contains(allStr, "modB -:") {
		t.Errorf("full log formatting off:\n%s", allStr)
	}

	errb, err := os.ReadFile(errPath)
	if err != nil {
		t.Fatal(err)
	}
	errStr := string(errb)
	if !strings.Contains(errStr, "AccessDenied") || !strings.Contains(errStr, "hard failure") {
		t.Errorf("error log missing a warn/error line:\n%s", errStr)
	}
	if strings.Contains(errStr, "starting up") || strings.Contains(errStr, "chatty detail") {
		t.Errorf("error log should exclude info/debug lines:\n%s", errStr)
	}
}

func TestIsErrLevel(t *testing.T) {
	for _, l := range []string{"warn", "WARNING", "error", "Err", "fatal"} {
		if !isErrLevel(l) {
			t.Errorf("%q should be an error level", l)
		}
	}
	for _, l := range []string{"info", "debug", "trace", ""} {
		if isErrLevel(l) {
			t.Errorf("%q should not be an error level", l)
		}
	}
}
