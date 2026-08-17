package secrets_scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeSourcePath(t *testing.T) {
	cases := map[string]string{
		"s3/my-bucket/path/to/key.env": filepath.Join("s3", "my-bucket", "path", "to", "key.env"),
		"lambda_env/my-func":           filepath.Join("lambda_env", "my-func"),
		"ssm_param/App:Secret":         filepath.Join("ssm_param", "App_Secret"),
		// Traversal attempts must be neutralised — no "..", no escape.
		"s3/../../etc/passwd": filepath.Join("s3", "etc", "passwd"),
		"/leading//double/":   filepath.Join("leading", "double"),
	}
	for in, want := range cases {
		got := sanitizeSourcePath(in)
		if got != want {
			t.Errorf("sanitizeSourcePath(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(got, "..") {
			t.Errorf("sanitizeSourcePath(%q) leaked a traversal segment: %q", in, got)
		}
	}
}

func TestS3MaxPages(t *testing.T) {
	// Unset context → default cap.
	if got := s3MaxPages(context.Background()); got != defaultS3MaxPages {
		t.Errorf("default = %d, want %d", got, defaultS3MaxPages)
	}
	// Explicit override is honored.
	ctx := context.WithValue(context.Background(), "bb.s3_max_pages", 100)
	if got := s3MaxPages(ctx); got != 100 {
		t.Errorf("override = %d, want 100", got)
	}
	// 0 propagates (caller treats it as unlimited), not replaced by the default.
	ctx0 := context.WithValue(context.Background(), "bb.s3_max_pages", 0)
	if got := s3MaxPages(ctx0); got != 0 {
		t.Errorf("zero override = %d, want 0 (unlimited)", got)
	}
}
