package secrets_scan

import (
	"context"
	"testing"
)

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
