package secrets_scan

import "testing"

// TestParseKingfisherJSON reproduces the real kingfisher output shape: a
// findings document followed by a run-summary document that reuses the
// "findings" key as a count. The summary must be skipped silently, not logged
// as a decode error.
func TestParseKingfisherJSON(t *testing.T) {
	out := []byte(`{"findings":[{"rule":{"id":"aws-key","name":"AWS Key"},"finding":{"snippet":"AKIAEXAMPLE","path":"/tmp/x/0001_lambda_env__foo.txt","line":3,"confidence":"high","validation":{"status":"valid"}}}]}
{"findings":1,"rules_run":42,"elapsed":"1.2s"}`)

	got, warns := parseKingfisherJSON(out)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings (summary doc should be skipped): %v", warns)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Rule.ID != "aws-key" || got[0].Finding.Validation.Status != "valid" {
		t.Errorf("finding parsed wrong: %+v", got[0])
	}
}

// A summary-only document (no array) yields nothing and no warning.
func TestParseKingfisherJSON_SummaryOnly(t *testing.T) {
	got, warns := parseKingfisherJSON([]byte(`{"findings":0,"rules_run":42}`))
	if len(got) != 0 || len(warns) != 0 {
		t.Fatalf("want 0 findings / 0 warnings, got %d / %v", len(got), warns)
	}
}

// Empty / no output is a no-op.
func TestParseKingfisherJSON_Empty(t *testing.T) {
	got, warns := parseKingfisherJSON(nil)
	if len(got) != 0 || len(warns) != 0 {
		t.Fatalf("want 0 findings / 0 warnings, got %d / %v", len(got), warns)
	}
}

// Genuinely malformed JSON still surfaces a warning (not silently dropped).
func TestParseKingfisherJSON_Malformed(t *testing.T) {
	_, warns := parseKingfisherJSON([]byte(`{"findings":[}`))
	if len(warns) == 0 {
		t.Fatal("malformed input should produce a warning")
	}
}
