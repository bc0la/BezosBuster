package apigw_lambda

import "testing"

func TestAnalyzePatternCrossing(t *testing.T) {
	// The canonical example from the spec.
	arn := "arn:aws:execute-api:sa-east-1:123456789012:api-id/prod/*/dashboard/*"
	risks := AnalyzePattern(arn)
	if len(risks) == 0 {
		t.Fatalf("expected at least one risk for %s", arn)
	}
	var foundMid bool
	for _, r := range risks {
		if r.SegmentIndex == 2 && r.Segment == "*" {
			foundMid = true
		}
	}
	if !foundMid {
		t.Fatalf("expected a crossing wildcard at segment 2, got %+v", risks)
	}
}

func TestAnalyzePatternTrailingOnlyIsSafe(t *testing.T) {
	// Trailing wildcard is a standard pattern, not flagged.
	arn := "arn:aws:execute-api:us-east-1:111122223333:api-id/prod/GET/dashboard/*"
	risks := AnalyzePattern(arn)
	if len(risks) != 0 {
		t.Fatalf("expected no risks for trailing wildcard, got %+v", risks)
	}
}

func TestAnalyzePatternPartialSegmentWildcard(t *testing.T) {
	arn := "arn:aws:execute-api:us-east-1:111122223333:api-id/prod/*/dashboard"
	risks := AnalyzePattern(arn)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d: %+v", len(risks), risks)
	}
}

func TestParseExecuteAPIARN(t *testing.T) {
	arn := "arn:aws:execute-api:sa-east-1:123456789012:api-id/prod/GET/dashboard/user/bob"
	got, ok := ParseExecuteAPIARN(arn)
	if !ok {
		t.Fatal("parse failed")
	}
	if got.Region != "sa-east-1" || got.AccountID != "123456789012" {
		t.Errorf("wrong region/account: %+v", got)
	}
	if got.APIID != "api-id" || got.Stage != "prod" || got.Method != "GET" {
		t.Errorf("wrong api/stage/method: %+v", got)
	}
	if got.Path != "dashboard/user/bob" {
		t.Errorf("wrong path: %q", got.Path)
	}
}
