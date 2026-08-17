package secrets_scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestPullCommand(t *testing.T) {
	tdArn := "arn:aws:ecs:us-east-1:111122223333:task-definition/web:5"
	got := pullCommand("ecs_taskdef", "us-east-1", map[string]string{"arn": tdArn, "family": "web"})
	want := "aws ecs describe-task-definition --task-definition " + tdArn + " --region us-east-1"
	if got != want {
		t.Errorf("ecs_taskdef:\n got %q\nwant %q", got, want)
	}

	// Global resources (iam) omit --region.
	if c := pullCommand("iam_keys", "global", map[string]string{"user": "svc"}); c != "aws iam list-access-keys --user-name svc" {
		t.Errorf("iam_keys global: %q", c)
	}

	// ID parsed out of the ARN for services keyed by opaque id.
	if c := pullCommand("apigw_vars", "eu-west-1", map[string]string{"arn": "arn:aws:apigateway:eu-west-1::/restapis/abc123", "stage": "prod"}); c != "aws apigateway get-stage --rest-api-id abc123 --stage-name prod --region eu-west-1" {
		t.Errorf("apigw_vars: %q", c)
	}

	if c := pullCommand("ssm_document", "us-east-1", map[string]string{"name": "My-Doc"}); c != "aws ssm get-document --name My-Doc --region us-east-1" {
		t.Errorf("ssm_document: %q", c)
	}
	if c := pullCommand("ssm_automation", "us-east-1", map[string]string{"execution_id": "abc-123"}); c != "aws ssm get-automation-execution --automation-execution-id abc-123 --region us-east-1" {
		t.Errorf("ssm_automation: %q", c)
	}

	// Unknown source type → no command.
	if c := pullCommand("mystery", "us-east-1", nil); c != "" {
		t.Errorf("unknown source should give empty command, got %q", c)
	}
}

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
