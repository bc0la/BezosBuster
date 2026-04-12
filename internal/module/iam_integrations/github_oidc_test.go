package iam_integrations

import (
	"testing"

	"github.com/you/bezosbuster/internal/findings"
)

func TestAnalyzeGitHubSub(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		value   string
		wantSev findings.Severity
		wantCat string
	}{
		{"empty", "StringEquals", "", findings.SevCritical, "github_oidc_empty_sub"},
		{"universal wildcard", "StringLike", "repo:*", findings.SevCritical, "github_oidc_universal_sub"},
		{"top wildcard", "StringLike", "*", findings.SevCritical, "github_oidc_universal_sub"},
		{"wildcard owner", "StringLike", "repo:*/project", findings.SevCritical, "github_oidc_wildcard_owner"},
		{"owner only", "StringEquals", "repo:octo-org", findings.SevCritical, "github_oidc_no_repo"},
		{"org-wide", "StringLike", "repo:octo-org/*", findings.SevHigh, "github_oidc_org_wide"},
		{"org-wide with colon", "StringLike", "repo:octo-org/*:*", findings.SevHigh, "github_oidc_org_wide"},
		{"wildcard repo", "StringLike", "repo:octo-org/proj-*:ref:refs/heads/main", findings.SevHigh, "github_oidc_wildcard_repo"},
		{"no tail", "StringEquals", "repo:octo-org/octo-repo", findings.SevHigh, "github_oidc_no_tail"},
		{"any ref", "StringLike", "repo:octo-org/octo-repo:*", findings.SevMedium, "github_oidc_any_ref"},
		{"pull_request", "StringEquals", "repo:octo-org/octo-repo:pull_request", findings.SevHigh, "github_oidc_pull_request"},
		{"scoped main", "StringEquals", "repo:octo-org/octo-repo:ref:refs/heads/main", findings.SevInfo, "github_oidc_scoped"},
		{"scoped env", "StringEquals", "repo:octo-org/octo-repo:environment:prod", findings.SevInfo, "github_oidc_scoped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeGitHubSub(tc.op, tc.value)
			if got.Severity != tc.wantSev {
				t.Errorf("severity: got %s, want %s (%+v)", got.Severity, tc.wantSev, got)
			}
			if got.Category != tc.wantCat {
				t.Errorf("category: got %s, want %s", got.Category, tc.wantCat)
			}
		})
	}
}
