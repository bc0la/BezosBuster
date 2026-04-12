package iam_integrations

import (
	"strings"

	"github.com/you/bezosbuster/internal/findings"
)

// GitHub Actions OIDC issuer.
const githubOIDCIssuer = "token.actions.githubusercontent.com"

// GHSubjectRisk classifies a GitHub Actions OIDC subject claim pattern.
// The GitHub OIDC `sub` claim has the shape:
//
//	repo:<owner>/<repo>:ref:refs/heads/<branch>
//	repo:<owner>/<repo>:environment:<env>
//	repo:<owner>/<repo>:pull_request
//
// An IAM trust condition that doesn't pin both owner AND repo is almost
// always a mistake — any repository on GitHub (or anywhere in an
// organization) could assume the role. IAM wildcards are NOT path-aware:
// `repo:*` matches literally any string starting with `repo:`.
type GHSubjectRisk struct {
	Pattern    string
	Severity   findings.Severity
	Category   string
	Reason     string
	Suggestion string
}

// AnalyzeGitHubSub examines a single `token.actions.githubusercontent.com:sub`
// condition value and returns a risk classification.
//
// operator is the IAM condition operator: "StringEquals", "StringLike",
// "ForAnyValue:StringEquals", etc. StringLike with no wildcard is treated
// the same as StringEquals.
func AnalyzeGitHubSub(operator, value string) GHSubjectRisk {
	v := strings.TrimSpace(value)
	if v == "" {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevCritical,
			Category:   "github_oidc_empty_sub",
			Reason:     "empty :sub claim condition",
			Suggestion: "Require the subject claim to include a specific owner AND repo, e.g. repo:octo-org/octo-repo:ref:refs/heads/main",
		}
	}

	// IAM pattern: Allow matches are tested literally unless operator is a
	// *Like variant. `*` in a StringEquals value is a literal asterisk.
	like := strings.Contains(strings.ToLower(operator), "like")

	// A completely wildcarded subject — any repo in any org.
	if like && (v == "*" || v == "repo:*" || strings.HasPrefix(v, "*")) {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevCritical,
			Category:   "github_oidc_universal_sub",
			Reason:     "subject wildcard allows any GitHub repository anywhere to assume this role",
			Suggestion: "Pin the subject to a specific owner and repo, e.g. repo:octo-org/octo-repo:*",
		}
	}

	if !strings.HasPrefix(v, "repo:") {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevHigh,
			Category:   "github_oidc_unrecognized_sub",
			Reason:     "subject does not start with `repo:` — may accept non-repo subjects",
			Suggestion: "Use a repo-scoped subject like repo:<owner>/<repo>:ref:refs/heads/main",
		}
	}

	// Strip "repo:" prefix, then look at what comes next.
	rest := strings.TrimPrefix(v, "repo:")

	// Split into <owner>/<repo>[:rest]
	slash := strings.Index(rest, "/")
	if slash == -1 {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevCritical,
			Category:   "github_oidc_no_repo",
			Reason:     "subject pins an owner but no repository",
			Suggestion: "Include the repository name: repo:<owner>/<repo>:...",
		}
	}
	owner := rest[:slash]
	afterOwner := rest[slash+1:]

	// Owner contains a wildcard (e.g. `*/foo`, `oct*/foo`).
	if like && strings.Contains(owner, "*") {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevCritical,
			Category:   "github_oidc_wildcard_owner",
			Reason:     "owner is wildcarded — any GitHub org/user matching the pattern can assume",
			Suggestion: "Pin a specific owner.",
		}
	}

	// Organization-wide wildcard: repo:owner/*, repo:owner/*:*
	if like && (afterOwner == "*" || strings.HasPrefix(afterOwner, "*:") || afterOwner == "*:*") {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevHigh,
			Category:   "github_oidc_org_wide",
			Reason:     "any repository in the `" + owner + "` organization can assume this role",
			Suggestion: "Scope to a specific repository: repo:" + owner + "/<repo>:...",
		}
	}

	// Split off repo name.
	colon := strings.Index(afterOwner, ":")
	var repo, tail string
	if colon == -1 {
		repo = afterOwner
	} else {
		repo = afterOwner[:colon]
		tail = afterOwner[colon+1:]
	}

	if like && strings.Contains(repo, "*") {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevHigh,
			Category:   "github_oidc_wildcard_repo",
			Reason:     "repository name is wildcarded — multiple repos in `" + owner + "` can assume this role",
			Suggestion: "Pin a single repository.",
		}
	}

	// No tail at all means the subject is effectively `repo:owner/repo` —
	// GitHub never emits that, so this is a config bug.
	if tail == "" {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevHigh,
			Category:   "github_oidc_no_tail",
			Reason:     "subject pins owner/repo but no ref/environment/pull_request qualifier — GitHub does not emit such subjects",
			Suggestion: "Add a qualifier like :ref:refs/heads/main or :environment:prod",
		}
	}

	// Tail is a wildcard — any ref/environment in the repo.
	if like && (tail == "*" || strings.HasPrefix(tail, "*")) {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevMedium,
			Category:   "github_oidc_any_ref",
			Reason:     "any branch / tag / environment / pull_request in `" + owner + "/" + repo + "` can assume this role — a PR from an attacker-controlled fork or a push to any branch is sufficient",
			Suggestion: "Scope to a specific branch or environment, e.g. :ref:refs/heads/main or :environment:production",
		}
	}

	// Pull-request subjects are especially dangerous — anyone can open a PR
	// from a fork and trigger the workflow if pull_request_target is used.
	if strings.HasPrefix(tail, "pull_request") {
		return GHSubjectRisk{
			Pattern:    value,
			Severity:   findings.SevHigh,
			Category:   "github_oidc_pull_request",
			Reason:     "subject allows pull_request runs — untrusted contributors can assume this role via fork PRs if the workflow uses pull_request_target",
			Suggestion: "Prefer :environment:<env> with a protection rule, or :ref:refs/heads/<branch>.",
		}
	}

	// Well-scoped: specific ref or environment.
	return GHSubjectRisk{
		Pattern:  value,
		Severity: findings.SevInfo,
		Category: "github_oidc_scoped",
		Reason:   "subject is pinned to a specific ref/environment in " + owner + "/" + repo,
	}
}
