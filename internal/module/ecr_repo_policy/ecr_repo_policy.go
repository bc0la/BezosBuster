// Package ecr_repo_policy flags private Amazon ECR repositories whose
// repository policy grants an anonymous ("*") principal or an external AWS
// account. A wildcard principal makes the repository's images pullable by
// anyone (docker pull of otherwise-private images); an external-account grant
// widens the audience beyond the owning account. This complements public_ecr,
// which only covers the ECR Public gallery.
package ecr_repo_policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/smithy-go"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "ecr_repo_policy" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"ecr:DescribeRepositories", "ecr:GetRepositoryPolicy"}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := ecr.NewFromConfig(t.Config, func(o *ecr.Options) { o.Region = region })
		pager := ecr.NewDescribeRepositoriesPaginator(cli, &ecr.DescribeRepositoriesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "ecr_repo_policy", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, r := range page.Repositories {
				name := aws.ToString(r.RepositoryName)
				pol, err := cli.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
					RepositoryName: r.RepositoryName,
				})
				if err != nil {
					// No policy attached is the common, benign case.
					if !isPolicyNotFound(err) {
						_ = sink.LogEvent(ctx, "ecr_repo_policy", t.AccountID, "warn", region+" "+name+": "+err.Error())
					}
					continue
				}
				anon, external := analyzeRepoPolicy(aws.ToString(pol.PolicyText), t.AccountID)
				if !anon && len(external) == 0 {
					continue
				}

				sev := findings.SevMedium
				check := "external_account"
				reason := "repository policy grants access to external account(s): " + strings.Join(external, ", ")
				if anon {
					sev = findings.SevHigh
					check = "anonymous_principal"
					reason = "repository policy allows an anonymous principal (\"*\") — images are pullable by anyone"
					if len(external) > 0 {
						reason += "; also grants external account(s): " + strings.Join(external, ", ")
					}
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "ecr_repo_policy",
					Severity:    sev,
					ResourceARN: aws.ToString(r.RepositoryArn),
					Title:       "Private ECR repo " + name + " — " + reason,
					Detail: map[string]any{
						"check":             check,
						"repository":        name,
						"uri":               aws.ToString(r.RepositoryUri),
						"anonymous":         anon,
						"external_accounts": external,
						"policy":            aws.ToString(pol.PolicyText),
					},
				})
			}
		}
	}
	return nil
}

func isPolicyNotFound(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "RepositoryPolicyNotFoundException"
	}
	return false
}

// analyzeRepoPolicy reports whether an ECR repository policy grants an
// anonymous ("*") principal and the set of external AWS account IDs it grants.
func analyzeRepoPolicy(doc, selfAccount string) (anon bool, external []string) {
	var p struct {
		Statement []struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return false, nil
	}
	seen := map[string]bool{}
	for _, st := range p.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		for _, pr := range awsPrincipals(st.Principal) {
			if pr == "*" {
				anon = true
				continue
			}
			if acct := accountOf(pr); acct != "" && acct != selfAccount && !seen[acct] {
				seen[acct] = true
				external = append(external, acct)
			}
		}
	}
	return anon, external
}

// awsPrincipals extracts principal values from a Principal field that may be
// "*", {"AWS":"*"}, or {"AWS":["arn...","arn..."]}.
func awsPrincipals(raw json.RawMessage) []string {
	s := strings.TrimSpace(string(raw))
	if s == `"*"` {
		return []string{"*"}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	var out []string
	if awsRaw, ok := m["AWS"]; ok {
		var one string
		if err := json.Unmarshal(awsRaw, &one); err == nil {
			out = append(out, one)
		} else {
			var many []string
			if err := json.Unmarshal(awsRaw, &many); err == nil {
				out = append(out, many...)
			}
		}
	}
	return out
}

// accountOf extracts the 12-digit account ID from an ARN or a bare account ID.
func accountOf(principal string) string {
	if principal == "*" {
		return ""
	}
	if !strings.Contains(principal, ":") {
		if len(principal) == 12 {
			return principal
		}
		return ""
	}
	parts := strings.Split(principal, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
