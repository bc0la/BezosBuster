// Package kms_key_exposure flags customer-managed KMS keys whose key policy
// grants access to an anonymous principal ("*") or to an external AWS account.
// A "*" principal on a key policy is the resource-side gate for cross-account
// and (combined with grants) anonymous key usage; external-account principals
// widen the blast radius of anything the key protects (Secrets Manager,
// EBS/RDS snapshots, S3 SSE-KMS objects, …).
package kms_key_exposure

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "kms_key_exposure" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy"}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := kms.NewFromConfig(t.Config, func(o *kms.Options) { o.Region = region })
		pager := kms.NewListKeysPaginator(cli, &kms.ListKeysInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "kms_key_exposure", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, k := range page.Keys {
				keyID := aws.ToString(k.KeyId)
				meta, err := cli.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
				if err != nil || meta.KeyMetadata == nil {
					continue
				}
				md := meta.KeyMetadata
				// Only customer-managed, usable keys are interesting; AWS-managed
				// key policies are fixed and pending-deletion keys are moot.
				if md.KeyManager != kmstypes.KeyManagerTypeCustomer {
					continue
				}
				if md.KeyState == kmstypes.KeyStatePendingDeletion {
					continue
				}
				pol, err := cli.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
					KeyId:      aws.String(keyID),
					PolicyName: aws.String("default"),
				})
				if err != nil || pol.Policy == nil {
					continue
				}
				anon, anonConditioned, external := analyzeKeyPolicy(aws.ToString(pol.Policy), t.AccountID)
				if !anon && len(external) == 0 {
					continue
				}

				sev := findings.SevMedium
				var reasons []string
				if anon {
					if anonConditioned {
						sev = worst(sev, findings.SevMedium)
						reasons = append(reasons, "key policy allows anonymous principal (\"*\"), gated by a Condition — verify it is tight")
					} else {
						sev = worst(sev, findings.SevHigh)
						reasons = append(reasons, "key policy allows anonymous principal (\"*\") with no Condition")
					}
				}
				if len(external) > 0 {
					sev = worst(sev, findings.SevMedium)
					reasons = append(reasons, "key policy grants access to external account(s): "+strings.Join(external, ", "))
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "kms_key_exposure",
					Severity:    sev,
					ResourceARN: aws.ToString(md.Arn),
					Title:       "KMS key " + keyID + " — " + strings.Join(reasons, "; "),
					Detail: map[string]any{
						"key_id":            keyID,
						"description":       aws.ToString(md.Description),
						"anonymous":         anon,
						"anon_conditioned":  anonConditioned,
						"external_accounts": external,
						"reasons":           reasons,
					},
				})
			}
		}
	}
	return nil
}

// analyzeKeyPolicy inspects a KMS key policy for anonymous and external-account
// Allow grants. It returns whether an anonymous ("*") principal is allowed
// (and whether every anonymous Allow carried a Condition), plus the set of
// external AWS account IDs referenced by AWS principals.
func analyzeKeyPolicy(doc, selfAccount string) (anon bool, anonConditioned bool, external []string) {
	var p struct {
		Statement []struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Condition json.RawMessage `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return false, false, nil
	}
	anonConditioned = true // vacuously true until we see an unconditioned anon Allow
	seen := map[string]bool{}
	for _, st := range p.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		hasCond := len(st.Condition) > 0 && strings.TrimSpace(string(st.Condition)) != "{}"
		for _, pr := range awsPrincipals(st.Principal) {
			if pr == "*" {
				anon = true
				if !hasCond {
					anonConditioned = false
				}
				continue
			}
			if acct := accountOf(pr); acct != "" && acct != selfAccount && !seen[acct] {
				seen[acct] = true
				external = append(external, acct)
			}
		}
	}
	if !anon {
		anonConditioned = false
	}
	return anon, anonConditioned, external
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
	// AWS field may be a string or []string.
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
		// Bare account id.
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

func worst(a, b findings.Severity) findings.Severity {
	order := map[findings.Severity]int{
		findings.SevInfo: 0, findings.SevLow: 1, findings.SevMedium: 2, findings.SevHigh: 3, findings.SevCritical: 4,
	}
	if order[a] >= order[b] {
		return a
	}
	return b
}
