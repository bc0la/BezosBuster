package web_identity

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string        { return "web_identity" }
func (Module) Kind() module.Kind   { return module.KindNative }
func (Module) Requires() []string  { return []string{"iam:ListRoles", "iam:GetRole"} }

type trustDoc struct {
	Version   string         `json:"Version"`
	Statement []trustStmt    `json:"Statement"`
}
type trustStmt struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Condition json.RawMessage `json:"Condition"`
}

func actionsInclude(raw json.RawMessage, want string) bool {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.EqualFold(s, want)
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err == nil {
		for _, a := range ss {
			if strings.EqualFold(a, want) {
				return true
			}
		}
	}
	return false
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	cli := iam.NewFromConfig(t.Config)
	var marker *string
	for {
		out, err := cli.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return err
		}
		for _, r := range out.Roles {
			doc := aws.ToString(r.AssumeRolePolicyDocument)
			if doc == "" {
				continue
			}
			decoded, err := url.QueryUnescape(doc)
			if err != nil {
				decoded = doc
			}
			var td trustDoc
			if err := json.Unmarshal([]byte(decoded), &td); err != nil {
				continue
			}
			for _, st := range td.Statement {
				if !strings.EqualFold(st.Effect, "Allow") {
					continue
				}
				if !actionsInclude(st.Action, "sts:AssumeRoleWithWebIdentity") {
					continue
				}
				sev := findings.SevMedium
				// Missing Condition block is a red flag — any OIDC identity can assume.
				if len(st.Condition) == 0 || string(st.Condition) == "null" || string(st.Condition) == "{}" {
					sev = findings.SevCritical
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Module:      "web_identity",
					Severity:    sev,
					ResourceARN: aws.ToString(r.Arn),
					Title:       "Role trusts AssumeRoleWithWebIdentity: " + aws.ToString(r.RoleName),
					Detail: map[string]any{
						"role":       aws.ToString(r.RoleName),
						"principal":  st.Principal,
						"condition":  st.Condition,
					},
				})
			}
		}
		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	return nil
}
