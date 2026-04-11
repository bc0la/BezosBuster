package apigw_lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "apigw_lambda" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"apigateway:GET", "apigatewayv2:GetApis", "apigatewayv2:GetRoutes",
		"lambda:ListFunctions", "lambda:GetPolicy",
	}
}

// resourcePolicyDoc is the minimal shape we care about in execute-api /
// lambda resource policies.
type resourcePolicyDoc struct {
	Version   string               `json:"Version"`
	Statement []resourcePolicyStmt `json:"Statement"`
}

type resourcePolicyStmt struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Condition json.RawMessage `json:"Condition"`
}

// isAnonymousPrincipal returns true when the policy principal is "*" or {"AWS":"*"}.
func isAnonymousPrincipal(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	if s == `"*"` {
		return true
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err == nil {
		for _, v := range m {
			vs := strings.TrimSpace(string(v))
			if vs == `"*"` || vs == `["*"]` {
				return true
			}
		}
	}
	return false
}

func asList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err == nil {
		return ss
	}
	return nil
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "apigw_lambda", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	// --- Lambda resource policies
	lcli := lambda.NewFromConfig(t.Config, func(o *lambda.Options) { o.Region = region })
	var marker *string
	for {
		out, err := lcli.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return fmt.Errorf("lambda list: %w", err)
		}
		for _, fn := range out.Functions {
			name := aws.ToString(fn.FunctionName)
			pol, err := lcli.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: fn.FunctionArn})
			if err != nil || pol.Policy == nil {
				continue
			}
			var doc resourcePolicyDoc
			if err := json.Unmarshal([]byte(aws.ToString(pol.Policy)), &doc); err != nil {
				continue
			}
			for _, st := range doc.Statement {
				if !strings.EqualFold(st.Effect, "Allow") {
					continue
				}
				anon := isAnonymousPrincipal(st.Principal)
				for _, res := range asList(st.Resource) {
					risks := AnalyzePattern(res)
					if len(risks) == 0 && !anon {
						continue
					}
					sev := findings.SevMedium
					if anon {
						sev = findings.SevHigh
					}
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "apigw_lambda",
						Severity:    sev,
						ResourceARN: aws.ToString(fn.FunctionArn),
						Title:       fmt.Sprintf("Lambda %s: %s", name, classify(anon, risks)),
						Detail: map[string]any{
							"function":      name,
							"statement":     st,
							"anonymous":     anon,
							"wildcard_risks": risks,
						},
					})
				}
			}
		}
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}

	// --- API Gateway v1 REST APIs: resource policy on each API
	acli := apigateway.NewFromConfig(t.Config, func(o *apigateway.Options) { o.Region = region })
	apis, err := acli.GetRestApis(ctx, &apigateway.GetRestApisInput{Limit: aws.Int32(500)})
	if err == nil {
		for _, api := range apis.Items {
			pol := aws.ToString(api.Policy)
			if pol == "" {
				continue
			}
			var doc resourcePolicyDoc
			if err := json.Unmarshal([]byte(pol), &doc); err != nil {
				continue
			}
			for _, st := range doc.Statement {
				if !strings.EqualFold(st.Effect, "Allow") {
					continue
				}
				anon := isAnonymousPrincipal(st.Principal)
				for _, res := range asList(st.Resource) {
					risks := AnalyzePattern(res)
					if len(risks) == 0 && !anon {
						continue
					}
					sev := findings.SevMedium
					if anon && len(risks) > 0 {
						sev = findings.SevCritical
					} else if anon {
						sev = findings.SevHigh
					}
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "apigw_lambda",
						Severity:    sev,
						ResourceARN: fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, aws.ToString(api.Id)),
						Title:       fmt.Sprintf("REST API %s: %s", aws.ToString(api.Name), classify(anon, risks)),
						Detail: map[string]any{
							"api_id":         aws.ToString(api.Id),
							"api_name":       aws.ToString(api.Name),
							"resource":       res,
							"anonymous":      anon,
							"wildcard_risks": risks,
							"statement":      st,
						},
					})
				}
			}
		}
	}

	// --- API Gateway v2 HTTP/WebSocket APIs (no IAM resource-policy field;
	// still list them so the report shows what's exposed)
	a2 := apigatewayv2.NewFromConfig(t.Config, func(o *apigatewayv2.Options) { o.Region = region })
	v2apis, err := a2.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err == nil {
		for _, api := range v2apis.Items {
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "apigw_lambda",
				Severity:    findings.SevInfo,
				ResourceARN: aws.ToString(api.ApiEndpoint),
				Title:       fmt.Sprintf("APIGWv2 %s (%s)", aws.ToString(api.Name), api.ProtocolType),
				Detail: map[string]any{
					"api_id":      aws.ToString(api.ApiId),
					"endpoint":    aws.ToString(api.ApiEndpoint),
					"protocol":    api.ProtocolType,
					"auth_types":  nil, // filled in below if we query routes
				},
			})
		}
	}

	return nil
}

func classify(anon bool, risks []WildcardRisk) string {
	switch {
	case anon && len(risks) > 0:
		return "anonymous invocation with wildcard-crossing ARN"
	case anon:
		return "anonymous invocation allowed"
	case len(risks) > 0:
		return "wildcard-crossing ARN in statement"
	}
	return "review"
}
