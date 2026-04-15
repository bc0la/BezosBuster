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
	ltypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

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
		"lambda:ListFunctions", "lambda:GetPolicy", "lambda:ListFunctionUrlConfigs",
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
		// Check for function URLs with AuthType NONE
		for _, fn := range out.Functions {
			urls, err := lcli.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{
				FunctionName: fn.FunctionArn,
			})
			if err != nil || len(urls.FunctionUrlConfigs) == 0 {
				continue
			}
			for _, u := range urls.FunctionUrlConfigs {
				if u.AuthType == ltypes.FunctionUrlAuthTypeNone {
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "apigw_lambda",
						Severity:    findings.SevHigh,
						ResourceARN: aws.ToString(fn.FunctionArn),
						Title:       fmt.Sprintf("Lambda %s: function URL with no auth", aws.ToString(fn.FunctionName)),
						Detail: map[string]any{
							"function": aws.ToString(fn.FunctionName),
							"url":      aws.ToString(u.FunctionUrl),
							"auth":     string(u.AuthType),
							"cors":     u.Cors,
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

	// --- API Gateway v1: check each method for authorizationType NONE
	if apis != nil {
		for _, api := range apis.Items {
			apiID := aws.ToString(api.Id)
			apiName := aws.ToString(api.Name)
			resPager := apigateway.NewGetResourcesPaginator(acli, &apigateway.GetResourcesInput{
				RestApiId: api.Id,
				Embed:     []string{"methods"},
			})
			for resPager.HasMorePages() {
				page, err := resPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, res := range page.Items {
					path := aws.ToString(res.Path)
					for httpMethod, m := range res.ResourceMethods {
						authType := aws.ToString(m.AuthorizationType)
						if strings.EqualFold(authType, "NONE") {
							_ = sink.Write(ctx, findings.Finding{
								AccountID:   t.AccountID,
								Region:      region,
								Module:      "apigw_lambda",
								Severity:    findings.SevHigh,
								ResourceARN: fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiID),
								Title:       fmt.Sprintf("REST API %s: %s %s has no auth", apiName, httpMethod, path),
								Detail: map[string]any{
									"api_id":     apiID,
									"api_name":   apiName,
									"method":     httpMethod,
									"path":       path,
									"auth_type":  authType,
									"api_key_required": aws.ToBool(m.ApiKeyRequired),
								},
							})
						}
					}
				}
			}
		}
	}

	// --- API Gateway v2 HTTP/WebSocket APIs: check routes for auth
	a2 := apigatewayv2.NewFromConfig(t.Config, func(o *apigatewayv2.Options) { o.Region = region })
	v2apis, err := a2.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err == nil {
		for _, api := range v2apis.Items {
			apiID := aws.ToString(api.ApiId)
			apiName := aws.ToString(api.Name)
			routes, err := a2.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: api.ApiId})
			if err != nil {
				continue
			}
			for _, r := range routes.Items {
				if r.AuthorizationType == "NONE" || r.AuthorizationType == "" {
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "apigw_lambda",
						Severity:    findings.SevHigh,
						ResourceARN: fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s", region, apiID),
						Title:       fmt.Sprintf("APIGWv2 %s: route %s has no auth", apiName, aws.ToString(r.RouteKey)),
						Detail: map[string]any{
							"api_id":    apiID,
							"api_name":  apiName,
							"route_key": aws.ToString(r.RouteKey),
							"endpoint":  aws.ToString(api.ApiEndpoint),
							"protocol":  api.ProtocolType,
							"auth_type": string(r.AuthorizationType),
						},
					})
				}
			}
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
