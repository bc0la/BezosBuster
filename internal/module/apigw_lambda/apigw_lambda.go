package apigw_lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	a2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
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

// hasCondition returns true when the statement has a non-empty Condition block.
func hasCondition(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "{}" && s != "null"
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
	// --- Lambda resource policies + function URLs
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
				cond := hasCondition(st.Condition)
				for _, res := range asList(st.Resource) {
					risks := AnalyzePattern(res)
					if len(risks) == 0 && !anon {
						continue
					}
					sev := findings.SevMedium
					if anon && !cond {
						sev = findings.SevHigh
					} else if anon && cond {
						sev = findings.SevMedium
					}
					title := classify(anon, risks)
					if cond {
						title += " (conditional)"
					}
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "apigw_lambda",
						Severity:    sev,
						ResourceARN: aws.ToString(fn.FunctionArn),
						Title:       fmt.Sprintf("Lambda %s: %s", name, title),
						Detail: map[string]any{
							"function":       name,
							"statement":      st,
							"anonymous":      anon,
							"has_condition":  cond,
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
					fnURL := aws.ToString(u.FunctionUrl)
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "apigw_lambda",
						Severity:    findings.SevHigh,
						ResourceARN: aws.ToString(fn.FunctionArn),
						Title:       fmt.Sprintf("Lambda %s: function URL with no auth", aws.ToString(fn.FunctionName)),
						Detail: map[string]any{
							"function": aws.ToString(fn.FunctionName),
							"url":      fnURL,
							"auth":     string(u.AuthType),
							"cors":     u.Cors,
							"curl":     fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' '%s'", fnURL),
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

	// --- API Gateway v1 REST APIs (paginated)
	acli := apigateway.NewFromConfig(t.Config, func(o *apigateway.Options) { o.Region = region })
	apiPager := apigateway.NewGetRestApisPaginator(acli, &apigateway.GetRestApisInput{})
	var restAPIs []apigateway.GetRestApisOutput
	for apiPager.HasMorePages() {
		page, err := apiPager.NextPage(ctx)
		if err != nil {
			break
		}
		restAPIs = append(restAPIs, *page)
	}

	for _, page := range restAPIs {
		for _, api := range page.Items {
			apiID := aws.ToString(api.Id)
			apiName := aws.ToString(api.Name)

			// Resource policy analysis (URL-decode the policy first).
			rawPol := aws.ToString(api.Policy)
			if rawPol != "" {
				decoded, err := url.QueryUnescape(rawPol)
				if err != nil {
					decoded = rawPol
				}
				var doc resourcePolicyDoc
				if err := json.Unmarshal([]byte(decoded), &doc); err == nil {
					for _, st := range doc.Statement {
						if !strings.EqualFold(st.Effect, "Allow") {
							continue
						}
						anon := isAnonymousPrincipal(st.Principal)
						cond := hasCondition(st.Condition)
						for _, res := range asList(st.Resource) {
							risks := AnalyzePattern(res)
							if len(risks) == 0 && !anon {
								continue
							}
							sev := findings.SevMedium
							if anon && !cond && len(risks) > 0 {
								sev = findings.SevCritical
							} else if anon && !cond {
								sev = findings.SevHigh
							}
							title := classify(anon, risks)
							if cond {
								title += " (conditional)"
							}
							_ = sink.Write(ctx, findings.Finding{
								AccountID:   t.AccountID,
								Region:      region,
								Module:      "apigw_lambda",
								Severity:    sev,
								ResourceARN: fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiID),
								Title:       fmt.Sprintf("REST API %s: %s", apiName, title),
								Detail: map[string]any{
									"api_id":         apiID,
									"api_name":       apiName,
									"resource":       res,
									"anonymous":      anon,
									"has_condition":  cond,
									"wildcard_risks": risks,
									"statement":      st,
								},
							})
						}
					}
				}
			}

			// Fetch deployed stages for curl URLs.
			stages, _ := acli.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
			var stageNames []string
			if stages != nil {
				for _, s := range stages.Item {
					stageNames = append(stageNames, aws.ToString(s.StageName))
				}
			}

			// Check each method for authorizationType NONE (skip OPTIONS — CORS preflight).
			resPager := apigateway.NewGetResourcesPaginator(acli, &apigateway.GetResourcesInput{
				RestApiId: api.Id,
				Embed:     []string{"methods"},
			})
			for resPager.HasMorePages() {
				resPage, err := resPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, res := range resPage.Items {
					path := aws.ToString(res.Path)
					for httpMethod, m := range res.ResourceMethods {
						if strings.EqualFold(httpMethod, "OPTIONS") {
							continue
						}
						authType := aws.ToString(m.AuthorizationType)
						if strings.EqualFold(authType, "NONE") {
							var curls []string
							for _, stage := range stageNames {
								u := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s%s", apiID, region, stage, path)
								curls = append(curls, fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' -X %s '%s'", httpMethod, u))
							}
							_ = sink.Write(ctx, findings.Finding{
								AccountID:   t.AccountID,
								Region:      region,
								Module:      "apigw_lambda",
								Severity:    findings.SevHigh,
								ResourceARN: fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiID),
								Title:       fmt.Sprintf("REST API %s: %s %s has no auth", apiName, httpMethod, path),
								Detail: map[string]any{
									"api_id":           apiID,
									"api_name":         apiName,
									"method":           httpMethod,
									"path":             path,
									"stages":           stageNames,
									"auth_type":        authType,
									"api_key_required": aws.ToBool(m.ApiKeyRequired),
									"curl":             curls,
								},
							})
						}
					}
				}
			}
		}
	}

	// --- API Gateway v2 HTTP/WebSocket APIs: check routes for auth (paginated)
	a2 := apigatewayv2.NewFromConfig(t.Config, func(o *apigatewayv2.Options) { o.Region = region })
	v2apis, err := a2.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err == nil {
		for _, api := range v2apis.Items {
			apiID := aws.ToString(api.ApiId)
			apiName := aws.ToString(api.Name)

			// Paginate routes
			var allRoutes []a2types.Route
			var nextToken *string
			for {
				routes, err := a2.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{
					ApiId:     api.ApiId,
					NextToken: nextToken,
				})
				if err != nil {
					break
				}
				allRoutes = append(allRoutes, routes.Items...)
				if routes.NextToken == nil {
					break
				}
				nextToken = routes.NextToken
			}

			for _, r := range allRoutes {
				if r.AuthorizationType == a2types.AuthorizationTypeNone || r.AuthorizationType == "" {
					endpoint := aws.ToString(api.ApiEndpoint)
					routeKey := aws.ToString(r.RouteKey)
					curl := buildV2Curl(endpoint, routeKey)
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "apigw_lambda",
						Severity:    findings.SevHigh,
						ResourceARN: fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s", region, apiID),
						Title:       fmt.Sprintf("APIGWv2 %s: route %s has no auth", apiName, routeKey),
						Detail: map[string]any{
							"api_id":    apiID,
							"api_name":  apiName,
							"route_key": routeKey,
							"endpoint":  endpoint,
							"protocol":  api.ProtocolType,
							"auth_type": string(r.AuthorizationType),
							"curl":      curl,
						},
					})
				}
			}
		}
	}

	return nil
}

// buildV2Curl turns an APIGWv2 endpoint + route key (e.g. "GET /users") into
// a curl command. $default routes use GET against the base endpoint.
func buildV2Curl(endpoint, routeKey string) string {
	method := "GET"
	path := "/"
	if routeKey != "$default" {
		parts := strings.SplitN(routeKey, " ", 2)
		if len(parts) == 2 {
			method = parts[0]
			path = parts[1]
		}
	}
	u := strings.TrimRight(endpoint, "/") + path
	return fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' -X %s '%s'", method, u)
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
