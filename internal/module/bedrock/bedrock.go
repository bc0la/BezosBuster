// Package bedrock reviews Amazon Bedrock for misconfigurations that expose
// generative-AI resources to unauthorized callers or weaken guardrails.
//
// Coverage:
//
//   - Public / cross-account exposure: resource policies on agents, agent
//     aliases, knowledge bases, prompts, and flows checked for "*"
//     principals or wildcard-crossing cross-account ARNs (same pattern as
//     the apigw_lambda analyzer).
//   - Knowledge-base S3 data sources whose buckets are themselves publicly
//     readable — chained exposure of training/RAG content via the agent.
//   - OpenSearch Serverless collections backing KBs whose data-access or
//     network policies allow wildcard public access.
//   - Guardrails: agents without a guardrailIdentifier, guardrails with
//     filter thresholds set to NONE on HATE/VIOLENCE/etc, and guardrails
//     missing a sensitiveInformationPolicy (no PII filtering).
//   - Action-group risk: Lambda executors with wildcard trust policies,
//     HTTP/OpenAPI action groups pointing at internal endpoints (SSRF),
//     and agent execution roles with AdministratorAccess / s3:* etc.
//   - Data-exfil chain: KB-S3-source bucket the agent exec role can also
//     write to.
package bedrock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedtypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	batypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "bedrock" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"bedrock-agent:ListAgents", "bedrock-agent:GetAgent",
		"bedrock-agent:ListAgentAliases", "bedrock-agent:GetAgentAlias",
		"bedrock-agent:ListAgentActionGroups", "bedrock-agent:GetAgentActionGroup",
		"bedrock-agent:ListKnowledgeBases", "bedrock-agent:GetKnowledgeBase",
		"bedrock-agent:ListDataSources", "bedrock-agent:GetDataSource",
		"bedrock-agent:ListPrompts", "bedrock-agent:ListFlows",
		"bedrock:GetResourcePolicy",
		"bedrock:ListGuardrails", "bedrock:GetGuardrail",
		"iam:GetRolePolicy", "iam:ListRolePolicies",
		"iam:ListAttachedRolePolicies",
		"lambda:GetPolicy",
		"aoss:ListAccessPolicies", "aoss:GetAccessPolicy",
		"aoss:ListSecurityPolicies", "aoss:GetSecurityPolicy",
		"s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicyStatus", "s3:GetBucketAcl",
	}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			// Bedrock is not available in every region — only surface real errors.
			if !isUnsupportedRegion(err) {
				_ = sink.LogEvent(ctx, "bedrock", t.AccountID, "warn", region+": "+err.Error())
			}
		}
	}
	return nil
}

// resourcePolicyDoc / resourcePolicyStmt are the bare-minimum shape we read
// out of any AWS resource policy JSON.
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

// crossAccountPrincipal returns the list of distinct account IDs referenced
// in a Principal block. A "*" principal is reported separately by
// isAnonymousPrincipal; here we look for explicit cross-account ARNs.
func crossAccountPrincipals(raw json.RawMessage, selfAccount string) []string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, v := range m {
		for _, p := range asList(v) {
			// principal can be ARN or bare account id
			parts := strings.Split(p, ":")
			var acct string
			if len(parts) >= 5 {
				acct = parts[4]
			} else if isAccountID(p) {
				acct = p
			}
			if acct == "" || acct == selfAccount {
				continue
			}
			if acct == "*" {
				seen["*"] = true
				continue
			}
			seen[acct] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

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

// isUnsupportedRegion returns true for the typical "service not in this
// region" / "endpoint not found" cases we hit when iterating all regions.
func isUnsupportedRegion(err error) bool {
	if err == nil {
		return false
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		c := ae.ErrorCode()
		if c == "UnrecognizedClientException" || c == "EndpointConnectionError" || c == "OptInRequired" {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "no endpoint") ||
		strings.Contains(msg, "could not be reached") ||
		strings.Contains(msg, "Bedrock is not available")
}

// isNotFound covers ResourceNotFoundException / AccessDeniedException-on-missing
// returned by bedrock:GetResourcePolicy when no policy is attached.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		c := ae.ErrorCode()
		if c == "ResourceNotFoundException" || c == "NoSuchResourcePolicy" {
			return true
		}
	}
	return false
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	bacli := bedrockagent.NewFromConfig(t.Config, func(o *bedrockagent.Options) { o.Region = region })
	bcli := bedrock.NewFromConfig(t.Config, func(o *bedrock.Options) { o.Region = region })

	// First, list agents and gather everything we need to cross-reference
	// (exec roles, attached KBs, guardrail status).
	agents, err := listAgents(ctx, bacli)
	if err != nil {
		return fmt.Errorf("list agents: %w", err)
	}

	// roleAnalysisCache memoizes IAM role permission lookups across an
	// account so we don't re-fetch policies for shared roles.
	roleCache := map[string]roleAnalysis{}
	icli := iam.NewFromConfig(t.Config)
	lcli := lambda.NewFromConfig(t.Config, func(o *lambda.Options) { o.Region = region })

	for _, sum := range agents {
		ag, err := bacli.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: sum.AgentId})
		if err != nil || ag.Agent == nil {
			continue
		}
		scanAgent(ctx, t, region, ag.Agent, bacli, bcli, icli, lcli, roleCache, sink)
	}

	// Knowledge bases live independently of agents.
	kbs, _ := listKnowledgeBases(ctx, bacli)
	osCli := opensearchserverless.NewFromConfig(t.Config, func(o *opensearchserverless.Options) { o.Region = region })
	s3Cli := s3.NewFromConfig(t.Config, func(o *s3.Options) { o.Region = region })

	for _, ksum := range kbs {
		kb, err := bacli.GetKnowledgeBase(ctx, &bedrockagent.GetKnowledgeBaseInput{KnowledgeBaseId: ksum.KnowledgeBaseId})
		if err != nil || kb.KnowledgeBase == nil {
			continue
		}
		scanKnowledgeBase(ctx, t, region, kb.KnowledgeBase, bacli, bcli, osCli, s3Cli, icli, roleCache, sink)
	}

	// Prompts and flows — resource-policy-only checks.
	scanPromptResourcePolicies(ctx, t, region, bacli, bcli, sink)
	scanFlowResourcePolicies(ctx, t, region, bacli, bcli, sink)

	// Guardrails.
	scanGuardrails(ctx, t, region, bcli, sink)

	return nil
}

// ---------- Agents ----------

func listAgents(ctx context.Context, cli *bedrockagent.Client) ([]batypes.AgentSummary, error) {
	var out []batypes.AgentSummary
	var next *string
	for {
		page, err := cli.ListAgents(ctx, &bedrockagent.ListAgentsInput{NextToken: next})
		if err != nil {
			return out, err
		}
		out = append(out, page.AgentSummaries...)
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
	return out, nil
}

func listKnowledgeBases(ctx context.Context, cli *bedrockagent.Client) ([]batypes.KnowledgeBaseSummary, error) {
	var out []batypes.KnowledgeBaseSummary
	var next *string
	for {
		page, err := cli.ListKnowledgeBases(ctx, &bedrockagent.ListKnowledgeBasesInput{NextToken: next})
		if err != nil {
			return out, err
		}
		out = append(out, page.KnowledgeBaseSummaries...)
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
	return out, nil
}

func scanAgent(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	ag *batypes.Agent,
	bacli *bedrockagent.Client,
	bcli *bedrock.Client,
	icli *iam.Client,
	lcli *lambda.Client,
	roleCache map[string]roleAnalysis,
	sink findings.Sink,
) {
	agentArn := aws.ToString(ag.AgentArn)
	agentName := aws.ToString(ag.AgentName)

	// 1) Missing guardrail.
	if ag.GuardrailConfiguration == nil || aws.ToString(ag.GuardrailConfiguration.GuardrailIdentifier) == "" {
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      region,
			Module:      "bedrock",
			Severity:    findings.SevMedium,
			ResourceARN: agentArn,
			Title:       fmt.Sprintf("Bedrock agent %s has no guardrail configured", agentName),
			Detail: map[string]any{
				"agent_id":   aws.ToString(ag.AgentId),
				"agent_name": agentName,
				"reason":     "agent invokes a foundation model without any guardrailIdentifier — no content/PII/topic filtering",
			},
		})
	}

	// 2) Execution role analysis.
	if roleArn := aws.ToString(ag.AgentResourceRoleArn); roleArn != "" {
		ra := analyzeRole(ctx, icli, roleArn, roleCache)
		if len(ra.Dangerous) > 0 {
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "bedrock",
				Severity:    ra.Sev,
				ResourceARN: agentArn,
				Title:       fmt.Sprintf("Bedrock agent %s: execution role grants %s", agentName, strings.Join(ra.Dangerous, ", ")),
				Detail: map[string]any{
					"agent_id":   aws.ToString(ag.AgentId),
					"role_arn":   roleArn,
					"dangerous":  ra.Dangerous,
					"managed":    ra.Managed,
					"inline":     ra.InlineStmts,
				},
			})
		}
	}

	// 3) Resource policy on the agent itself.
	checkBedrockResourcePolicy(ctx, t, region, bcli, agentArn,
		fmt.Sprintf("Bedrock agent %s", agentName), "agent", sink)

	// 4) Action groups (use DRAFT version — the working copy).
	scanActionGroups(ctx, t, region, ag, bacli, lcli, sink)

	// 5) Agent aliases — each can be shared cross-account separately.
	scanAgentAliases(ctx, t, region, ag, bacli, bcli, sink)
}

func scanActionGroups(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	ag *batypes.Agent,
	bacli *bedrockagent.Client,
	lcli *lambda.Client,
	sink findings.Sink,
) {
	agentID := aws.ToString(ag.AgentId)
	agentName := aws.ToString(ag.AgentName)
	agentArn := aws.ToString(ag.AgentArn)

	var next *string
	for {
		page, err := bacli.ListAgentActionGroups(ctx, &bedrockagent.ListAgentActionGroupsInput{
			AgentId:      ag.AgentId,
			AgentVersion: aws.String("DRAFT"),
			NextToken:    next,
		})
		if err != nil {
			return
		}
		for _, agSum := range page.ActionGroupSummaries {
			det, err := bacli.GetAgentActionGroup(ctx, &bedrockagent.GetAgentActionGroupInput{
				AgentId:       ag.AgentId,
				AgentVersion:  aws.String("DRAFT"),
				ActionGroupId: agSum.ActionGroupId,
			})
			if err != nil || det.AgentActionGroup == nil {
				continue
			}
			grp := det.AgentActionGroup
			groupName := aws.ToString(grp.ActionGroupName)

			// Lambda executor: pivot to lambda resource policy and look
			// for anonymous / wildcard principals.
			if exe, ok := grp.ActionGroupExecutor.(*batypes.ActionGroupExecutorMemberLambda); ok && exe != nil {
				fnArn := exe.Value
				pol, err := lcli.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(fnArn)})
				if err == nil && pol.Policy != nil {
					var doc resourcePolicyDoc
					if json.Unmarshal([]byte(aws.ToString(pol.Policy)), &doc) == nil {
						for _, st := range doc.Statement {
							if !strings.EqualFold(st.Effect, "Allow") {
								continue
							}
							if !isAnonymousPrincipal(st.Principal) {
								continue
							}
							sev := findings.SevHigh
							if hasCondition(st.Condition) {
								sev = findings.SevMedium
							}
							_ = sink.Write(ctx, findings.Finding{
								AccountID:   t.AccountID,
								Region:      region,
								Module:      "bedrock",
								Severity:    sev,
								ResourceARN: agentArn,
								Title:       fmt.Sprintf("Bedrock agent %s: action group %s Lambda has wildcard trust policy", agentName, groupName),
								Detail: map[string]any{
									"agent_id":      agentID,
									"action_group":  groupName,
									"lambda_arn":    fnArn,
									"statement":     st,
									"has_condition": hasCondition(st.Condition),
								},
							})
						}
					}
				}
			}

			// OpenAPI / HTTP schemas: scan payload for internal endpoints.
			if grp.ApiSchema != nil {
				var schemaBody string
				switch s := grp.ApiSchema.(type) {
				case *batypes.APISchemaMemberPayload:
					schemaBody = s.Value
				case *batypes.APISchemaMemberS3:
					schemaBody = fmt.Sprintf("s3://%s/%s",
						aws.ToString(s.Value.S3BucketName),
						aws.ToString(s.Value.S3ObjectKey))
				}
				if internal := internalEndpoints(schemaBody); len(internal) > 0 {
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "bedrock",
						Severity:    findings.SevHigh,
						ResourceARN: agentArn,
						Title:       fmt.Sprintf("Bedrock agent %s: action group %s OpenAPI schema targets internal endpoint", agentName, groupName),
						Detail: map[string]any{
							"agent_id":     agentID,
							"action_group": groupName,
							"endpoints":    internal,
							"reason":       "agent action-group HTTP schema points at RFC1918 / metadata / .internal hosts — possible SSRF pivot",
						},
					})
				}
			}
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
}

// internalEndpoints scans an OpenAPI/JSON/YAML schema body for URLs that
// resolve to clearly-internal targets: RFC1918, link-local (169.254/16,
// notably the EC2 metadata service), localhost, and *.internal hostnames.
func internalEndpoints(body string) []string {
	if body == "" {
		return nil
	}
	var hits []string
	// Cheap scanner: look for "http://...":  find every scheme prefix and
	// pull the host out.
	for _, scheme := range []string{"http://", "https://"} {
		for i := 0; ; {
			idx := strings.Index(body[i:], scheme)
			if idx < 0 {
				break
			}
			start := i + idx + len(scheme)
			end := start
			for end < len(body) && !isURLBoundary(body[end]) {
				end++
			}
			raw := body[start:end]
			i = end
			u, err := url.Parse(scheme + raw)
			if err != nil {
				continue
			}
			host := u.Hostname()
			if isInternalHost(host) {
				hits = append(hits, scheme+raw)
			}
		}
	}
	return hits
}

func isURLBoundary(c byte) bool {
	switch c {
	case '"', '\'', ' ', '\t', '\n', '\r', ',', ')', ']', '}', '>', '<':
		return true
	}
	return false
}

func isInternalHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return true
	}
	if strings.Contains(host, ".compute.internal") || strings.Contains(host, ".ec2.internal") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	return false
}

func scanAgentAliases(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	ag *batypes.Agent,
	bacli *bedrockagent.Client,
	bcli *bedrock.Client,
	sink findings.Sink,
) {
	var next *string
	for {
		page, err := bacli.ListAgentAliases(ctx, &bedrockagent.ListAgentAliasesInput{
			AgentId:   ag.AgentId,
			NextToken: next,
		})
		if err != nil {
			return
		}
		for _, alSum := range page.AgentAliasSummaries {
			det, err := bacli.GetAgentAlias(ctx, &bedrockagent.GetAgentAliasInput{
				AgentId:      ag.AgentId,
				AgentAliasId: alSum.AgentAliasId,
			})
			if err != nil || det.AgentAlias == nil {
				continue
			}
			aliasArn := aws.ToString(det.AgentAlias.AgentAliasArn)
			aliasName := aws.ToString(det.AgentAlias.AgentAliasName)
			checkBedrockResourcePolicy(ctx, t, region, bcli, aliasArn,
				fmt.Sprintf("Bedrock agent %s alias %s", aws.ToString(ag.AgentName), aliasName),
				"agent_alias", sink)
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
}

// ---------- Knowledge bases ----------

func scanKnowledgeBase(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	kb *batypes.KnowledgeBase,
	bacli *bedrockagent.Client,
	bcli *bedrock.Client,
	osCli *opensearchserverless.Client,
	s3Cli *s3.Client,
	icli *iam.Client,
	roleCache map[string]roleAnalysis,
	sink findings.Sink,
) {
	kbArn := aws.ToString(kb.KnowledgeBaseArn)
	kbName := aws.ToString(kb.Name)

	// Resource policy on the KB itself.
	checkBedrockResourcePolicy(ctx, t, region, bcli, kbArn,
		fmt.Sprintf("Bedrock knowledge base %s", kbName), "knowledge_base", sink)

	// Storage backing — check OpenSearch Serverless network/data policies.
	if kb.StorageConfiguration != nil && kb.StorageConfiguration.OpensearchServerlessConfiguration != nil {
		colArn := aws.ToString(kb.StorageConfiguration.OpensearchServerlessConfiguration.CollectionArn)
		if colName := openSearchCollectionName(colArn); colName != "" {
			scanOpenSearchCollection(ctx, t, region, kbArn, kbName, colArn, colName, osCli, sink)
		}
	}

	// KB execution-role analysis (separate from agent roles).
	kbRoleArn := aws.ToString(kb.RoleArn)
	if kbRoleArn != "" {
		ra := analyzeRole(ctx, icli, kbRoleArn, roleCache)
		if len(ra.Dangerous) > 0 {
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "bedrock",
				Severity:    ra.Sev,
				ResourceARN: kbArn,
				Title:       fmt.Sprintf("Bedrock KB %s: execution role grants %s", kbName, strings.Join(ra.Dangerous, ", ")),
				Detail: map[string]any{
					"knowledge_base_id": aws.ToString(kb.KnowledgeBaseId),
					"role_arn":          kbRoleArn,
					"dangerous":         ra.Dangerous,
				},
			})
		}
	}

	// Data sources — S3 chained-public-read + exec-role write-back exfil.
	var next *string
	for {
		page, err := bacli.ListDataSources(ctx, &bedrockagent.ListDataSourcesInput{
			KnowledgeBaseId: kb.KnowledgeBaseId,
			NextToken:       next,
		})
		if err != nil {
			return
		}
		for _, ds := range page.DataSourceSummaries {
			d, err := bacli.GetDataSource(ctx, &bedrockagent.GetDataSourceInput{
				KnowledgeBaseId: kb.KnowledgeBaseId,
				DataSourceId:    ds.DataSourceId,
			})
			if err != nil || d.DataSource == nil || d.DataSource.DataSourceConfiguration == nil {
				continue
			}
			s3cfg := d.DataSource.DataSourceConfiguration.S3Configuration
			if s3cfg == nil {
				continue
			}
			bucket := bucketFromArn(aws.ToString(s3cfg.BucketArn))
			if bucket == "" {
				continue
			}
			if isPublic, why := isBucketPublic(ctx, s3Cli, bucket); isPublic {
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "bedrock",
					Severity:    findings.SevHigh,
					ResourceARN: kbArn,
					Title:       fmt.Sprintf("Bedrock KB %s ingests from public S3 bucket %s", kbName, bucket),
					Detail: map[string]any{
						"knowledge_base_id": aws.ToString(kb.KnowledgeBaseId),
						"data_source_id":    aws.ToString(d.DataSource.DataSourceId),
						"bucket":            bucket,
						"reason":            why,
					},
				})
			}
			// Exfil chain: KB exec role can also write to this bucket.
			if kbRoleArn != "" {
				ra := analyzeRole(ctx, icli, kbRoleArn, roleCache)
				if ra.AllowsS3WriteAll {
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "bedrock",
						Severity:    findings.SevHigh,
						ResourceARN: kbArn,
						Title:       fmt.Sprintf("Bedrock KB %s: exec role can read AND write S3 bucket %s (exfil chain)", kbName, bucket),
						Detail: map[string]any{
							"knowledge_base_id": aws.ToString(kb.KnowledgeBaseId),
							"bucket":            bucket,
							"role_arn":          kbRoleArn,
							"reason":            "agent ingesting from this bucket can overwrite its objects — combined with prompt injection this is a data-exfil path",
						},
					})
				}
			}
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
}

func openSearchCollectionName(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	res := parts[5]
	// "collection/<id-or-name>"
	if !strings.HasPrefix(res, "collection/") {
		return ""
	}
	return strings.TrimPrefix(res, "collection/")
}

func bucketFromArn(arn string) string {
	if !strings.HasPrefix(arn, "arn:aws:s3:::") {
		return ""
	}
	return strings.TrimPrefix(arn, "arn:aws:s3:::")
}

func scanOpenSearchCollection(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	kbArn, kbName, colArn, colName string,
	osCli *opensearchserverless.Client,
	sink findings.Sink,
) {
	resourceFilter := []string{"collection/" + colName}

	// Data-access policies.
	dataPager := opensearchserverless.NewListAccessPoliciesPaginator(osCli, &opensearchserverless.ListAccessPoliciesInput{
		Type:     "data",
		Resource: resourceFilter,
	})
	for dataPager.HasMorePages() {
		page, err := dataPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, pSum := range page.AccessPolicySummaries {
			det, err := osCli.GetAccessPolicy(ctx, &opensearchserverless.GetAccessPolicyInput{
				Name: pSum.Name,
				Type: "data",
			})
			if err != nil || det.AccessPolicyDetail == nil {
				continue
			}
			raw, err := json.Marshal(det.AccessPolicyDetail.Policy)
			if err != nil {
				continue
			}
			if widePrincipals := wildcardPrincipalsInOSSDoc(raw); len(widePrincipals) > 0 {
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "bedrock",
					Severity:    findings.SevHigh,
					ResourceARN: kbArn,
					Title:       fmt.Sprintf("Bedrock KB %s: OpenSearch Serverless data policy %s allows wildcard principals", kbName, aws.ToString(pSum.Name)),
					Detail: map[string]any{
						"collection_arn":   colArn,
						"collection_name":  colName,
						"policy_name":      aws.ToString(pSum.Name),
						"wide_principals":  widePrincipals,
						"reason":           "the data-access policy backing this KB grants index/document access to wildcard principals",
					},
				})
			}
		}
	}

	// Network policies.
	netPager := opensearchserverless.NewListSecurityPoliciesPaginator(osCli, &opensearchserverless.ListSecurityPoliciesInput{
		Type:     "network",
		Resource: resourceFilter,
	})
	for netPager.HasMorePages() {
		page, err := netPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, pSum := range page.SecurityPolicySummaries {
			det, err := osCli.GetSecurityPolicy(ctx, &opensearchserverless.GetSecurityPolicyInput{
				Name: pSum.Name,
				Type: "network",
			})
			if err != nil || det.SecurityPolicyDetail == nil {
				continue
			}
			raw, err := json.Marshal(det.SecurityPolicyDetail.Policy)
			if err != nil {
				continue
			}
			if publicAccess(raw) {
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "bedrock",
					Severity:    findings.SevHigh,
					ResourceARN: kbArn,
					Title:       fmt.Sprintf("Bedrock KB %s: OpenSearch Serverless collection has public network policy", kbName),
					Detail: map[string]any{
						"collection_arn":  colArn,
						"collection_name": colName,
						"policy_name":     aws.ToString(pSum.Name),
						"reason":          "AllowFromPublic=true on the network policy — collection reachable from anywhere on the internet",
					},
				})
			}
		}
	}
}

// wildcardPrincipalsInOSSDoc walks an OpenSearch Serverless data-access policy
// JSON (which is an array of {Rules, Principal, Description}) and returns the
// list of Principal entries that are "*" or grant index/data access to any
// caller.
func wildcardPrincipalsInOSSDoc(raw []byte) []string {
	var doc []struct {
		Principal []string `json:"Principal"`
		Rules     []any    `json:"Rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var hits []string
	for _, entry := range doc {
		for _, p := range entry.Principal {
			ps := strings.TrimSpace(p)
			if ps == "*" || ps == "principal:*" {
				hits = append(hits, p)
			}
		}
	}
	return hits
}

// publicAccess returns true if the network policy contains
// "AllowFromPublic": true on any rule.
func publicAccess(raw []byte) bool {
	var doc []struct {
		AllowFromPublic bool `json:"AllowFromPublic"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false
	}
	for _, entry := range doc {
		if entry.AllowFromPublic {
			return true
		}
	}
	return false
}

// ---------- Prompts and flows ----------

func scanPromptResourcePolicies(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	bacli *bedrockagent.Client,
	bcli *bedrock.Client,
	sink findings.Sink,
) {
	var next *string
	for {
		page, err := bacli.ListPrompts(ctx, &bedrockagent.ListPromptsInput{NextToken: next})
		if err != nil {
			return
		}
		for _, p := range page.PromptSummaries {
			arn := aws.ToString(p.Arn)
			checkBedrockResourcePolicy(ctx, t, region, bcli, arn,
				fmt.Sprintf("Bedrock prompt %s", aws.ToString(p.Name)), "prompt", sink)
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
}

func scanFlowResourcePolicies(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	bacli *bedrockagent.Client,
	bcli *bedrock.Client,
	sink findings.Sink,
) {
	var next *string
	for {
		page, err := bacli.ListFlows(ctx, &bedrockagent.ListFlowsInput{NextToken: next})
		if err != nil {
			return
		}
		for _, f := range page.FlowSummaries {
			arn := aws.ToString(f.Arn)
			checkBedrockResourcePolicy(ctx, t, region, bcli, arn,
				fmt.Sprintf("Bedrock flow %s", aws.ToString(f.Name)), "flow", sink)
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
}

// checkBedrockResourcePolicy fetches the resource policy for a Bedrock
// resource ARN and emits findings for wildcard or cross-account grants.
func checkBedrockResourcePolicy(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	bcli *bedrock.Client,
	arn, label, kind string,
	sink findings.Sink,
) {
	pol, err := bcli.GetResourcePolicy(ctx, &bedrock.GetResourcePolicyInput{ResourceArn: aws.String(arn)})
	if err != nil {
		if !isNotFound(err) {
			_ = sink.LogEvent(ctx, "bedrock", t.AccountID, "debug",
				fmt.Sprintf("get policy %s: %s", arn, err.Error()))
		}
		return
	}
	body := aws.ToString(pol.ResourcePolicy)
	if body == "" {
		return
	}
	var doc resourcePolicyDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return
	}
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		anon := isAnonymousPrincipal(st.Principal)
		xacct := crossAccountPrincipals(st.Principal, t.AccountID)
		if !anon && len(xacct) == 0 {
			continue
		}
		cond := hasCondition(st.Condition)
		sev := findings.SevMedium
		switch {
		case anon && !cond:
			sev = findings.SevCritical
		case anon && cond:
			sev = findings.SevHigh
		case sliceContains(xacct, "*") && !cond:
			sev = findings.SevHigh
		}
		var title string
		switch {
		case anon:
			title = label + ": resource policy allows anonymous (*) principal"
		default:
			title = label + ": resource policy shared cross-account with " + strings.Join(xacct, ",")
		}
		if cond {
			title += " (conditional)"
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      region,
			Module:      "bedrock",
			Severity:    sev,
			ResourceARN: arn,
			Title:       title,
			Detail: map[string]any{
				"resource_kind":   kind,
				"anonymous":       anon,
				"cross_accounts":  xacct,
				"has_condition":   cond,
				"statement":       st,
			},
		})
	}
}

func sliceContains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// ---------- Guardrails ----------

func scanGuardrails(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	bcli *bedrock.Client,
	sink findings.Sink,
) {
	var next *string
	for {
		page, err := bcli.ListGuardrails(ctx, &bedrock.ListGuardrailsInput{NextToken: next})
		if err != nil {
			return
		}
		for _, g := range page.Guardrails {
			det, err := bcli.GetGuardrail(ctx, &bedrock.GetGuardrailInput{
				GuardrailIdentifier: g.Id,
				GuardrailVersion:    g.Version,
			})
			if err != nil {
				continue
			}
			analyzeGuardrail(ctx, t, region, det, sink)
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
}

func analyzeGuardrail(
	ctx context.Context,
	t creds.AccountTarget,
	region string,
	g *bedrock.GetGuardrailOutput,
	sink findings.Sink,
) {
	arn := aws.ToString(g.GuardrailArn)
	name := aws.ToString(g.Name)

	var weakFilters []string
	if g.ContentPolicy != nil {
		for _, f := range g.ContentPolicy.Filters {
			if f.Type == bedtypes.GuardrailContentFilterTypeHate ||
				f.Type == bedtypes.GuardrailContentFilterTypeViolence ||
				f.Type == bedtypes.GuardrailContentFilterTypePromptAttack {
				if f.InputStrength == bedtypes.GuardrailFilterStrengthNone ||
					f.OutputStrength == bedtypes.GuardrailFilterStrengthNone {
					weakFilters = append(weakFilters,
						fmt.Sprintf("%s (in=%s out=%s)", f.Type, f.InputStrength, f.OutputStrength))
				}
			}
		}
	}
	if len(weakFilters) > 0 {
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      region,
			Module:      "bedrock",
			Severity:    findings.SevMedium,
			ResourceARN: arn,
			Title:       fmt.Sprintf("Bedrock guardrail %s has weak filter thresholds: %s", name, strings.Join(weakFilters, ", ")),
			Detail: map[string]any{
				"guardrail_id":   aws.ToString(g.GuardrailId),
				"weak_filters":   weakFilters,
				"reason":         "NONE on these filter types means the model can produce harmful content without intervention",
			},
		})
	}

	if g.SensitiveInformationPolicy == nil ||
		(len(g.SensitiveInformationPolicy.PiiEntities) == 0 && len(g.SensitiveInformationPolicy.Regexes) == 0) {
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      region,
			Module:      "bedrock",
			Severity:    findings.SevMedium,
			ResourceARN: arn,
			Title:       fmt.Sprintf("Bedrock guardrail %s does not block PII", name),
			Detail: map[string]any{
				"guardrail_id": aws.ToString(g.GuardrailId),
				"reason":       "no sensitiveInformationPolicyConfig — sensitive data can pass through prompts or responses",
			},
		})
	}
}

// ---------- Role analysis ----------

type roleAnalysis struct {
	Dangerous        []string
	Managed          []string
	InlineStmts      []map[string]any
	AllowsS3WriteAll bool
	Sev              findings.Severity
}

func analyzeRole(ctx context.Context, icli *iam.Client, roleArn string, cache map[string]roleAnalysis) roleAnalysis {
	if r, ok := cache[roleArn]; ok {
		return r
	}
	out := roleAnalysis{Sev: findings.SevMedium}
	roleName := iamRoleNameFromArn(roleArn)
	if roleName == "" {
		cache[roleArn] = out
		return out
	}

	// Managed policies.
	attached, err := icli.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, p := range attached.AttachedPolicies {
			name := aws.ToString(p.PolicyName)
			out.Managed = append(out.Managed, name)
			if desc, ok := dangerousManagedPolicies[name]; ok {
				out.Dangerous = append(out.Dangerous, name+" ("+desc+")")
				if name == "AdministratorAccess" || name == "PowerUserAccess" {
					out.Sev = findings.SevHigh
				}
			}
			if name == "AmazonS3FullAccess" || name == "AdministratorAccess" || name == "PowerUserAccess" {
				out.AllowsS3WriteAll = true
			}
		}
	}

	// Inline policies.
	inline, err := icli.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(roleName)})
	if err == nil {
		for _, pname := range inline.PolicyNames {
			doc, err := icli.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(pname),
			})
			if err != nil || doc.PolicyDocument == nil {
				continue
			}
			decoded, err := url.QueryUnescape(aws.ToString(doc.PolicyDocument))
			if err != nil {
				decoded = aws.ToString(doc.PolicyDocument)
			}
			var pd resourcePolicyDoc
			if err := json.Unmarshal([]byte(decoded), &pd); err != nil {
				continue
			}
			for _, st := range pd.Statement {
				if !strings.EqualFold(st.Effect, "Allow") {
					continue
				}
				actions := asList(st.Action)
				for _, a := range actions {
					if a == "*" {
						out.Dangerous = append(out.Dangerous, "inline `*` on `*`")
						out.AllowsS3WriteAll = true
						out.Sev = findings.SevHigh
					}
					if a == "s3:*" {
						out.Dangerous = append(out.Dangerous, "inline `s3:*`")
						out.AllowsS3WriteAll = true
					}
					if strings.HasPrefix(a, "s3:Put") || strings.HasPrefix(a, "s3:Delete") {
						out.AllowsS3WriteAll = true
					}
				}
				out.InlineStmts = append(out.InlineStmts, map[string]any{
					"policy":   pname,
					"actions":  actions,
					"resource": asList(st.Resource),
				})
			}
		}
	}

	if out.Sev == "" {
		out.Sev = findings.SevMedium
	}
	cache[roleArn] = out
	return out
}

func iamRoleNameFromArn(arn string) string {
	// arn:aws:iam::<acct>:role/<path>/<name> — name is the last segment.
	if !strings.HasPrefix(arn, "arn:aws:iam::") {
		return ""
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	res := parts[5]
	if !strings.HasPrefix(res, "role/") {
		return ""
	}
	res = strings.TrimPrefix(res, "role/")
	if i := strings.LastIndex(res, "/"); i >= 0 {
		return res[i+1:]
	}
	return res
}

var dangerousManagedPolicies = map[string]string{
	"AdministratorAccess":         "full admin access",
	"PowerUserAccess":             "full access except IAM",
	"AmazonS3FullAccess":          "full S3 access",
	"AmazonDynamoDBFullAccess":    "full DynamoDB access",
	"AmazonSQSFullAccess":         "full SQS access",
	"AmazonSNSFullAccess":         "full SNS access",
	"IAMFullAccess":               "full IAM access",
	"AWSLambda_FullAccess":        "full Lambda access",
	"AmazonEC2FullAccess":         "full EC2 access",
	"AmazonSSMFullAccess":         "full SSM access",
	"SecretsManagerReadWrite":     "read/write Secrets Manager",
	"AmazonBedrockFullAccess":     "full Bedrock access",
}

// ---------- S3 publicness ----------

func isBucketPublic(ctx context.Context, cli *s3.Client, bucket string) (bool, string) {
	// Cheap fast-path: PublicAccessBlock. If all four flags are true, we're
	// safe; if any is missing, fall through and check policy/ACL.
	pab, err := cli.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucket)})
	allBlocked := false
	if err == nil && pab.PublicAccessBlockConfiguration != nil {
		c := pab.PublicAccessBlockConfiguration
		allBlocked = aws.ToBool(c.BlockPublicAcls) &&
			aws.ToBool(c.IgnorePublicAcls) &&
			aws.ToBool(c.BlockPublicPolicy) &&
			aws.ToBool(c.RestrictPublicBuckets)
	}
	if allBlocked {
		return false, "BPA fully blocks public access"
	}

	status, err := cli.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String(bucket)})
	if err == nil && status.PolicyStatus != nil && aws.ToBool(status.PolicyStatus.IsPublic) {
		return true, "bucket policy marks the bucket as public"
	}

	acl, err := cli.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(bucket)})
	if err == nil {
		for _, g := range acl.Grants {
			if g.Grantee == nil {
				continue
			}
			if g.Grantee.Type == s3types.TypeGroup {
				uri := aws.ToString(g.Grantee.URI)
				if uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
					uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
					return true, "ACL grants " + uri
				}
			}
		}
	}
	return false, ""
}

// ensure unused-import guard for iamtypes — used implicitly when callers
// (here, only the role-cache) rely on the iam SDK; this prevents drift if
// further iam-type-based analysis is added later.
var _ iamtypes.Role
