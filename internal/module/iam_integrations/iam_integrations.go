// Package iam_integrations reviews AWS identity federation for
// misconfigurations and potential role-takeover paths. It covers:
//
//   - IAM identity providers (SAML + OIDC): enumerated, cross-referenced
//     against roles that trust them, checked for orphans and expiry.
//   - IAM role trust policies: condition-aware analysis of trust policies
//     that permit sts:AssumeRole, sts:AssumeRoleWithSAML, and especially
//     sts:AssumeRoleWithWebIdentity. Flags missing `:aud` / `:sub`
//     conditions, wildcard principals, and GitHub/GitLab/EKS OIDC subject
//     patterns that accept untrusted repositories / branches / PRs / pods.
//   - Cross-account sts:AssumeRole without sts:ExternalId (confused deputy).
//   - Cognito identity pools: `AllowUnauthenticatedIdentities=true`,
//     classic flow, and dangerous permissions on the unauthenticated role.
package iam_integrations

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "iam_integrations" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"iam:ListSAMLProviders", "iam:GetSAMLProvider",
		"iam:ListOpenIDConnectProviders", "iam:GetOpenIDConnectProvider",
		"iam:ListRoles", "iam:GetRole",
		"iam:ListAttachedRolePolicies",
		"cognito-identity:ListIdentityPools",
		"cognito-identity:DescribeIdentityPool",
		"cognito-identity:GetIdentityPoolRoles",
	}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	icli := iam.NewFromConfig(t.Config)

	// Enumerate all roles once — used by provider cross-reference and trust
	// policy analysis.
	roles, err := listAllRoles(ctx, icli)
	if err != nil {
		return fmt.Errorf("list roles: %w", err)
	}

	// Collect sets of provider ARNs referenced by any role's trust policy.
	referencedProviders := map[string]bool{}
	for _, r := range roles {
		for _, p := range referencedFederatedPrincipals(r) {
			referencedProviders[p] = true
		}
	}

	// IAM identity providers.
	if err := scanSAMLProviders(ctx, icli, t, sink, referencedProviders); err != nil {
		_ = sink.LogEvent(ctx, "iam_integrations", t.AccountID, "warn", "saml: "+err.Error())
	}
	oidcProviders, err := scanOIDCProviders(ctx, icli, t, sink, referencedProviders)
	if err != nil {
		_ = sink.LogEvent(ctx, "iam_integrations", t.AccountID, "warn", "oidc: "+err.Error())
	}

	// Role trust policies — condition-aware review.
	if err := scanRoleTrustPolicies(ctx, icli, t, sink, roles, oidcProviders); err != nil {
		_ = sink.LogEvent(ctx, "iam_integrations", t.AccountID, "warn", "trust policies: "+err.Error())
	}

	// Cognito identity pools (per region).
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanCognitoIdentityPools(ctx, icli, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "iam_integrations", t.AccountID, "warn", "cognito "+region+": "+err.Error())
		}
	}
	return nil
}

// ---------- helpers: role enumeration + trust policy types ----------

func listAllRoles(ctx context.Context, cli *iam.Client) ([]iamtypes.Role, error) {
	var out []iamtypes.Role
	var marker *string
	for {
		resp, err := cli.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Roles...)
		if resp.Marker == nil {
			break
		}
		marker = resp.Marker
	}
	return out, nil
}

// isServiceLinkedRole returns true for AWS-managed service-linked roles
// whose trust policies cannot be modified.
func isServiceLinkedRole(r iamtypes.Role) bool {
	path := aws.ToString(r.Path)
	return strings.HasPrefix(path, "/aws-service-role/")
}

// trustDoc is a minimal schema for an IAM role assume-role policy.
type trustDoc struct {
	Version   string      `json:"Version"`
	Statement []trustStmt `json:"Statement"`
}

type trustStmt struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Condition condMap         `json:"Condition"`
}

// condMap is operator → key → value(s). We keep values as RawMessage so
// they can be either a string or a []string.
type condMap map[string]map[string]json.RawMessage

func parseTrustDoc(urlEncoded string) (trustDoc, error) {
	decoded, err := url.QueryUnescape(urlEncoded)
	if err != nil {
		decoded = urlEncoded
	}
	var td trustDoc
	err = json.Unmarshal([]byte(decoded), &td)
	return td, err
}

// asList returns a string slice from a JSON field that may be a string or
// an array of strings.
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

// principalMap extracts {Type: values} from a Principal field which may be
// the string "*" or an object like {"AWS":"*","Federated":["..."]}.
func principalMap(raw json.RawMessage) map[string][]string {
	out := map[string][]string{}
	if len(raw) == 0 {
		return out
	}
	// String "*"
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		out["*"] = []string{s}
		return out
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err == nil {
		for k, v := range m {
			out[k] = asList(v)
		}
	}
	return out
}

// referencedFederatedPrincipals returns the set of Federated principal ARNs
// referenced by a role's trust policy (across all statements).
func referencedFederatedPrincipals(r iamtypes.Role) []string {
	td, err := parseTrustDoc(aws.ToString(r.AssumeRolePolicyDocument))
	if err != nil {
		return nil
	}
	var out []string
	for _, st := range td.Statement {
		p := principalMap(st.Principal)
		for _, fed := range p["Federated"] {
			out = append(out, fed)
		}
	}
	return out
}

// condGet walks a condition block for an exact-or-like match on key.
// Returns the first matching (operator, value) pair found, or ("", "", false).
func condGet(c condMap, key string) (string, []string, bool) {
	if c == nil {
		return "", nil, false
	}
	for op, kv := range c {
		for k, v := range kv {
			if strings.EqualFold(k, key) {
				return op, asList(v), true
			}
		}
	}
	return "", nil, false
}

// isExternalAccount returns true if the principal ARN belongs to a different
// AWS account than the one being scanned.
func isExternalAccount(principalARN, currentAccountID string) bool {
	// ARN format: arn:aws:iam::123456789012:root or arn:aws:iam::123456789012:role/name
	parts := strings.Split(principalARN, ":")
	if len(parts) < 5 {
		return false
	}
	acct := parts[4]
	return acct != "" && acct != currentAccountID
}

// ---------- SAML providers ----------

type samlMetadata struct {
	XMLName    xml.Name `xml:"EntityDescriptor"`
	EntityID   string   `xml:"entityID,attr"`
	ValidUntil string   `xml:"validUntil,attr"`
}

func scanSAMLProviders(ctx context.Context, cli *iam.Client, t creds.AccountTarget, sink findings.Sink, referenced map[string]bool) error {
	out, err := cli.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return err
	}
	for _, p := range out.SAMLProviderList {
		arn := aws.ToString(p.Arn)
		desc, err := cli.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{SAMLProviderArn: aws.String(arn)})
		if err != nil {
			_ = sink.LogEvent(ctx, "iam_integrations", t.AccountID, "warn", "GetSAMLProvider "+arn+": "+err.Error())
			continue
		}
		var md samlMetadata
		_ = xml.Unmarshal([]byte(aws.ToString(desc.SAMLMetadataDocument)), &md)
		var validUntil time.Time
		if md.ValidUntil != "" {
			validUntil, _ = time.Parse(time.RFC3339, md.ValidUntil)
		}

		sev := findings.SevInfo
		title := "SAML identity provider: " + arn
		reasons := []string{}
		if !referenced[arn] {
			sev = findings.SevLow
			reasons = append(reasons, "no role trust policy references this provider (orphaned)")
		}
		if !validUntil.IsZero() {
			now := time.Now().UTC()
			if validUntil.Before(now) {
				sev = findings.SevCritical
				reasons = append(reasons, "metadata validUntil is in the past ("+validUntil.Format("2006-01-02")+")")
			} else if validUntil.Sub(now) < 30*24*time.Hour {
				if sev != findings.SevCritical {
					sev = findings.SevHigh
				}
				reasons = append(reasons, "metadata expires within 30 days ("+validUntil.Format("2006-01-02")+")")
			}
		}
		if len(reasons) > 0 {
			title += " — " + strings.Join(reasons, "; ")
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Module:      "iam_integrations",
			Severity:    sev,
			ResourceARN: arn,
			Title:       title,
			Detail: map[string]any{
				"arn":         arn,
				"entity_id":   md.EntityID,
				"valid_until": md.ValidUntil,
				"referenced":  referenced[arn],
				"reasons":     reasons,
			},
		})
	}
	return nil
}

// ---------- OIDC providers ----------

// knownOIDCIssuer returns a human label and hint for a known provider URL,
// or ("", false).
func knownOIDCIssuer(urlStr string) (string, bool) {
	host := urlStr
	if u, err := url.Parse("https://" + strings.TrimPrefix(strings.TrimPrefix(urlStr, "https://"), "http://")); err == nil && u.Host != "" {
		host = u.Host
	}
	switch {
	case strings.EqualFold(host, "token.actions.githubusercontent.com"):
		return "GitHub Actions", true
	case strings.HasSuffix(host, ".eks.amazonaws.com") || strings.Contains(host, "oidc.eks."):
		return "EKS service account", true
	case strings.EqualFold(host, "gitlab.com") || strings.HasSuffix(host, ".gitlab.com"):
		return "GitLab", true
	case strings.EqualFold(host, "oidc.circleci.com"):
		return "CircleCI", true
	case strings.Contains(host, "dev.azure.com") || strings.Contains(host, "visualstudio.com"):
		return "Azure DevOps", true
	case strings.Contains(host, "bitbucket.org"):
		return "Bitbucket Pipelines", true
	case strings.Contains(host, "buildkite.com"):
		return "Buildkite", true
	case strings.EqualFold(host, "accounts.google.com") || strings.Contains(host, "googleapis.com"):
		return "Google", true
	}
	return "", false
}

type oidcProviderInfo struct {
	ARN       string
	URL       string
	ClientIDs []string
	Known     string
}

func scanOIDCProviders(ctx context.Context, cli *iam.Client, t creds.AccountTarget, sink findings.Sink, referenced map[string]bool) (map[string]oidcProviderInfo, error) {
	out, err := cli.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, err
	}
	byARN := map[string]oidcProviderInfo{}
	for _, p := range out.OpenIDConnectProviderList {
		arn := aws.ToString(p.Arn)
		desc, err := cli.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: aws.String(arn),
		})
		if err != nil {
			_ = sink.LogEvent(ctx, "iam_integrations", t.AccountID, "warn", "GetOpenIDConnectProvider "+arn+": "+err.Error())
			continue
		}
		info := oidcProviderInfo{
			ARN:       arn,
			URL:       aws.ToString(desc.Url),
			ClientIDs: desc.ClientIDList,
		}
		if label, ok := knownOIDCIssuer(info.URL); ok {
			info.Known = label
		}
		byARN[arn] = info

		sev := findings.SevInfo
		reasons := []string{}
		if !referenced[arn] {
			sev = findings.SevLow
			reasons = append(reasons, "no role trust policy references this provider (orphaned)")
		}
		if len(info.ClientIDs) == 0 {
			sev = worstSeverity(sev, findings.SevMedium)
			reasons = append(reasons, "no client IDs configured — trust is unscoped unless all roles enforce `:aud` conditions")
		}
		title := "OIDC identity provider: " + info.URL
		if info.Known != "" {
			title += " (" + info.Known + ")"
		}
		if len(reasons) > 0 {
			title += " — " + strings.Join(reasons, "; ")
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Module:      "iam_integrations",
			Severity:    sev,
			ResourceARN: arn,
			Title:       title,
			Detail: map[string]any{
				"arn":         arn,
				"url":         info.URL,
				"client_ids":  info.ClientIDs,
				"thumbprints": desc.ThumbprintList,
				"known":       info.Known,
				"referenced":  referenced[arn],
				"reasons":     reasons,
			},
		})
	}
	return byARN, nil
}

// ---------- role trust policy analysis ----------

func scanRoleTrustPolicies(ctx context.Context, icli *iam.Client, t creds.AccountTarget, sink findings.Sink, roles []iamtypes.Role, oidcProviders map[string]oidcProviderInfo) error {
	for _, r := range roles {
		if isServiceLinkedRole(r) {
			continue
		}
		td, err := parseTrustDoc(aws.ToString(r.AssumeRolePolicyDocument))
		if err != nil {
			continue
		}
		for _, st := range td.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			actions := asList(st.Action)
			principals := principalMap(st.Principal)
			hasCond := len(st.Condition) > 0

			// Principal wildcard checks — apply regardless of action.
			if stars, ok := principals["*"]; ok && len(stars) > 0 {
				sev := findings.SevCritical
				reason := "role trust allows Principal: \"*\" — literally anyone on the internet can assume"
				if hasCond {
					sev = findings.SevHigh
					reason += " (mitigated by conditions, review required)"
				}
				_ = writeRoleFinding(ctx, sink, t, r, "wildcard_principal", sev, reason, st)
			}
			if awsPrincs, ok := principals["AWS"]; ok {
				for _, ap := range awsPrincs {
					if ap == "*" {
						sev := findings.SevCritical
						reason := "role trust allows Principal.AWS: \"*\" — any AWS account can assume"
						if hasCond {
							sev = findings.SevHigh
							reason += " (mitigated by conditions, review required)"
						}
						_ = writeRoleFinding(ctx, sink, t, r, "wildcard_aws_principal", sev, reason, st)
					}
				}
			}

			// Per-action analysis.
			for _, a := range actions {
				switch {
				case strings.EqualFold(a, "sts:AssumeRoleWithWebIdentity"):
					analyzeWebIdentity(ctx, sink, t, r, st, oidcProviders)
				case strings.EqualFold(a, "sts:AssumeRoleWithSAML"):
					analyzeSAMLTrust(ctx, sink, t, r, st)
				case strings.EqualFold(a, "sts:AssumeRole"):
					analyzeAssumeRole(ctx, sink, t, r, st)
				}
			}
		}
	}
	return nil
}

func analyzeWebIdentity(ctx context.Context, sink findings.Sink, t creds.AccountTarget, r iamtypes.Role, st trustStmt, oidcProviders map[string]oidcProviderInfo) {
	feds := principalMap(st.Principal)["Federated"]
	for _, fedARN := range feds {
		info, known := oidcProviders[fedARN]
		issuerHost := info.URL
		if !known {
			// Provider not in our map (maybe we couldn't describe it) —
			// infer from ARN suffix.
			if idx := strings.Index(fedARN, "/"); idx >= 0 {
				issuerHost = fedARN[idx+1:]
			}
		}

		// Missing Condition entirely → catastrophic.
		if len(st.Condition) == 0 {
			_ = writeRoleFinding(ctx, sink, t, r, "web_identity_no_condition", findings.SevCritical,
				"role trusts AssumeRoleWithWebIdentity from "+issuerHost+" with no Condition block — any OIDC identity can assume", st)
			continue
		}

		// :aud check
		audKey := issuerHost + ":aud"
		audOp, audVals, hasAud := condGet(st.Condition, audKey)
		if !hasAud {
			_ = writeRoleFinding(ctx, sink, t, r, "web_identity_missing_aud", findings.SevHigh,
				"role trust for "+issuerHost+" is missing `"+audKey+"` condition", st)
		} else {
			for _, v := range audVals {
				if v == "*" && strings.Contains(strings.ToLower(audOp), "like") {
					_ = writeRoleFinding(ctx, sink, t, r, "web_identity_wildcard_aud", findings.SevHigh,
						"audience is wildcarded (`"+audKey+"` = \"*\")", st)
				}
			}
		}

		// Provider-specific :sub analysis.
		switch {
		case strings.EqualFold(issuerHost, githubOIDCIssuer):
			analyzeGitHubOIDCTrust(ctx, sink, t, r, st, issuerHost)
		case strings.EqualFold(issuerHost, "gitlab.com") || strings.HasSuffix(strings.ToLower(issuerHost), ".gitlab.com"):
			analyzeGitLabOIDCTrust(ctx, sink, t, r, st, issuerHost)
		case strings.Contains(strings.ToLower(issuerHost), "oidc.eks.") || strings.HasSuffix(strings.ToLower(issuerHost), ".eks.amazonaws.com"):
			analyzeEKSOIDCTrust(ctx, sink, t, r, st, issuerHost)
		default:
			// Generic OIDC: require :sub present.
			subKey := issuerHost + ":sub"
			if _, _, hasSub := condGet(st.Condition, subKey); !hasSub {
				_ = writeRoleFinding(ctx, sink, t, r, "oidc_missing_sub", findings.SevHigh,
					"OIDC trust for "+issuerHost+" is missing `"+subKey+"` condition", st)
			}
		}
	}
}

func analyzeGitHubOIDCTrust(ctx context.Context, sink findings.Sink, t creds.AccountTarget, r iamtypes.Role, st trustStmt, issuerHost string) {
	subKey := githubOIDCIssuer + ":sub"
	subOp, subVals, hasSub := condGet(st.Condition, subKey)
	if !hasSub {
		_ = writeRoleFinding(ctx, sink, t, r, "github_oidc_no_sub", findings.SevCritical,
			"GitHub Actions OIDC trust with no `"+subKey+"` condition — any GitHub repo can assume this role", st)
		return
	}
	for _, v := range subVals {
		risk := AnalyzeGitHubSub(subOp, v)
		if risk.Severity == findings.SevInfo {
			continue
		}
		_ = writeRoleFinding(ctx, sink, t, r, risk.Category, risk.Severity,
			risk.Reason+" — "+risk.Suggestion, st)
	}
}

// analyzeGitLabOIDCTrust checks GitLab CI/CD OIDC subject conditions.
// GitLab subjects look like:
//
//	project_path:<group>/<project>:ref_type:branch:ref:<branch>
//	project_path:<group>/<project>:ref_type:tag:ref:<tag>
func analyzeGitLabOIDCTrust(ctx context.Context, sink findings.Sink, t creds.AccountTarget, r iamtypes.Role, st trustStmt, issuerHost string) {
	subKey := issuerHost + ":sub"
	subOp, subVals, hasSub := condGet(st.Condition, subKey)
	if !hasSub {
		_ = writeRoleFinding(ctx, sink, t, r, "gitlab_oidc_no_sub", findings.SevCritical,
			"GitLab OIDC trust with no `"+subKey+"` condition — any GitLab project can assume this role", st)
		return
	}
	like := strings.Contains(strings.ToLower(subOp), "like")
	for _, v := range subVals {
		v = strings.TrimSpace(v)
		switch {
		case v == "" || (like && (v == "*" || v == "project_path:*")):
			_ = writeRoleFinding(ctx, sink, t, r, "gitlab_oidc_universal_sub", findings.SevCritical,
				"GitLab OIDC subject is wildcarded — any GitLab project can assume this role", st)
		case like && strings.HasPrefix(v, "project_path:") && !strings.Contains(v, "/"):
			_ = writeRoleFinding(ctx, sink, t, r, "gitlab_oidc_no_project", findings.SevCritical,
				"GitLab OIDC subject pins a group but no project — any project in the group can assume", st)
		case like && strings.HasPrefix(v, "project_path:"):
			// Check if the group or project portion is wildcarded.
			rest := strings.TrimPrefix(v, "project_path:")
			slash := strings.Index(rest, "/")
			if slash >= 0 {
				group := rest[:slash]
				if strings.Contains(group, "*") {
					_ = writeRoleFinding(ctx, sink, t, r, "gitlab_oidc_wildcard_group", findings.SevCritical,
						"GitLab OIDC subject has wildcarded group — multiple groups can assume this role", st)
				}
			}
		case !strings.HasPrefix(v, "project_path:"):
			_ = writeRoleFinding(ctx, sink, t, r, "gitlab_oidc_unrecognized_sub", findings.SevHigh,
				"GitLab OIDC subject does not start with `project_path:` — may accept unexpected subjects", st)
		}
	}
}

// analyzeEKSOIDCTrust checks EKS OIDC subject conditions.
// EKS subjects look like: system:serviceaccount:<namespace>:<sa-name>
func analyzeEKSOIDCTrust(ctx context.Context, sink findings.Sink, t creds.AccountTarget, r iamtypes.Role, st trustStmt, issuerHost string) {
	subKey := issuerHost + ":sub"
	subOp, subVals, hasSub := condGet(st.Condition, subKey)
	if !hasSub {
		_ = writeRoleFinding(ctx, sink, t, r, "eks_oidc_no_sub", findings.SevCritical,
			"EKS OIDC trust with no `"+subKey+"` condition — any pod in the cluster can assume this role", st)
		return
	}
	like := strings.Contains(strings.ToLower(subOp), "like")
	for _, v := range subVals {
		v = strings.TrimSpace(v)
		switch {
		case v == "" || (like && v == "*"):
			_ = writeRoleFinding(ctx, sink, t, r, "eks_oidc_universal_sub", findings.SevCritical,
				"EKS OIDC subject is wildcarded — any pod in the cluster can assume this role", st)
		case like && v == "system:serviceaccount:*" || (like && v == "system:serviceaccount:*:*"):
			_ = writeRoleFinding(ctx, sink, t, r, "eks_oidc_any_namespace", findings.SevHigh,
				"EKS OIDC subject allows any namespace — any service account in the cluster can assume this role", st)
		case strings.HasPrefix(v, "system:serviceaccount:"):
			rest := strings.TrimPrefix(v, "system:serviceaccount:")
			parts := strings.SplitN(rest, ":", 2)
			ns := parts[0]
			if like && strings.Contains(ns, "*") {
				_ = writeRoleFinding(ctx, sink, t, r, "eks_oidc_wildcard_namespace", findings.SevHigh,
					"EKS OIDC subject has wildcarded namespace `"+ns+"` — multiple namespaces can assume this role", st)
			} else if len(parts) == 2 && like && parts[1] == "*" {
				_ = writeRoleFinding(ctx, sink, t, r, "eks_oidc_any_sa", findings.SevMedium,
					"EKS OIDC subject allows any service account in namespace `"+ns+"`", st)
			}
		case !strings.HasPrefix(v, "system:serviceaccount:"):
			_ = writeRoleFinding(ctx, sink, t, r, "eks_oidc_unrecognized_sub", findings.SevHigh,
				"EKS OIDC subject does not start with `system:serviceaccount:` — may accept unexpected subjects", st)
		}
	}
}

// analyzeAssumeRole checks cross-account sts:AssumeRole trusts for confused
// deputy risk (missing sts:ExternalId condition).
func analyzeAssumeRole(ctx context.Context, sink findings.Sink, t creds.AccountTarget, r iamtypes.Role, st trustStmt) {
	principals := principalMap(st.Principal)
	awsPrincs := principals["AWS"]
	if len(awsPrincs) == 0 {
		return
	}
	for _, ap := range awsPrincs {
		if ap == "*" {
			continue // already caught by wildcard principal check
		}
		if !isExternalAccount(ap, t.AccountID) {
			continue
		}
		if _, _, hasExtID := condGet(st.Condition, "sts:ExternalId"); !hasExtID {
			_ = writeRoleFinding(ctx, sink, t, r, "cross_account_no_external_id", findings.SevMedium,
				"cross-account trust to "+ap+" without sts:ExternalId condition (confused deputy risk)", st)
		}
	}
}

func analyzeSAMLTrust(ctx context.Context, sink findings.Sink, t creds.AccountTarget, r iamtypes.Role, st trustStmt) {
	if _, _, ok := condGet(st.Condition, "SAML:aud"); !ok {
		_ = writeRoleFinding(ctx, sink, t, r, "saml_missing_aud", findings.SevHigh,
			"SAML trust is missing `SAML:aud` condition — audience not pinned", st)
	}
}

func writeRoleFinding(ctx context.Context, sink findings.Sink, t creds.AccountTarget, r iamtypes.Role, category string, sev findings.Severity, reason string, st trustStmt) error {
	return sink.Write(ctx, findings.Finding{
		AccountID:   t.AccountID,
		Module:      "iam_integrations",
		Severity:    sev,
		ResourceARN: aws.ToString(r.Arn),
		Title:       "IAM role " + aws.ToString(r.RoleName) + ": " + reason,
		Detail: map[string]any{
			"role":      aws.ToString(r.RoleName),
			"category":  category,
			"statement": st,
		},
	})
}

func worstSeverity(a, b findings.Severity) findings.Severity {
	order := map[findings.Severity]int{
		findings.SevInfo: 0, findings.SevLow: 1, findings.SevMedium: 2, findings.SevHigh: 3, findings.SevCritical: 4,
	}
	if order[a] >= order[b] {
		return a
	}
	return b
}

// ---------- Cognito identity pools ----------

// dangerousManagedPolicies is a set of AWS-managed policy ARN suffixes that
// grant broad or dangerous permissions when attached to an unauthenticated
// Cognito role.
var dangerousManagedPolicies = map[string]string{
	"AdministratorAccess":          "full admin access",
	"PowerUserAccess":              "full access except IAM",
	"AmazonS3FullAccess":           "full S3 access",
	"AmazonDynamoDBFullAccess":     "full DynamoDB access",
	"AmazonSQSFullAccess":          "full SQS access",
	"AmazonSNSFullAccess":          "full SNS access",
	"IAMFullAccess":                "full IAM access",
	"AWSLambda_FullAccess":         "full Lambda access",
	"AmazonEC2FullAccess":          "full EC2 access",
	"AmazonSSMFullAccess":          "full SSM access",
	"SecretsManagerReadWrite":      "read/write Secrets Manager",
	"AWSKeyManagementServicePowerUser": "KMS power user",
}

func scanCognitoIdentityPools(ctx context.Context, icli *iam.Client, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := cognitoidentity.NewFromConfig(t.Config, func(o *cognitoidentity.Options) { o.Region = region })
	var next *string
	for {
		list, err := cli.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{
			MaxResults: aws.Int32(60),
			NextToken:  next,
		})
		if err != nil {
			return err
		}
		for _, p := range list.IdentityPools {
			pid := aws.ToString(p.IdentityPoolId)
			desc, err := cli.DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{
				IdentityPoolId: aws.String(pid),
			})
			if err != nil {
				_ = sink.LogEvent(ctx, "iam_integrations", t.AccountID, "warn", "DescribeIdentityPool "+pid+": "+err.Error())
				continue
			}
			var unauthRole string
			roles, err := cli.GetIdentityPoolRoles(ctx, &cognitoidentity.GetIdentityPoolRolesInput{
				IdentityPoolId: aws.String(pid),
			})
			if err == nil {
				unauthRole = roles.Roles["unauthenticated"]
			}

			allowUnauth := desc.AllowUnauthenticatedIdentities
			allowClassic := desc.AllowClassicFlow != nil && *desc.AllowClassicFlow

			sev := findings.SevInfo
			reasons := []string{}
			if allowUnauth {
				sev = findings.SevHigh
				reasons = append(reasons, "AllowUnauthenticatedIdentities=true — anonymous users receive AWS credentials via "+unauthRole)
			}
			if allowClassic {
				sev = worstSeverity(sev, findings.SevMedium)
				reasons = append(reasons, "AllowClassicFlow=true — classic auth flow enabled (replay risk)")
			}

			// Check what the unauthenticated role can do.
			var dangerousPolicies []string
			if allowUnauth && unauthRole != "" {
				roleName := unauthRole
				// Extract role name from ARN if needed.
				if strings.Contains(unauthRole, "/") {
					parts := strings.SplitN(unauthRole, "/", 2)
					roleName = parts[len(parts)-1]
				}
				attached, err := icli.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
					RoleName: aws.String(roleName),
				})
				if err == nil {
					for _, pol := range attached.AttachedPolicies {
						policyName := aws.ToString(pol.PolicyName)
						if desc, ok := dangerousManagedPolicies[policyName]; ok {
							dangerousPolicies = append(dangerousPolicies, policyName+" ("+desc+")")
						}
					}
				}
				if len(dangerousPolicies) > 0 {
					sev = findings.SevCritical
					reasons = append(reasons, "unauthenticated role has dangerous policies: "+strings.Join(dangerousPolicies, ", "))
				}
			}

			title := "Cognito identity pool " + aws.ToString(desc.IdentityPoolName) + " (" + pid + ")"
			if len(reasons) > 0 {
				title += " — " + strings.Join(reasons, "; ")
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "iam_integrations",
				Severity:    sev,
				ResourceARN: fmt.Sprintf("arn:aws:cognito-identity:%s:%s:identitypool/%s", region, t.AccountID, pid),
				Title:       title,
				Detail: map[string]any{
					"identity_pool_id":              pid,
					"name":                          aws.ToString(desc.IdentityPoolName),
					"allow_unauthenticated":         allowUnauth,
					"allow_classic_flow":             allowClassic,
					"unauthenticated_role":           unauthRole,
					"dangerous_policies":             dangerousPolicies,
					"developer_provider_name":        aws.ToString(desc.DeveloperProviderName),
					"cognito_identity_providers":     desc.CognitoIdentityProviders,
					"saml_provider_arns":             desc.SamlProviderARNs,
					"open_id_connect_provider_arns":  desc.OpenIdConnectProviderARNs,
					"reasons":                        reasons,
				},
			})
		}
		if list.NextToken == nil {
			break
		}
		next = list.NextToken
	}
	return nil
}
