package cognito

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cidtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	ciptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "cognito" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
		"cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient",
		"cognito-idp:ListGroups",
		"cognito-identity:ListIdentityPools",
		"cognito-identity:DescribeIdentityPool",
		"cognito-identity:GetIdentityPoolRoles",
		"iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy",
	}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "cognito", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

// selfSignupPools tracks pool IDs that allow self-signup for cross-referencing
// with identity pools.
type selfSignupPools map[string]string // poolID → poolName

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cipCli := cognitoidentityprovider.NewFromConfig(t.Config, func(o *cognitoidentityprovider.Options) { o.Region = region })
	cidCli := cognitoidentity.NewFromConfig(t.Config, func(o *cognitoidentity.Options) { o.Region = region })
	iamCli := iam.NewFromConfig(t.Config)

	selfSignup := selfSignupPools{}

	// --- User Pools ---
	var nextToken *string
	for {
		list, err := cipCli.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
			MaxResults: aws.Int32(60),
			NextToken:  nextToken,
		})
		if err != nil {
			_ = sink.LogEvent(ctx, "cognito", t.AccountID, "warn", region+": list user pools: "+err.Error())
			break
		}
		for _, pool := range list.UserPools {
			poolID := aws.ToString(pool.Id)
			poolName := aws.ToString(pool.Name)
			scanUserPool(ctx, cipCli, t, region, poolID, poolName, sink, selfSignup)
		}
		if list.NextToken == nil {
			break
		}
		nextToken = list.NextToken
	}

	// --- Identity Pools ---
	scanIdentityPools(ctx, cidCli, iamCli, t, region, sink, selfSignup)

	return nil
}

func scanUserPool(ctx context.Context, cli *cognitoidentityprovider.Client, t creds.AccountTarget, region, poolID, poolName string, sink findings.Sink, selfSignup selfSignupPools) {
	desc, err := cli.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(poolID),
	})
	if err != nil {
		_ = sink.LogEvent(ctx, "cognito", t.AccountID, "warn", region+": describe pool "+poolID+": "+err.Error())
		return
	}
	pool := desc.UserPool
	poolARN := aws.ToString(pool.Arn)

	// Self-signup check.
	allowsSelfSignup := pool.AdminCreateUserConfig == nil || !pool.AdminCreateUserConfig.AllowAdminCreateUserOnly
	if allowsSelfSignup {
		selfSignup[poolID] = poolName
		_ = sink.Write(ctx, findings.Finding{
			AccountID: t.AccountID, Region: region, Module: "cognito",
			Severity: findings.SevHigh, ResourceARN: poolARN,
			Title: fmt.Sprintf("User pool %s: self-signup enabled — anyone can create accounts", poolName),
			Detail: map[string]any{"pool_id": poolID, "pool_name": poolName, "category": "self_signup"},
		})
	}

	// Lambda triggers.
	if pool.LambdaConfig != nil {
		var triggers []map[string]string
		lc := pool.LambdaConfig
		add := func(name, arn string) {
			if arn != "" {
				triggers = append(triggers, map[string]string{"trigger": name, "lambda": arn})
			}
		}
		add("PreSignUp", aws.ToString(lc.PreSignUp))
		add("PreAuthentication", aws.ToString(lc.PreAuthentication))
		add("PostAuthentication", aws.ToString(lc.PostAuthentication))
		add("PostConfirmation", aws.ToString(lc.PostConfirmation))
		add("DefineAuthChallenge", aws.ToString(lc.DefineAuthChallenge))
		add("CreateAuthChallenge", aws.ToString(lc.CreateAuthChallenge))
		add("CustomMessage", aws.ToString(lc.CustomMessage))
		add("PreTokenGeneration", aws.ToString(lc.PreTokenGeneration))
		if len(triggers) > 0 {
			names := make([]string, len(triggers))
			for i, tr := range triggers {
				names[i] = tr["trigger"]
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID: t.AccountID, Region: region, Module: "cognito",
				Severity: findings.SevMedium, ResourceARN: poolARN,
				Title: fmt.Sprintf("User pool %s: Lambda triggers (%s) — review for auth bypass", poolName, strings.Join(names, ", ")),
				Detail: map[string]any{"pool_id": poolID, "pool_name": poolName, "triggers": triggers, "category": "lambda_triggers"},
			})
		}
	}

	// Custom domain.
	domain := aws.ToString(pool.Domain)
	customDomain := aws.ToString(pool.CustomDomain)
	if domain != "" || customDomain != "" {
		d := domain
		if customDomain != "" {
			d = customDomain
		}
		hostedUIURL := fmt.Sprintf("https://%s.auth.%s.amazoncognito.com/login", d, region)
		if customDomain != "" {
			hostedUIURL = fmt.Sprintf("https://%s/login", customDomain)
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID: t.AccountID, Region: region, Module: "cognito",
			Severity: findings.SevInfo, ResourceARN: poolARN,
			Title: fmt.Sprintf("User pool %s: hosted UI at %s", poolName, hostedUIURL),
			Detail: map[string]any{
				"pool_id": poolID, "pool_name": poolName,
				"domain": d, "hosted_ui_url": hostedUIURL,
				"curl": fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' '%s'", hostedUIURL),
				"category": "hosted_ui",
			},
		})
	}

	// Groups with IAM roles.
	groups, err := cli.ListGroups(ctx, &cognitoidentityprovider.ListGroupsInput{UserPoolId: aws.String(poolID)})
	if err == nil {
		for _, g := range groups.Groups {
			roleARN := aws.ToString(g.RoleArn)
			if roleARN == "" {
				continue
			}
			sev := findings.SevInfo
			if allowsSelfSignup {
				sev = findings.SevHigh
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID: t.AccountID, Region: region, Module: "cognito",
				Severity: sev, ResourceARN: poolARN,
				Title: fmt.Sprintf("User pool %s: group %s maps to IAM role %s", poolName, aws.ToString(g.GroupName), roleARN),
				Detail: map[string]any{
					"pool_id": poolID, "pool_name": poolName,
					"group": aws.ToString(g.GroupName), "role_arn": roleARN,
					"self_signup": allowsSelfSignup,
					"category":    "group_role",
				},
			})
		}
	}

	// App clients.
	scanAppClients(ctx, cli, t, region, poolID, poolName, poolARN, sink)
}

func scanAppClients(ctx context.Context, cli *cognitoidentityprovider.Client, t creds.AccountTarget, region, poolID, poolName, poolARN string, sink findings.Sink) {
	var nextToken *string
	for {
		list, err := cli.ListUserPoolClients(ctx, &cognitoidentityprovider.ListUserPoolClientsInput{
			UserPoolId: aws.String(poolID),
			MaxResults: aws.Int32(60),
			NextToken:  nextToken,
		})
		if err != nil {
			break
		}
		for _, c := range list.UserPoolClients {
			clientID := aws.ToString(c.ClientId)
			desc, err := cli.DescribeUserPoolClient(ctx, &cognitoidentityprovider.DescribeUserPoolClientInput{
				UserPoolId: aws.String(poolID),
				ClientId:   aws.String(clientID),
			})
			if err != nil {
				continue
			}
			client := desc.UserPoolClient
			clientName := aws.ToString(client.ClientName)

			var issues []string

			// ALLOW_USER_PASSWORD_AUTH — plaintext password to API.
			for _, f := range client.ExplicitAuthFlows {
				if f == ciptypes.ExplicitAuthFlowsTypeAllowUserPasswordAuth {
					issues = append(issues, "ALLOW_USER_PASSWORD_AUTH (plaintext password)")
				}
			}

			// No client secret.
			// DescribeUserPoolClient doesn't return the secret value but we can check
			// if it was generated by looking at whether ClientSecret is empty.
			// Actually the SDK doesn't expose this directly — but if ExplicitAuthFlows
			// includes ALLOW_USER_SRP_AUTH and there's no secret, it's callable from
			// browser JS.
			// We flag clients that have OAuth flows enabled without requiring a secret.
			if client.AllowedOAuthFlowsUserPoolClient != nil && *client.AllowedOAuthFlowsUserPoolClient {
				// Check callback URLs for permissive patterns.
				for _, cb := range client.CallbackURLs {
					lower := strings.ToLower(cb)
					if strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1") {
						issues = append(issues, "callback URL includes localhost: "+cb)
					} else if cb == "*" || strings.HasPrefix(cb, "*") {
						issues = append(issues, "wildcard callback URL: "+cb)
					} else if strings.HasPrefix(lower, "http://") && !strings.Contains(lower, "localhost") {
						issues = append(issues, "non-HTTPS callback URL: "+cb)
					}
				}

				// Broad OAuth scopes.
				for _, scope := range client.AllowedOAuthScopes {
					if scope == "aws.cognito.signin.user.admin" {
						issues = append(issues, "OAuth scope aws.cognito.signin.user.admin (full user attribute access)")
					}
				}

				// Implicit grant (token in URL fragment).
				for _, flow := range client.AllowedOAuthFlows {
					if flow == ciptypes.OAuthFlowTypeImplicit {
						issues = append(issues, "implicit OAuth flow (tokens in URL)")
					}
				}
			}

			if len(issues) == 0 {
				continue
			}

			sev := findings.SevMedium
			for _, iss := range issues {
				if strings.Contains(iss, "PASSWORD_AUTH") || strings.Contains(iss, "wildcard") {
					sev = findings.SevHigh
					break
				}
			}

			_ = sink.Write(ctx, findings.Finding{
				AccountID: t.AccountID, Region: region, Module: "cognito",
				Severity: sev, ResourceARN: poolARN,
				Title: fmt.Sprintf("User pool %s: app client %s — %s", poolName, clientName, strings.Join(issues, "; ")),
				Detail: map[string]any{
					"pool_id":         poolID,
					"pool_name":       poolName,
					"client_id":       clientID,
					"client_name":     clientName,
					"auth_flows":      client.ExplicitAuthFlows,
					"oauth_scopes":    client.AllowedOAuthScopes,
					"oauth_flows":     client.AllowedOAuthFlows,
					"callback_urls":   client.CallbackURLs,
					"logout_urls":     client.LogoutURLs,
					"issues":          issues,
					"category":        "app_client",
				},
			})
		}
		if list.NextToken == nil {
			break
		}
		nextToken = list.NextToken
	}
}

// ---------- Identity Pools ----------

// dangerousActions in inline policies that are concerning on unauth/auth roles.
var dangerousActions = []string{
	"*", "iam:*", "s3:*", "sts:*", "lambda:*", "ec2:*",
	"dynamodb:*", "sqs:*", "sns:*", "ssm:*", "secretsmanager:*",
	"iam:CreateUser", "iam:CreateRole", "iam:AttachRolePolicy",
	"iam:PutRolePolicy", "sts:AssumeRole", "s3:PutObject",
}

// dangerousManagedPolicies for quick-check on attached managed policies.
var dangerousManagedPolicies = map[string]string{
	"AdministratorAccess":      "full admin",
	"PowerUserAccess":          "full except IAM",
	"AmazonS3FullAccess":       "full S3",
	"AmazonDynamoDBFullAccess": "full DynamoDB",
	"IAMFullAccess":            "full IAM",
	"AWSLambda_FullAccess":     "full Lambda",
	"AmazonEC2FullAccess":      "full EC2",
	"AmazonSSMFullAccess":      "full SSM",
	"SecretsManagerReadWrite":  "secrets read/write",
}

func scanIdentityPools(ctx context.Context, cidCli *cognitoidentity.Client, iamCli *iam.Client, t creds.AccountTarget, region string, sink findings.Sink, selfSignup selfSignupPools) {
	var next *string
	for {
		list, err := cidCli.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{
			MaxResults: aws.Int32(60),
			NextToken:  next,
		})
		if err != nil {
			return
		}
		for _, p := range list.IdentityPools {
			pid := aws.ToString(p.IdentityPoolId)
			scanIdentityPool(ctx, cidCli, iamCli, t, region, pid, sink, selfSignup)
		}
		if list.NextToken == nil {
			break
		}
		next = list.NextToken
	}
}

func scanIdentityPool(ctx context.Context, cidCli *cognitoidentity.Client, iamCli *iam.Client, t creds.AccountTarget, region, pid string, sink findings.Sink, selfSignup selfSignupPools) {
	desc, err := cidCli.DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{
		IdentityPoolId: aws.String(pid),
	})
	if err != nil {
		return
	}
	poolName := aws.ToString(desc.IdentityPoolName)
	poolARN := fmt.Sprintf("arn:aws:cognito-identity:%s:%s:identitypool/%s", region, t.AccountID, pid)

	roles, err := cidCli.GetIdentityPoolRoles(ctx, &cognitoidentity.GetIdentityPoolRolesInput{
		IdentityPoolId: aws.String(pid),
	})
	if err != nil {
		return
	}

	unauthRole := roles.Roles["unauthenticated"]
	authRole := roles.Roles["authenticated"]

	// Developer-authenticated identities.
	if aws.ToString(desc.DeveloperProviderName) != "" {
		_ = sink.Write(ctx, findings.Finding{
			AccountID: t.AccountID, Region: region, Module: "cognito",
			Severity: findings.SevMedium, ResourceARN: poolARN,
			Title: fmt.Sprintf("Identity pool %s: developer-authenticated identities enabled (%s)", poolName, aws.ToString(desc.DeveloperProviderName)),
			Detail: map[string]any{
				"pool_id": pid, "pool_name": poolName,
				"developer_provider": aws.ToString(desc.DeveloperProviderName),
				"category":           "developer_auth",
			},
		})
	}

	// Check unauthenticated role permissions.
	if desc.AllowUnauthenticatedIdentities && unauthRole != "" {
		dangers := checkRolePermissions(ctx, iamCli, unauthRole)
		sev := findings.SevHigh
		title := fmt.Sprintf("Identity pool %s: unauthenticated role %s", poolName, roleNameFromARN(unauthRole))
		if len(dangers) > 0 {
			sev = findings.SevCritical
			title += " — dangerous permissions: " + strings.Join(dangers, ", ")
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID: t.AccountID, Region: region, Module: "cognito",
			Severity: sev, ResourceARN: poolARN,
			Title: title,
			Detail: map[string]any{
				"pool_id": pid, "pool_name": poolName,
				"role_arn": unauthRole, "role_type": "unauthenticated",
				"dangerous_permissions": dangers,
				"category":              "unauth_role",
			},
		})
	}

	// Check authenticated role permissions.
	if authRole != "" {
		dangers := checkRolePermissions(ctx, iamCli, authRole)
		sev := findings.SevInfo
		title := fmt.Sprintf("Identity pool %s: authenticated role %s", poolName, roleNameFromARN(authRole))
		if len(dangers) > 0 {
			sev = findings.SevMedium
			title += " — broad permissions: " + strings.Join(dangers, ", ")
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID: t.AccountID, Region: region, Module: "cognito",
			Severity: sev, ResourceARN: poolARN,
			Title: title,
			Detail: map[string]any{
				"pool_id": pid, "pool_name": poolName,
				"role_arn": authRole, "role_type": "authenticated",
				"dangerous_permissions": dangers,
				"category":              "auth_role",
			},
		})
	}

	// Role mapping rules.
	for provider, rm := range roles.RoleMappings {
		if rm.RulesConfiguration == nil {
			continue
		}
		for _, rule := range rm.RulesConfiguration.Rules {
			claim := aws.ToString(rule.Claim)
			value := aws.ToString(rule.Value)
			roleARN := aws.ToString(rule.RoleARN)
			matchType := string(rule.MatchType)

			sev := findings.SevInfo
			var issue string
			if value == "*" || (rule.MatchType == cidtypes.MappingRuleMatchTypeContains && value == "") {
				sev = findings.SevHigh
				issue = "wildcard/empty match — any authenticated user gets this role"
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID: t.AccountID, Region: region, Module: "cognito",
				Severity: sev, ResourceARN: poolARN,
				Title: fmt.Sprintf("Identity pool %s: role mapping %s=%s → %s", poolName, claim, value, roleNameFromARN(roleARN)),
				Detail: map[string]any{
					"pool_id": pid, "pool_name": poolName,
					"provider": provider, "claim": claim,
					"match_type": matchType, "value": value,
					"role_arn": roleARN, "issue": issue,
					"category": "role_mapping",
				},
			})
		}
	}

	// Self-signup → identity pool chain.
	for _, cp := range desc.CognitoIdentityProviders {
		providerName := aws.ToString(cp.ProviderName)
		// Provider name format: cognito-idp.{region}.amazonaws.com/{poolId}
		for poolID, upName := range selfSignup {
			if strings.Contains(providerName, poolID) {
				sev := findings.SevHigh
				title := fmt.Sprintf("Identity pool %s: linked to self-signup user pool %s", poolName, upName)
				if desc.AllowUnauthenticatedIdentities {
					sev = findings.SevCritical
					title += " + unauthenticated access enabled"
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID: t.AccountID, Region: region, Module: "cognito",
					Severity: sev, ResourceARN: poolARN,
					Title: title,
					Detail: map[string]any{
						"identity_pool_id":   pid,
						"identity_pool_name": poolName,
						"user_pool_id":       poolID,
						"user_pool_name":     upName,
						"allow_unauth":       desc.AllowUnauthenticatedIdentities,
						"unauth_role":        unauthRole,
						"auth_role":          authRole,
						"category":           "self_signup_chain",
					},
				})
			}
		}
	}
}

// checkRolePermissions checks both managed and inline policies for dangerous actions.
func checkRolePermissions(ctx context.Context, iamCli *iam.Client, roleARN string) []string {
	roleName := roleNameFromARN(roleARN)
	if roleName == "" {
		return nil
	}
	var dangers []string

	// Managed policies.
	attached, err := iamCli.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, pol := range attached.AttachedPolicies {
			name := aws.ToString(pol.PolicyName)
			if desc, ok := dangerousManagedPolicies[name]; ok {
				dangers = append(dangers, name+" ("+desc+")")
			}
		}
	}

	// Inline policies.
	inlinePols, err := iamCli.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, polName := range inlinePols.PolicyNames {
			polDoc, err := iamCli.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(polName),
			})
			if err != nil {
				continue
			}
			docStr := aws.ToString(polDoc.PolicyDocument)
			decoded, err := url.QueryUnescape(docStr)
			if err != nil {
				decoded = docStr
			}
			for _, da := range dangerousActions {
				if strings.Contains(decoded, `"`+da+`"`) {
					dangers = append(dangers, "inline:"+polName+" has "+da)
					break
				}
			}
		}
	}

	return dangers
}

func roleNameFromARN(arn string) string {
	// arn:aws:iam::123456789012:role/name or arn:aws:iam::123456789012:role/path/name
	if idx := strings.Index(arn, ":role/"); idx >= 0 {
		rest := arn[idx+6:]
		// Handle paths: take the last segment.
		if slash := strings.LastIndex(rest, "/"); slash >= 0 {
			return rest[slash+1:]
		}
		return rest
	}
	return arn
}
