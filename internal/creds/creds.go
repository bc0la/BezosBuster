package creds

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

// AccountTarget is what modules receive: an AWS SDK config pinned to one account.
type AccountTarget struct {
	AccountID string
	Alias     string
	Profile   string // source profile name (may be empty for assumed roles)
	Config    aws.Config
}

type Options struct {
	Profile    string
	Profiles   []string
	Org        bool
	AssumeRole string // role *name* to assume in org mode
	Region     string

	// Cross-account mode: assume one or more explicit role ARNs starting from
	// the base profile/creds (Profile, or the ambient default chain). This is
	// the consultant/customer-environment pattern — you hold one hub identity
	// and hop into each customer account via a role they've let you assume.
	// Unlike Org mode it needs no organizations:ListAccounts, so it works from
	// outside the target's AWS Organization.
	AssumeRoleArns  []string
	ExternalID      string // sts:AssumeRole ExternalId (third-party trust / confused-deputy guard)
	RoleSessionName string // session name for assumed roles (default "bezosbuster")
}

// Detect figures out which account(s) to scan based on user options. It
// returns a slice of AccountTargets; callers iterate.
func Detect(ctx context.Context, opts Options) ([]AccountTarget, error) {
	region := opts.Region
	if region == "" {
		region = "us-east-1"
	}
	assumeRole := opts.AssumeRole
	if assumeRole == "" {
		assumeRole = "OrganizationAccountAccessRole"
	}

	// Mode: explicit cross-account role ARNs assumed from a base identity.
	// Highest precedence — if the user named target ARNs, that's exactly what
	// they want to scan.
	if len(opts.AssumeRoleArns) > 0 {
		base, err := loadProfile(ctx, opts.Profile, region)
		if err != nil {
			return nil, fmt.Errorf("load base profile: %w", err)
		}
		return assumeRoleArns(ctx, base, opts)
	}

	// Mode: explicit profile list.
	if len(opts.Profiles) > 0 {
		var out []AccountTarget
		for _, p := range opts.Profiles {
			t, err := loadProfile(ctx, p, region)
			if err != nil {
				return nil, fmt.Errorf("profile %s: %w", p, err)
			}
			out = append(out, t)
		}
		return out, nil
	}

	// Default: single profile (possibly default).
	base, err := loadProfile(ctx, opts.Profile, region)
	if err != nil {
		return nil, err
	}

	if !opts.Org {
		return []AccountTarget{base}, nil
	}

	// Org mode: enumerate accounts and assume role into each.
	return enumerateOrg(ctx, base, assumeRole, opts.ExternalID, opts.RoleSessionName)
}

// assumeRoleArns hops from the base identity into each explicitly named role
// ARN. Every ARN is probed with sts:GetCallerIdentity so a bad ARN / wrong
// ExternalID / missing trust surfaces immediately rather than mid-scan.
func assumeRoleArns(ctx context.Context, base AccountTarget, opts Options) ([]AccountTarget, error) {
	sessName := opts.RoleSessionName
	if sessName == "" {
		sessName = "bezosbuster"
	}
	stsClient := sts.NewFromConfig(base.Config)
	var out []AccountTarget
	for _, arn := range opts.AssumeRoleArns {
		arn = strings.TrimSpace(arn)
		if arn == "" {
			continue
		}
		prov := stscreds.NewAssumeRoleProvider(stsClient, arn, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessName
			if opts.ExternalID != "" {
				o.ExternalID = aws.String(opts.ExternalID)
			}
		})
		cfg := base.Config.Copy()
		cfg.Credentials = aws.NewCredentialsCache(prov)
		id, alias, err := whoAmI(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("assume %s: %w", arn, err)
		}
		out = append(out, AccountTarget{
			AccountID: id,
			Alias:     alias,
			Profile:   opts.Profile,
			Config:    cfg,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid role ARNs to assume")
	}
	return out, nil
}

func loadProfile(ctx context.Context, profile, region string) (AccountTarget, error) {
	loadOpts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return AccountTarget{}, err
	}
	id, alias, err := whoAmI(ctx, cfg)
	if err != nil {
		return AccountTarget{}, err
	}
	return AccountTarget{AccountID: id, Alias: alias, Profile: profile, Config: cfg}, nil
}

func whoAmI(ctx context.Context, cfg aws.Config) (string, string, error) {
	client := sts.NewFromConfig(cfg)
	id, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", err
	}
	arn := aws.ToString(id.Arn)
	return aws.ToString(id.Account), arn, nil
}

func enumerateOrg(ctx context.Context, base AccountTarget, roleName, externalID, sessionName string) ([]AccountTarget, error) {
	if sessionName == "" {
		sessionName = "bezosbuster"
	}
	org := organizations.NewFromConfig(base.Config)
	var accounts []orgtypes.Account
	var token *string
	for {
		out, err := org.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("organizations:ListAccounts: %w", err)
		}
		accounts = append(accounts, out.Accounts...)
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}

	stsClient := sts.NewFromConfig(base.Config)
	var targets []AccountTarget
	// Always include the management account itself (base).
	targets = append(targets, base)
	for _, a := range accounts {
		accID := aws.ToString(a.Id)
		if accID == base.AccountID {
			continue
		}
		if a.Status != orgtypes.AccountStatusActive {
			continue
		}
		roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accID, roleName)
		prov := stscreds.NewAssumeRoleProvider(stsClient, roleArn, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessionName
			if externalID != "" {
				o.ExternalID = aws.String(externalID)
			}
		})
		cfg := base.Config.Copy()
		cfg.Credentials = aws.NewCredentialsCache(prov)
		// Probe it now so we can skip broken assumes.
		if _, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
			// Skip, but don't fatal.
			continue
		}
		targets = append(targets, AccountTarget{
			AccountID: accID,
			Alias:     aws.ToString(a.Name),
			Profile:   base.Profile,
			Config:    cfg,
		})
	}
	return targets, nil
}

// ListProfiles returns all profile names found in ~/.aws/config and
// ~/.aws/credentials. The "default" profile is included if present.
func ListProfiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, path := range []string{
		filepath.Join(home, ".aws", "config"),
		filepath.Join(home, ".aws", "credentials"),
	} {
		names, _ := parseProfileNames(path)
		for _, n := range names {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out, nil
}

// parseProfileNames extracts profile names from an INI-style AWS config file.
// In ~/.aws/config sections are "[profile foo]"; in ~/.aws/credentials they're "[foo]".
func parseProfileNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
			continue
		}
		section := line[1 : len(line)-1]
		section = strings.TrimSpace(section)
		section = strings.TrimPrefix(section, "profile ")
		section = strings.TrimSpace(section)
		if section != "" {
			names = append(names, section)
		}
	}
	return names, scanner.Err()
}

// IsExpired returns true when an AWS SDK error indicates expired credentials.
func IsExpired(err error) bool {
	if err == nil {
		return false
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		code := ae.ErrorCode()
		if strings.Contains(code, "Expired") || code == "ExpiredToken" || code == "ExpiredTokenException" {
			return true
		}
	}
	if strings.Contains(err.Error(), "ExpiredToken") {
		return true
	}
	return false
}

// Ensure unused imports aren't dropped by go compile.
var _ = ststypes.Credentials{}

// ExpiryWatcher is a simple shared flag modules can check to see whether the
// scheduler has paused work due to expired creds. Not currently wired for
// live refresh — resume is via CLI `bezosbuster resume`.
type ExpiryWatcher struct{ tripped atomic.Bool }

func (w *ExpiryWatcher) Trip()         { w.tripped.Store(true) }
func (w *ExpiryWatcher) Tripped() bool { return w.tripped.Load() }
