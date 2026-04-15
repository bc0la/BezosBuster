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
	Profile     string
	Profiles    []string
	Org         bool
	AssumeRole  string // for org mode
	Region      string
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
	return enumerateOrg(ctx, base, assumeRole)
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

func enumerateOrg(ctx context.Context, base AccountTarget, roleName string) ([]AccountTarget, error) {
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
			o.RoleSessionName = "bezosbuster"
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

func (w *ExpiryWatcher) Trip()      { w.tripped.Store(true) }
func (w *ExpiryWatcher) Tripped() bool { return w.tripped.Load() }
