// Package secrets_scan collects text from 30+ AWS locations where secrets
// can be stored insecurely and feeds them through kingfisher for detection.
package secrets_scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "secrets_scan" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"ec2:DescribeInstances", "ec2:DescribeInstanceAttribute",
		"lambda:ListFunctions", "lambda:GetFunction",
		"ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition",
		"codebuild:ListProjects", "codebuild:BatchGetProjects",
		"ssm:GetParametersByPath", "ssm:DescribeParameters",
		"ssm:ListCommands", "ssm:ListCommandInvocations",
		"cloudformation:ListStacks", "cloudformation:GetTemplate",
		"cloudformation:DescribeStacks",
		"apigateway:GET",
		"s3:ListAllMyBuckets", "s3:ListBucket", "s3:GetObject",
		"states:ListStateMachines", "states:DescribeStateMachine",
		"logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:GetLogEvents",
		"iam:ListUsers", "iam:ListAccessKeys",
		"glue:GetJobs", "glue:GetConnections",
		"codepipeline:ListPipelines", "codepipeline:GetPipeline",
		"elasticbeanstalk:DescribeEnvironments",
		"elasticbeanstalk:DescribeConfigurationSettings",
		"appsync:ListGraphqlApis", "appsync:ListApiKeys",
		"cognito-idp:ListUserPools",
	}
}

// sample is a piece of text collected from an AWS source to scan for secrets.
type sample struct {
	Source   string // e.g. "ec2_userdata/i-abc123"
	Region   string
	Content  string
	Metadata map[string]string
}

// kfFinding is the subset of kingfisher JSON output we parse.
type kfFinding struct {
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	Match      string `json:"match"`
	FilePath   string `json:"file_path"`
	Line       int    `json:"line"`
	Confidence string `json:"confidence"`
	Severity   string `json:"severity"`
	Verified   *bool  `json:"verified"`
}

type kfReport struct {
	Findings []kfFinding `json:"findings"`
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	// Check kingfisher is available.
	kfPath, err := exec.LookPath("kingfisher")
	if err != nil {
		return fmt.Errorf("kingfisher not on PATH — install in Docker image: %w", err)
	}

	regions := awsapi.EnabledRegions(ctx, t.Config)

	// Collect samples from all sources concurrently.
	var mu sync.Mutex
	var allSamples []sample
	var wg sync.WaitGroup
	var sampleCount atomic.Int64

	collect := func(fn func(ctx context.Context, t creds.AccountTarget, regions []string) []sample) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			samples := fn(ctx, t, regions)
			mu.Lock()
			allSamples = append(allSamples, samples...)
			mu.Unlock()
			sampleCount.Add(int64(len(samples)))
		}()
	}

	// Launch all collectors.
	collect(collectEC2UserData)
	collect(collectLambdaEnv)
	collect(collectLambdaCode)
	collect(collectECSTaskDefs)
	collect(collectCodeBuildEnv)
	collect(collectSSMParams)
	collect(collectSSMCommandOutput)
	collect(collectCloudFormation)
	collect(collectAPIGWStageVars)
	collect(collectS3Secrets)
	collect(collectStepFunctions)
	collect(collectCloudWatchLogs)
	collect(collectIAMKeys)
	collect(collectGlue)
	collect(collectCodePipeline)
	collect(collectBeanstalk)
	collect(collectAppSync)

	wg.Wait()

	_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
		fmt.Sprintf("collected %d samples from %d sources", len(allSamples), sampleCount.Load()))

	if len(allSamples) == 0 {
		return nil
	}

	// Write samples to temp directory as files for kingfisher to scan.
	tmpDir, err := os.MkdirTemp("", "bb-secrets-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Map file paths back to sample metadata.
	fileMap := map[string]*sample{}
	for i := range allSamples {
		s := &allSamples[i]
		// Create subdirectory per source type for organization.
		safe := strings.ReplaceAll(s.Source, "/", "__")
		safe = strings.ReplaceAll(safe, ":", "_")
		fname := fmt.Sprintf("%04d_%s.txt", i, safe)
		fpath := filepath.Join(tmpDir, fname)
		if err := os.WriteFile(fpath, []byte(s.Content), 0600); err != nil {
			continue
		}
		fileMap[fname] = s
	}

	// Run kingfisher.
	cmd := exec.CommandContext(ctx, kfPath, "scan", tmpDir,
		"--format", "json",
		"--git-history", "none",
		"--no-validate",
	)
	out, err := cmd.Output()
	if err != nil {
		// Kingfisher exits 200 when findings exist — that's not an error.
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 200 && exitErr.ExitCode() != 205 {
				_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "warn",
					fmt.Sprintf("kingfisher exited %d: %s", exitErr.ExitCode(), string(exitErr.Stderr)))
			}
			// Use stdout even on non-zero exit.
			if len(out) == 0 {
				out = exitErr.Stderr
			}
		} else {
			return fmt.Errorf("kingfisher: %w", err)
		}
	}

	// Parse kingfisher output.
	var report kfReport
	if err := json.Unmarshal(out, &report); err != nil {
		// Try parsing as array directly.
		if err2 := json.Unmarshal(out, &report.Findings); err2 != nil {
			_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "warn",
				"failed to parse kingfisher output: "+err.Error())
			return nil
		}
	}

	// Emit findings.
	for _, f := range report.Findings {
		fname := filepath.Base(f.FilePath)
		s, ok := fileMap[fname]
		if !ok {
			continue
		}

		sev := findings.SevHigh
		if f.Verified != nil && *f.Verified {
			sev = findings.SevCritical
		} else if strings.EqualFold(f.Severity, "low") || strings.EqualFold(f.Confidence, "low") {
			sev = findings.SevMedium
		}

		region := s.Region
		if region == "" {
			region = "global"
		}

		title := fmt.Sprintf("[%s] %s in %s", f.RuleID, f.RuleName, s.Source)

		// Redact the match to show only first/last few chars.
		redacted := redactMatch(f.Match)

		detail := map[string]any{
			"rule_id":    f.RuleID,
			"rule_name":  f.RuleName,
			"match":      redacted,
			"source":     s.Source,
			"line":       f.Line,
			"confidence": f.Confidence,
		}
		if f.Verified != nil {
			detail["verified"] = *f.Verified
		}
		for k, v := range s.Metadata {
			detail[k] = v
		}

		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      region,
			Module:      "secrets_scan",
			Severity:    sev,
			ResourceARN: s.Metadata["arn"],
			Title:       title,
			Detail:      detail,
		})
	}

	return nil
}

func redactMatch(s string) string {
	if len(s) <= 12 {
		return s[:min(4, len(s))] + "..."
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
