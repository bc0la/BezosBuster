// Package secrets_scan collects text from 35+ AWS locations where secrets
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
		"apprunner:ListServices", "apprunner:DescribeService",
		"sagemaker:ListNotebookInstances",
		"sagemaker:DescribeNotebookInstanceLifecycleConfig",
		"emr:ListClusters", "emr:DescribeCluster", "emr:ListBootstrapActions",
		"redshift:DescribeClusters", "redshift:DescribeClusterParameters",
		"amplify:ListApps", "amplify:ListBranches",
	}
}

// sample is a piece of text collected from an AWS source to scan for secrets.
type sample struct {
	Source   string
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
	kfPath, err := exec.LookPath("kingfisher")
	if err != nil {
		return fmt.Errorf("kingfisher not on PATH — install in Docker image: %w", err)
	}

	regions := awsapi.EnabledRegions(ctx, t.Config)

	// --- Phase 1: Collect non-S3 samples concurrently ---
	var mu sync.Mutex
	var allSamples []sample
	var wg sync.WaitGroup

	collectors := []func(ctx context.Context, t creds.AccountTarget, regions []string) []sample{
		collectEC2UserData,
		collectLambdaEnv,
		collectLambdaCode,
		collectECSTaskDefs,
		collectCodeBuildEnv,
		collectSSMParams,
		collectSSMCommandOutput,
		collectCloudFormation,
		collectAPIGWStageVars,
		collectStepFunctions,
		collectCloudWatchLogs,
		collectIAMKeys,
		collectGlue,
		collectCodePipeline,
		collectBeanstalk,
		collectAppSync,
		collectAppRunner,
		collectLightsail,
		collectSageMaker,
		collectEMR,
		collectAmplify,
		collectRedshift,
	}

	for _, fn := range collectors {
		fn := fn
		wg.Add(1)
		go func() {
			defer wg.Done()
			samples := fn(ctx, t, regions)
			mu.Lock()
			allSamples = append(allSamples, samples...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
		fmt.Sprintf("collected %d non-S3 samples", len(allSamples)))

	// Scan non-S3 samples.
	if len(allSamples) > 0 {
		scanSamples(ctx, kfPath, allSamples, t, sink)
	}

	// --- Phase 2: S3 — scan per-bucket with cleanup ---
	_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info", "starting S3 scan")
	scanS3PerBucket(ctx, kfPath, t, sink)

	return nil
}

// scanSamples writes samples to a temp dir, runs kingfisher, emits findings, cleans up.
func scanSamples(ctx context.Context, kfPath string, samples []sample, t creds.AccountTarget, sink findings.Sink) {
	tmpDir, err := os.MkdirTemp("", "bb-secrets-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(tmpDir)

	fileMap := map[string]*sample{}
	for i := range samples {
		s := &samples[i]
		safe := strings.ReplaceAll(s.Source, "/", "__")
		safe = strings.ReplaceAll(safe, ":", "_")
		fname := fmt.Sprintf("%04d_%s.txt", i, safe)
		fpath := filepath.Join(tmpDir, fname)
		if err := os.WriteFile(fpath, []byte(s.Content), 0600); err != nil {
			continue
		}
		fileMap[fname] = s
	}

	kfFindings := runKingfisher(ctx, kfPath, tmpDir, t, sink)
	emitFindings(kfFindings, fileMap, t, sink)
}

func runKingfisher(ctx context.Context, kfPath, dir string, t creds.AccountTarget, sink findings.Sink) []kfFinding {
	cmd := exec.CommandContext(ctx, kfPath, "scan", dir,
		"--format", "json",
		"--git-history", "none",
		"--no-validate",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 200 && exitErr.ExitCode() != 205 {
				_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "warn",
					fmt.Sprintf("kingfisher exit %d: %s", exitErr.ExitCode(), string(exitErr.Stderr)))
			}
			if len(out) == 0 {
				out = exitErr.Stderr
			}
		} else {
			return nil
		}
	}

	var report kfReport
	if err := json.Unmarshal(out, &report); err != nil {
		if err2 := json.Unmarshal(out, &report.Findings); err2 != nil {
			return nil
		}
	}
	return report.Findings
}

func emitFindings(kfFindings []kfFinding, fileMap map[string]*sample, t creds.AccountTarget, sink findings.Sink) {
	ctx := context.Background()
	for _, f := range kfFindings {
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
