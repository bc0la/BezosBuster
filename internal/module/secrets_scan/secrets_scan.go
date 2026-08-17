// Package secrets_scan collects text from 35+ AWS locations where secrets
// can be stored insecurely and feeds them through kingfisher for detection.
package secrets_scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bc0la/BezosBuster/internal/awsapi"
	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

// progressKey is the context key used to pass the sink to collectors so they
// can emit live progress without a signature change.
type progressKey struct{}

// progress emits a TUI/log progress event if a sink is in ctx. accountID is
// captured at Run() entry — collectors don't need it.
func progress(ctx context.Context, msg string) {
	pc, _ := ctx.Value(progressKey{}).(progressCtx)
	if pc.sink == nil {
		return
	}
	_ = pc.sink.LogEvent(ctx, "secrets_scan", pc.accountID, "info", msg)
}

type progressCtx struct {
	sink      findings.Sink
	accountID string
}

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
		"ssm:ListDocuments", "ssm:GetDocument",
		"ssm:DescribeAutomationExecutions", "ssm:GetAutomationExecution",
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

// kfFinding matches kingfisher's nested JSON output structure.
type kfFinding struct {
	Rule    kfRule   `json:"rule"`
	Finding kfDetail `json:"finding"`
}

type kfRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type kfDetail struct {
	Snippet    string       `json:"snippet"`
	Path       string       `json:"path"`
	Line       int          `json:"line"`
	Confidence string       `json:"confidence"`
	Validation kfValidation `json:"validation"`
}

type kfValidation struct {
	Status string `json:"status"`
}

// kfReport is one document of kingfisher's --format json output. Findings is a
// RawMessage rather than []kfFinding because kingfisher emits the findings
// report ({"findings":[...]}) AND a trailing run summary that reuses the key as
// a count ({"findings":<number>,...}); decoding straight into a slice trips on
// the number. parseKingfisherJSON inspects the raw value and only harvests the
// array form.
type kfReport struct {
	Findings json.RawMessage `json:"findings"`
}

// parseKingfisherJSON extracts findings from kingfisher's (possibly multi-
// document) JSON output. It streams every document but only harvests the one
// whose "findings" is a JSON array; the summary document (a number) is skipped
// rather than logged as a decode error. Hard decode failures are returned as
// warning strings so the caller can surface them without aborting the scan.
func parseKingfisherJSON(out []byte) (all []kfFinding, warnings []string) {
	dec := json.NewDecoder(bytes.NewReader(out))
	docIdx := 0
	for dec.More() {
		var report kfReport
		if err := dec.Decode(&report); err != nil {
			// Log head of what was left so we can see what kingfisher really outputs.
			off := int(dec.InputOffset())
			snippet := ""
			if off < len(out) {
				end := off + 200
				if end > len(out) {
					end = len(out)
				}
				snippet = string(out[off:end])
			}
			warnings = append(warnings, fmt.Sprintf(
				"kingfisher JSON decode error at doc %d offset %d: %s — next bytes: %q",
				docIdx, off, err.Error(), snippet))
			break
		}
		docIdx++
		raw := bytes.TrimSpace(report.Findings)
		if len(raw) == 0 || raw[0] != '[' {
			// Summary document (findings is a count) or a doc without findings.
			continue
		}
		var fs []kfFinding
		if err := json.Unmarshal(raw, &fs); err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"kingfisher: could not parse findings array in doc %d: %s", docIdx-1, err.Error()))
			continue
		}
		all = append(all, fs...)
	}
	return all, warnings
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	kfPath, err := exec.LookPath("kingfisher")
	if err != nil {
		// Degrade gracefully like the collect wrappers: warn and skip rather
		// than fail the module. Lets the native binary run `scan` clean; use
		// the Docker image (kingfisher baked in) or `--no-secrets` otherwise.
		_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "warn",
			"kingfisher not on PATH — skipping secrets_scan (install kingfisher, use the Docker image, or pass --no-secrets)")
		return nil
	}

	regions := awsapi.EnabledRegions(ctx, t.Config)
	ctx = context.WithValue(ctx, progressKey{}, progressCtx{sink: sink, accountID: t.AccountID})

	// --- Phase 1: Collect non-S3 samples concurrently ---
	type namedCollector struct {
		name string
		fn   func(ctx context.Context, t creds.AccountTarget, regions []string) []sample
	}
	collectors := []namedCollector{
		{"EC2 user data", collectEC2UserData},
		{"Lambda env vars", collectLambdaEnv},
		{"Lambda code", collectLambdaCode},
		{"ECS task defs", collectECSTaskDefs},
		{"CodeBuild env", collectCodeBuildEnv},
		{"SSM parameters", collectSSMParams},
		{"SSM command output", collectSSMCommandOutput},
		{"SSM documents", collectSSMDocuments},
		{"SSM automation", collectSSMAutomation},
		{"CloudFormation", collectCloudFormation},
		{"API GW stage vars", collectAPIGWStageVars},
		{"Step Functions", collectStepFunctions},
		{"CloudWatch Logs", collectCloudWatchLogs},
		{"IAM keys", collectIAMKeys},
		{"Glue jobs/connections", collectGlue},
		{"CodePipeline", collectCodePipeline},
		{"Elastic Beanstalk", collectBeanstalk},
		{"AppSync", collectAppSync},
		{"App Runner", collectAppRunner},
		{"Lightsail", collectLightsail},
		{"SageMaker", collectSageMaker},
		{"EMR", collectEMR},
		{"Amplify", collectAmplify},
		{"Redshift", collectRedshift},
	}

	var mu sync.Mutex
	var allSamples []sample
	var wg sync.WaitGroup
	var doneCount int32

	// Optional per-collector timeout from context.
	var timeoutMins int
	if v, ok := ctx.Value("bb.secrets_collector_timeout_mins").(int); ok {
		timeoutMins = v
	}

	for _, c := range collectors {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
				fmt.Sprintf("collecting: %s", c.name))

			collectCtx := ctx
			var cancel context.CancelFunc
			if timeoutMins > 0 {
				collectCtx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMins)*time.Minute)
				defer cancel()
			}

			samples := c.fn(collectCtx, t, regions)
			mu.Lock()
			allSamples = append(allSamples, samples...)
			doneCount++
			done := doneCount
			total := int32(len(collectors))
			mu.Unlock()
			timedOut := ""
			if collectCtx.Err() == context.DeadlineExceeded {
				timedOut = " (timed out — partial results kept)"
			}
			_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
				fmt.Sprintf("collected %d samples from %s (%d/%d collectors done)%s",
					len(samples), c.name, done, total, timedOut))
		}()
	}
	wg.Wait()

	_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
		fmt.Sprintf("collected %d total non-S3 samples", len(allSamples)))

	// Scan non-S3 samples.
	if len(allSamples) > 0 {
		_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
			fmt.Sprintf("running kingfisher on %d non-S3 samples", len(allSamples)))
		scanSamples(ctx, kfPath, allSamples, t, sink)
		_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info", "kingfisher non-S3 scan complete")
	}

	// --- Phase 2: S3 — scan per-bucket with cleanup ---
	if ctx.Value("bb.no_s3") != nil {
		_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info", "S3 scan skipped (--no-s3)")
	} else {
		_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info", "starting S3 scan")
		scanS3PerBucket(ctx, kfPath, t, sink)
	}

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

	kfFindings := runKingfisher(ctx, kfPath, tmpDir, "non_s3", t, sink)
	emitFindings(kfFindings, fileMap, tmpDir, t, sink, ctx.Value("bb.redact_secrets") == nil)
}

// saveRawOutput writes kingfisher's raw output to
// <engagement>/secrets_scan/<account>/<phase>.json.
func saveRawOutput(phase string, out []byte, t creds.AccountTarget, sink findings.Sink) {
	rawDir, err := sink.RawDir("secrets_scan", t.AccountID)
	if err != nil {
		return
	}
	// Sanitize phase for filesystem (bucket names may contain dots, etc).
	safe := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' {
			return '_'
		}
		return r
	}, phase)
	path := filepath.Join(rawDir, safe+".json")
	_ = os.WriteFile(path, out, 0600)
}

func runKingfisher(ctx context.Context, kfPath, dir, phase string, t creds.AccountTarget, sink findings.Sink) []kfFinding {
	cmd := exec.CommandContext(ctx, kfPath, "scan", dir,
		"--format", "json",
		"--git-history", "none",
		"--no-validate",
	)

	tickDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-tickDone:
				return
			case <-ticker.C:
				_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
					fmt.Sprintf("kingfisher %s: still scanning… (%s elapsed)",
						phase, time.Since(start).Truncate(time.Second)))
			}
		}
	}()

	out, err := cmd.Output()
	close(tickDone)
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

	// Save raw kingfisher output for auditing.
	if len(out) > 0 {
		saveRawOutput(phase, out, t, sink)
	}

	// Kingfisher emits multiple JSON documents (the findings report plus a run
	// summary that reuses the "findings" key as a count). parseKingfisherJSON
	// harvests only the array form and reports any real decode failures.
	all, warnings := parseKingfisherJSON(out)
	for _, w := range warnings {
		_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "warn", w)
	}
	_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
		fmt.Sprintf("kingfisher found %d findings, %d total bytes", len(all), len(out)))
	return all
}

// emitFindings writes one report finding per kingfisher hit. unredact defaults
// to true: the full secret value is stored so it's usable straight from the
// report UI, and the file that hit is copied into the engagement dir (see
// saveHitFile) with the finding's RawOutputPath pointing at it. Pass
// --redact-secrets to keep only a short redacted preview and skip saving files.
func emitFindings(kfFindings []kfFinding, fileMap map[string]*sample, tmpDir string, t creds.AccountTarget, sink findings.Sink, unredact bool) {
	ctx := context.Background()
	for _, f := range kfFindings {
		fname := filepath.Base(f.Finding.Path)
		s, ok := fileMap[fname]
		if !ok {
			continue
		}

		sev := findings.SevHigh
		if strings.EqualFold(f.Finding.Validation.Status, "valid") {
			sev = findings.SevCritical
		} else if strings.EqualFold(f.Finding.Confidence, "low") {
			sev = findings.SevMedium
		}

		region := s.Region
		if region == "" {
			region = "global"
		}

		title := fmt.Sprintf("[%s] %s in %s", f.Rule.ID, f.Rule.Name, s.Source)
		match := redactMatch(f.Finding.Snippet)
		if unredact {
			match = f.Finding.Snippet
		}

		// The sample Source is "<sourcetype>/<resource>" (e.g. "ssm_param/Name",
		// "s3/bucket/key"). Expose the leading source-type as a filterable check
		// facet, namespaced "kf:" so the report UI keeps kingfisher hits visually
		// distinct from the native secrets modules (lambda_env, ssm_commands, …).
		sourceType := s.Source
		if i := strings.IndexByte(sourceType, '/'); i >= 0 {
			sourceType = sourceType[:i]
		}

		detail := map[string]any{
			"rule_id":     f.Rule.ID,
			"rule_name":   f.Rule.Name,
			"match":       match,
			"source":      s.Source,
			"source_type": sourceType,
			"check":       "kf:" + sourceType,
			"line":        f.Finding.Line,
			"confidence":  f.Finding.Confidence,
			"validation":  f.Finding.Validation.Status,
		}
		for k, v := range s.Metadata {
			detail[k] = v
		}

		// Command to re-fetch the raw resource by hand (e.g. the exact task-def
		// revision by ARN), so the finding is actionable straight from the report.
		if cmd := pullCommand(sourceType, region, s.Metadata); cmd != "" {
			detail["pull_command"] = cmd
		}

		// Persist the file that hit (unless redacting) so the report can link
		// straight to the offending content. RawOutputPath points at the
		// containing folder — the report's /raw/ browser appends a trailing
		// slash and lists it.
		var rawOut string
		if unredact {
			if saved := saveHitFile(filepath.Join(tmpDir, fname), s.Source, t, sink); saved != "" {
				detail["saved_file"] = saved
				rawOut = filepath.Dir(saved)
			}
		}

		_ = sink.Write(ctx, findings.Finding{
			AccountID:     t.AccountID,
			Region:        region,
			Module:        "secrets_scan",
			Severity:      sev,
			ResourceARN:   s.Metadata["arn"],
			Title:         title,
			Detail:        detail,
			RawOutputPath: rawOut,
		})
	}
}

// saveHitFile copies a file kingfisher flagged into a browsable location under
// the engagement dir: <engagement>/secrets_scan/<account>/hits/<source>, where
// <source> is the sample Source (e.g. "s3/bucket/key") preserved as a nested
// path. Returns the destination path, or "" on any failure (best-effort).
//
// Sources are not always unique: collectECSTaskDefs emits one sample per
// task-def revision but keys them all on "ecs_taskdef/<family>". To avoid one
// revision clobbering another, an identical existing file is reused, otherwise
// the next free "<name>-N" suffix is chosen.
func saveHitFile(srcPath, source string, t creds.AccountTarget, sink findings.Sink) string {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return ""
	}
	rawDir, err := sink.RawDir("secrets_scan", t.AccountID)
	if err != nil {
		return ""
	}
	rel := sanitizeSourcePath(source)
	if rel == "" {
		return ""
	}
	base := filepath.Join(rawDir, "hits", rel)
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		return ""
	}
	dest := base
	for i := 2; ; i++ {
		existing, rerr := os.ReadFile(dest)
		if os.IsNotExist(rerr) {
			break // free slot
		}
		if rerr == nil && bytes.Equal(existing, data) {
			return dest // exact content already saved (e.g. re-hit of same file)
		}
		dest = fmt.Sprintf("%s-%d", base, i) // occupied by different content
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return ""
	}
	return dest
}

// sanitizeSourcePath turns a sample Source into a safe relative path, keeping
// "/" as directory separators but dropping empty/"."/".." segments (no
// traversal) and neutralising ":" / "\".
func sanitizeSourcePath(source string) string {
	repl := strings.NewReplacer(":", "_", "\\", "_")
	var clean []string
	for _, p := range strings.Split(source, "/") {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		clean = append(clean, repl.Replace(p))
	}
	return filepath.Join(clean...)
}

// afterLast returns the substring after the last occurrence of sep (or s whole).
func afterLast(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+len(sep):]
	}
	return s
}

// pullCommand returns an AWS CLI command that re-fetches the raw resource a
// kingfisher hit came from, so an analyst can pull the full object by hand.
// Returns "" for source types we can't reconstruct a command for.
func pullCommand(sourceType, region string, meta map[string]string) string {
	r := ""
	if region != "" && region != "global" {
		r = " --region " + region
	}
	switch sourceType {
	case "ecs_taskdef":
		return "aws ecs describe-task-definition --task-definition " + meta["arn"] + r
	case "lambda_env":
		return "aws lambda get-function-configuration --function-name " + meta["function"] + r
	case "lambda_code":
		return "aws lambda get-function --function-name " + meta["function"] + " --query Code.Location --output text" + r + "   # then curl the returned URL"
	case "ssm_param":
		return "aws ssm get-parameter --name '" + meta["name"] + "' --with-decryption" + r
	case "ssm_output":
		return "aws ssm list-command-invocations --command-id " + meta["command_id"] + " --details" + r
	case "ssm_document":
		return "aws ssm get-document --name " + meta["name"] + r
	case "ssm_automation":
		return "aws ssm get-automation-execution --automation-execution-id " + meta["execution_id"] + r
	case "cfn_params":
		return "aws cloudformation describe-stacks --stack-name " + meta["stack"] + r
	case "cfn_template":
		return "aws cloudformation get-template --stack-name " + meta["stack"] + " --query TemplateBody" + r
	case "codebuild":
		return "aws codebuild batch-get-projects --names " + meta["project"] + r
	case "ec2_userdata":
		return "aws ec2 describe-instance-attribute --instance-id " + meta["instance_id"] + " --attribute userData --query UserData.Value --output text" + r + " | base64 -d"
	case "s3":
		return "aws s3api get-object --bucket " + meta["bucket"] + " --key '" + meta["key"] + "' /dev/stdout" + r
	case "stepfn":
		return "aws stepfunctions describe-state-machine --state-machine-arn " + meta["arn"] + r
	case "cwlogs":
		cmd := "aws logs get-log-events --log-group-name '" + meta["group"] + "'"
		if s := meta["stream"]; s != "" {
			cmd += " --log-stream-name '" + s + "'"
		}
		return cmd + r
	case "iam_keys":
		return "aws iam list-access-keys --user-name " + meta["user"]
	case "glue_job":
		return "aws glue get-job --job-name " + meta["name"] + r
	case "glue_conn":
		return "aws glue get-connection --name " + meta["name"] + r
	case "codepipeline":
		return "aws codepipeline get-pipeline --name " + meta["name"] + r
	case "beanstalk":
		return "aws elasticbeanstalk describe-configuration-settings --application-name " + meta["app"] + " --environment-name " + meta["env"] + r
	case "apprunner":
		return "aws apprunner describe-service --service-arn " + meta["arn"] + r
	case "redshift_params":
		return "aws redshift describe-cluster-parameters --parameter-group-name " + meta["parameter_group"] + r
	case "sagemaker_lc":
		return "aws sagemaker describe-notebook-instance-lifecycle-config --notebook-instance-lifecycle-config-name " + meta["name"] + r
	case "apigw_vars":
		return "aws apigateway get-stage --rest-api-id " + afterLast(meta["arn"], "/") + " --stage-name " + meta["stage"] + r
	case "emr":
		return "aws emr list-bootstrap-actions --cluster-id " + afterLast(meta["arn"], "/") + r
	case "amplify":
		return "aws amplify get-app --app-id " + afterLast(meta["arn"], "/") + r
	case "appsync":
		return "aws appsync list-graphql-apis" + r + "   # api '" + meta["api"] + "'"
	}
	return ""
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
