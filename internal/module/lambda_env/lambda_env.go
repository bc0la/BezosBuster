package lambda_env

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "lambda_env" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"lambda:ListFunctions"} }

var suspiciousKey = regexp.MustCompile(`(?i)(secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)`)
var suspiciousValue = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|-----BEGIN|xox[baprs]-|eyJ[A-Za-z0-9_-]{10,})`)

// Run walks every Lambda function in every enabled region and emits one
// finding per (function, env var) pair so every variable is visible in the
// report UI as its own row, filterable and searchable. Variables whose key
// or value matches secret-like patterns are flagged high; the rest are info.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := lambda.NewFromConfig(t.Config, func(o *lambda.Options) { o.Region = region })
		var marker *string
		for {
			out, err := cli.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
			if err != nil {
				_ = sink.LogEvent(ctx, "lambda_env", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, fn := range out.Functions {
				if fn.Environment == nil || len(fn.Environment.Variables) == 0 {
					continue
				}
				fnName := aws.ToString(fn.FunctionName)
				fnArn := aws.ToString(fn.FunctionArn)
				runtime := string(fn.Runtime)

				// Stable sort by key so ordering is deterministic across runs.
				keys := make([]string, 0, len(fn.Environment.Variables))
				for k := range fn.Environment.Variables {
					keys = append(keys, k)
				}
				sort.Strings(keys)

				for _, k := range keys {
					v := fn.Environment.Variables[k]
					keyHit := suspiciousKey.MatchString(k)
					valHit := suspiciousValue.MatchString(v)
					sev := findings.SevInfo
					reasons := []string{}
					if keyHit {
						sev = findings.SevHigh
						reasons = append(reasons, "secret-like key name")
					}
					if valHit {
						sev = findings.SevHigh
						reasons = append(reasons, "secret-like value (AKIA/JWT/private key/slack token)")
					}

					title := fnName + " / " + k + " = " + truncate(v, 80)
					if len(reasons) > 0 {
						title = "[flagged] " + title
					}
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "lambda_env",
						Severity:    sev,
						ResourceARN: fnArn,
						Title:       title,
						Detail: map[string]any{
							"function": fnName,
							"runtime":  runtime,
							"key":      k,
							"value":    truncate(v, 512),
							"flagged":  reasons,
						},
					})
				}
			}
			if out.NextMarker == nil {
				break
			}
			marker = out.NextMarker
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
