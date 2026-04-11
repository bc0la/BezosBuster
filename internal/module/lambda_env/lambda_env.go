package lambda_env

import (
	"context"
	"regexp"
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
				flagged := map[string]string{}
				for k, v := range fn.Environment.Variables {
					if suspiciousKey.MatchString(k) || suspiciousValue.MatchString(v) {
						flagged[k] = truncate(v, 120)
					}
				}
				sev := findings.SevInfo
				title := "Lambda env vars: " + aws.ToString(fn.FunctionName)
				if len(flagged) > 0 {
					sev = findings.SevHigh
					title = "Lambda env vars contain secret-like material: " + aws.ToString(fn.FunctionName)
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "lambda_env",
					Severity:    sev,
					ResourceARN: aws.ToString(fn.FunctionArn),
					Title:       title,
					Detail: map[string]any{
						"function": aws.ToString(fn.FunctionName),
						"all_env":  fn.Environment.Variables,
						"flagged":  flagged,
					},
				})
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
