package ssm_commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "ssm_commands" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"ssm:ListCommands", "ssm:ListCommandInvocations"}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "ssm_commands", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

// secretPatterns flags parameter values that look like they contain secrets.
var secretKeys = []string{"password", "secret", "token", "key", "credential", "passwd"}

func looksLikeSecret(key string) bool {
	k := strings.ToLower(key)
	for _, s := range secretKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := ssm.NewFromConfig(t.Config, func(o *ssm.Options) { o.Region = region })

	pager := ssm.NewListCommandsPaginator(cli, &ssm.ListCommandsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ssm list commands: %w", err)
		}
		for _, cmd := range page.Commands {
			commandID := aws.ToString(cmd.CommandId)
			docName := aws.ToString(cmd.DocumentName)
			comment := aws.ToString(cmd.Comment)
			status := string(cmd.Status)

			// Collect target instances for this command.
			var targets []string
			targets = append(targets, cmd.InstanceIds...)
			for _, tgt := range cmd.Targets {
				targets = append(targets, fmt.Sprintf("%s=%s", aws.ToString(tgt.Key), strings.Join(tgt.Values, ",")))
			}

			// Flatten parameters for display.
			params := map[string]string{}
			for k, v := range cmd.Parameters {
				params[k] = strings.Join(v, " ")
			}

			// Check for secrets in parameters.
			sev := findings.SevInfo
			var secretFindings []string
			for k, v := range params {
				if looksLikeSecret(k) && v != "" {
					sev = findings.SevHigh
					secretFindings = append(secretFindings, k)
				}
			}

			// Shell commands via AWS-RunShellScript / AWS-RunPowerShellScript
			// are interesting even without secrets.
			if strings.Contains(docName, "RunShellScript") || strings.Contains(docName, "RunPowerShellScript") {
				if sev == findings.SevInfo {
					sev = findings.SevLow
				}
			}

			title := fmt.Sprintf("SSM command %s: %s", commandID, docName)
			if len(secretFindings) > 0 {
				title += " — secrets in params: " + strings.Join(secretFindings, ", ")
			}

			var requestedAt string
			if cmd.RequestedDateTime != nil {
				requestedAt = cmd.RequestedDateTime.Format("2006-01-02 15:04:05 UTC")
			}

			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "ssm_commands",
				Severity:    sev,
				ResourceARN: fmt.Sprintf("arn:aws:ssm:%s:%s:command/%s", region, t.AccountID, commandID),
				Title:       title,
				Detail: map[string]any{
					"command_id":   commandID,
					"document":     docName,
					"comment":      comment,
					"status":       status,
					"targets":      targets,
					"parameters":   params,
					"requested_at": requestedAt,
					"instance_ids": cmd.InstanceIds,
					"s3_bucket":    aws.ToString(cmd.OutputS3BucketName),
					"s3_prefix":    aws.ToString(cmd.OutputS3KeyPrefix),
				},
			})
		}
	}
	return nil
}
