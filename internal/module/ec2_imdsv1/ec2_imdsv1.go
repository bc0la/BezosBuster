package ec2_imdsv1

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "ec2_imdsv1" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"ec2:DescribeInstances"}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "ec2_imdsv1", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := ec2.NewFromConfig(t.Config, func(o *ec2.Options) { o.Region = region })
	pager := ec2.NewDescribeInstancesPaginator(cli, &ec2.DescribeInstancesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				if inst.State != nil && inst.State.Name == ec2types.InstanceStateNameTerminated {
					continue
				}
				if inst.MetadataOptions == nil {
					continue
				}
				// HttpTokens == "optional" means IMDSv1 is allowed.
				if inst.MetadataOptions.HttpTokens != ec2types.HttpTokensStateOptional {
					continue
				}

				instanceID := aws.ToString(inst.InstanceId)
				name := instanceID
				for _, tag := range inst.Tags {
					if aws.ToString(tag.Key) == "Name" {
						name = aws.ToString(tag.Value) + " (" + instanceID + ")"
						break
					}
				}

				hopLimit := aws.ToInt32(inst.MetadataOptions.HttpPutResponseHopLimit)
				var iamRole string
				if inst.IamInstanceProfile != nil {
					iamRole = aws.ToString(inst.IamInstanceProfile.Arn)
				}

				// Severity: HIGH if IAM role attached (SSRF → creds), MEDIUM otherwise.
				sev := findings.SevMedium
				reason := "IMDSv1 allowed (HttpTokens=optional)"
				if iamRole != "" {
					sev = findings.SevHigh
					reason += " with IAM role attached — SSRF → credentials exfiltration"
				}
				if hopLimit > 1 {
					reason += fmt.Sprintf(" (hop limit %d, increases container reachability)", hopLimit)
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "ec2_imdsv1",
					Severity:    sev,
					ResourceARN: fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, t.AccountID, instanceID),
					Title:       fmt.Sprintf("EC2 %s: %s", name, reason),
					Detail: map[string]any{
						"instance_id":   instanceID,
						"name":          name,
						"state":         string(inst.State.Name),
						"http_tokens":   string(inst.MetadataOptions.HttpTokens),
						"http_endpoint": string(inst.MetadataOptions.HttpEndpoint),
						"hop_limit":     hopLimit,
						"iam_role":      iamRole,
						"instance_type": string(inst.InstanceType),
						"launch_time":   inst.LaunchTime,
					},
				})
			}
		}
	}
	return nil
}
