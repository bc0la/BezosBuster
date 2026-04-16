package ec2_userdata

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

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

func (Module) Name() string      { return "ec2_userdata" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"ec2:DescribeInstances", "ec2:DescribeInstanceAttribute"}
}

var secretPatterns = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"aws_access_key", "aws_secret", "credential", "private_key",
	"BEGIN RSA", "BEGIN PRIVATE", "BEGIN EC PRIVATE", "AKIA",
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "ec2_userdata", t.AccountID, "warn", region+": "+err.Error())
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
				instanceID := aws.ToString(inst.InstanceId)
				attr, err := cli.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
					InstanceId: aws.String(instanceID),
					Attribute:  ec2types.InstanceAttributeNameUserData,
				})
				if err != nil || attr.UserData == nil || aws.ToString(attr.UserData.Value) == "" {
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(aws.ToString(attr.UserData.Value))
				if err != nil {
					continue
				}
				userData := string(decoded)

				// Check for secrets in user data.
				sev := findings.SevInfo
				var secretHits []string
				lower := strings.ToLower(userData)
				for _, p := range secretPatterns {
					if strings.Contains(lower, strings.ToLower(p)) {
						secretHits = append(secretHits, p)
					}
				}
				if len(secretHits) > 0 {
					sev = findings.SevHigh
				}

				name := instanceID
				for _, tag := range inst.Tags {
					if aws.ToString(tag.Key) == "Name" {
						name = aws.ToString(tag.Value) + " (" + instanceID + ")"
						break
					}
				}

				title := "EC2 user data: " + name
				if len(secretHits) > 0 {
					title += " — potential secrets: " + strings.Join(secretHits, ", ")
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "ec2_userdata",
					Severity:    sev,
					ResourceARN: fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, t.AccountID, instanceID),
					Title:       title,
					Detail: map[string]any{
						"instance_id":    instanceID,
						"name":           name,
						"state":          string(inst.State.Name),
						"user_data":      userData,
						"secret_matches": secretHits,
					},
				})
			}
		}
	}
	return nil
}
