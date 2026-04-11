package public_snapshots

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "public_snapshots" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"ec2:DescribeSnapshots"}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := ec2.NewFromConfig(t.Config, func(o *ec2.Options) { o.Region = region })
		// Snapshots restorable by "all" AND owned by this account.
		var nextToken *string
		for {
			out, err := cli.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
				OwnerIds:            []string{"self"},
				RestorableByUserIds: []string{"all"},
				NextToken:           nextToken,
			})
			if err != nil {
				_ = sink.LogEvent(ctx, "public_snapshots", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, s := range out.Snapshots {
				f := findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_snapshots",
					Severity:    findings.SevHigh,
					ResourceARN: "arn:aws:ec2:" + region + "::snapshot/" + aws.ToString(s.SnapshotId),
					Title:       "Public EBS snapshot: " + aws.ToString(s.SnapshotId),
					Detail: map[string]any{
						"snapshot_id": aws.ToString(s.SnapshotId),
						"volume_id":   aws.ToString(s.VolumeId),
						"volume_size": s.VolumeSize,
						"description": aws.ToString(s.Description),
						"start_time":  s.StartTime,
					},
				}
				if err := sink.Write(ctx, f); err != nil {
					return err
				}
			}
			if out.NextToken == nil {
				break
			}
			nextToken = out.NextToken
		}
	}
	return nil
}
