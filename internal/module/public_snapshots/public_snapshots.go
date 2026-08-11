package public_snapshots

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"

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
	return []string{
		"ec2:DescribeSnapshots",
		"rds:DescribeDBSnapshots", "rds:DescribeDBSnapshotAttributes",
		"rds:DescribeDBClusterSnapshots", "rds:DescribeDBClusterSnapshotAttributes",
	}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanEBS(ctx, t, region, sink); err != nil {
			return err
		}
		scanRDS(ctx, t, region, sink)
	}
	return nil
}

// scanEBS finds EBS snapshots owned by this account and restorable by "all".
func scanEBS(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := ec2.NewFromConfig(t.Config, func(o *ec2.Options) { o.Region = region })
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
					"kind":        "ebs",
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
	return nil
}

// scanRDS finds manual RDS DB and cluster snapshots whose restore attribute
// has been shared with "all" (public). Automated snapshots cannot be shared,
// so only manual snapshots are inspected.
func scanRDS(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) {
	cli := rds.NewFromConfig(t.Config, func(o *rds.Options) { o.Region = region })

	// DB (instance) snapshots.
	dbPager := rds.NewDescribeDBSnapshotsPaginator(cli, &rds.DescribeDBSnapshotsInput{
		SnapshotType: aws.String("manual"),
	})
	for dbPager.HasMorePages() {
		page, err := dbPager.NextPage(ctx)
		if err != nil {
			_ = sink.LogEvent(ctx, "public_snapshots", t.AccountID, "warn", region+" (rds db): "+err.Error())
			break
		}
		for _, s := range page.DBSnapshots {
			id := aws.ToString(s.DBSnapshotIdentifier)
			attr, err := cli.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
				DBSnapshotIdentifier: s.DBSnapshotIdentifier,
			})
			if err != nil || attr.DBSnapshotAttributesResult == nil {
				continue
			}
			shared := false
			for _, a := range attr.DBSnapshotAttributesResult.DBSnapshotAttributes {
				if aws.ToString(a.AttributeName) == "restore" && valuesHaveAll(a.AttributeValues) {
					shared = true
					break
				}
			}
			if !shared {
				continue
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "public_snapshots",
				Severity:    findings.SevHigh,
				ResourceARN: aws.ToString(s.DBSnapshotArn),
				Title:       "Public RDS DB snapshot: " + id,
				Detail: map[string]any{
					"kind":            "rds_db",
					"snapshot_id":     id,
					"db_instance":     aws.ToString(s.DBInstanceIdentifier),
					"engine":          aws.ToString(s.Engine),
					"encrypted":       aws.ToBool(s.Encrypted),
					"allocated_gb":    s.AllocatedStorage,
					"snapshot_create": s.SnapshotCreateTime,
				},
			})
		}
	}

	// Cluster (Aurora) snapshots.
	clPager := rds.NewDescribeDBClusterSnapshotsPaginator(cli, &rds.DescribeDBClusterSnapshotsInput{
		SnapshotType: aws.String("manual"),
	})
	for clPager.HasMorePages() {
		page, err := clPager.NextPage(ctx)
		if err != nil {
			_ = sink.LogEvent(ctx, "public_snapshots", t.AccountID, "warn", region+" (rds cluster): "+err.Error())
			break
		}
		for _, s := range page.DBClusterSnapshots {
			id := aws.ToString(s.DBClusterSnapshotIdentifier)
			attr, err := cli.DescribeDBClusterSnapshotAttributes(ctx, &rds.DescribeDBClusterSnapshotAttributesInput{
				DBClusterSnapshotIdentifier: s.DBClusterSnapshotIdentifier,
			})
			if err != nil || attr.DBClusterSnapshotAttributesResult == nil {
				continue
			}
			shared := false
			for _, a := range attr.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes {
				if aws.ToString(a.AttributeName) == "restore" && valuesHaveAll(a.AttributeValues) {
					shared = true
					break
				}
			}
			if !shared {
				continue
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "public_snapshots",
				Severity:    findings.SevHigh,
				ResourceARN: aws.ToString(s.DBClusterSnapshotArn),
				Title:       "Public RDS cluster snapshot: " + id,
				Detail: map[string]any{
					"kind":            "rds_cluster",
					"snapshot_id":     id,
					"db_cluster":      aws.ToString(s.DBClusterIdentifier),
					"engine":          aws.ToString(s.Engine),
					"encrypted":       aws.ToBool(s.StorageEncrypted),
					"snapshot_create": s.SnapshotCreateTime,
				},
			})
		}
	}
}

// valuesHaveAll reports whether a snapshot "restore" attribute's value list
// includes the special value "all" (i.e. the snapshot is shared publicly).
func valuesHaveAll(values []string) bool {
	for _, v := range values {
		if v == "all" {
			return true
		}
	}
	return false
}
