// Package public_documentdb flags Amazon DocumentDB instances marked
// PubliclyAccessible, which places the MongoDB-compatible endpoint behind an
// internet-routable address. Reachability is confirmed with a TCP dial.
package public_documentdb

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"

	"github.com/bc0la/BezosBuster/internal/awsapi"
	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "public_documentdb" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"rds:DescribeDBInstances"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := docdb.NewFromConfig(t.Config, func(o *docdb.Options) { o.Region = region })
		pager := docdb.NewDescribeDBInstancesPaginator(cli, &docdb.DescribeDBInstancesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "public_documentdb", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, db := range page.DBInstances {
				// The docdb endpoint returns DocumentDB instances; guard on the
				// engine so a shared control-plane response can't mislabel one.
				if aws.ToString(db.Engine) != "docdb" {
					continue
				}
				if !aws.ToBool(db.PubliclyAccessible) {
					continue
				}
				id := aws.ToString(db.DBInstanceIdentifier)
				endpoint, port := "", int32(0)
				if db.Endpoint != nil {
					endpoint = aws.ToString(db.Endpoint.Address)
					port = aws.ToInt32(db.Endpoint.Port)
				}
				reachable := awsapi.DialTCP(ctx, endpoint, port)
				sev := findings.SevHigh
				if reachable {
					sev = findings.SevCritical
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_documentdb",
					Severity:    sev,
					ResourceARN: aws.ToString(db.DBInstanceArn),
					Title:       fmt.Sprintf("Public DocumentDB instance %s", id),
					Detail: map[string]any{
						"instance":            id,
						"cluster":             aws.ToString(db.DBClusterIdentifier),
						"engine":              aws.ToString(db.Engine),
						"endpoint":            endpoint,
						"port":                port,
						"publicly_accessible": true,
						"tcp_reachable":       reachable,
					},
				})
			}
		}
	}
	return nil
}
