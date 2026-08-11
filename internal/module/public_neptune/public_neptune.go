// Package public_neptune flags Amazon Neptune instances marked
// PubliclyAccessible, exposing the graph-database endpoint to the internet.
// Reachability is confirmed with a TCP dial.
package public_neptune

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "public_neptune" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"rds:DescribeDBInstances"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := neptune.NewFromConfig(t.Config, func(o *neptune.Options) { o.Region = region })
		pager := neptune.NewDescribeDBInstancesPaginator(cli, &neptune.DescribeDBInstancesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "public_neptune", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, db := range page.DBInstances {
				// Neptune shares the RDS control plane; DescribeDBInstances
				// returns non-Neptune engines too, so filter by engine.
				engine := aws.ToString(db.Engine)
				if engine != "neptune" {
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
					Module:      "public_neptune",
					Severity:    sev,
					ResourceARN: aws.ToString(db.DBInstanceArn),
					Title:       fmt.Sprintf("Public Neptune instance %s", id),
					Detail: map[string]any{
						"instance":            id,
						"cluster":             aws.ToString(db.DBClusterIdentifier),
						"engine":              engine,
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
