package public_rds

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "public_rds" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"rds:DescribeDBInstances", "rds:DescribeDBClusters"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := rds.NewFromConfig(t.Config, func(o *rds.Options) { o.Region = region })
		out, err := cli.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
		if err != nil {
			_ = sink.LogEvent(ctx, "public_rds", t.AccountID, "warn", region+": "+err.Error())
			continue
		}
		for _, db := range out.DBInstances {
			if db.PubliclyAccessible == nil || !*db.PubliclyAccessible {
				continue
			}
			endpoint := ""
			port := int32(0)
			if db.Endpoint != nil {
				endpoint = aws.ToString(db.Endpoint.Address)
				if db.Endpoint.Port != nil {
					port = *db.Endpoint.Port
				}
			}
			reachable := false
			if endpoint != "" && port > 0 {
				d := net.Dialer{Timeout: 3 * time.Second}
				c, dErr := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", endpoint, port))
				if dErr == nil {
					c.Close()
					reachable = true
				}
			}
			sev := findings.SevHigh
			if reachable {
				sev = findings.SevCritical
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "public_rds",
				Severity:    sev,
				ResourceARN: aws.ToString(db.DBInstanceArn),
				Title:       fmt.Sprintf("Public RDS %s (%s)", aws.ToString(db.DBInstanceIdentifier), aws.ToString(db.Engine)),
				Detail: map[string]any{
					"endpoint":            endpoint,
					"port":                port,
					"engine":              aws.ToString(db.Engine),
					"publicly_accessible": true,
					"tcp_reachable":       reachable,
				},
			})
		}
	}
	return nil
}
