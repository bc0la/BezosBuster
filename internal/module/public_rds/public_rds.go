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
		publicInstances := map[string]bool{}
		for _, db := range out.DBInstances {
			if !aws.ToBool(db.PubliclyAccessible) {
				continue
			}
			publicInstances[aws.ToString(db.DBInstanceIdentifier)] = true
			endpoint := ""
			port := int32(0)
			if db.Endpoint != nil {
				endpoint = aws.ToString(db.Endpoint.Address)
				port = aws.ToInt32(db.Endpoint.Port)
			}
			reachable := dialTCP(ctx, endpoint, port)
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
					"cluster":             aws.ToString(db.DBClusterIdentifier),
				},
			})
		}

		clusters, err := cli.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
		if err != nil {
			_ = sink.LogEvent(ctx, "public_rds", t.AccountID, "warn", region+" (clusters): "+err.Error())
			continue
		}
		for _, c := range clusters.DBClusters {
			clusterPublic := aws.ToBool(c.PubliclyAccessible)
			var publicMembers []string
			var writerPublic bool
			for _, m := range c.DBClusterMembers {
				id := aws.ToString(m.DBInstanceIdentifier)
				if !publicInstances[id] {
					continue
				}
				publicMembers = append(publicMembers, id)
				if aws.ToBool(m.IsClusterWriter) {
					writerPublic = true
				}
			}
			if !clusterPublic && len(publicMembers) == 0 {
				continue
			}

			writerEP := aws.ToString(c.Endpoint)
			readerEP := aws.ToString(c.ReaderEndpoint)
			port := aws.ToInt32(c.Port)
			// Writer endpoint resolves to the writer instance — only reachable
			// via cluster DNS when the writer itself is public (or the cluster
			// is Multi-AZ-public).
			writerReachable := false
			if clusterPublic || writerPublic {
				writerReachable = dialTCP(ctx, writerEP, port)
			}
			readerReachable := false
			if clusterPublic || len(publicMembers) > 0 {
				readerReachable = dialTCP(ctx, readerEP, port)
			}

			sev := findings.SevHigh
			if writerReachable || readerReachable {
				sev = findings.SevCritical
			}
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "public_rds",
				Severity:    sev,
				ResourceARN: aws.ToString(c.DBClusterArn),
				Title:       fmt.Sprintf("Public RDS cluster %s (%s)", aws.ToString(c.DBClusterIdentifier), aws.ToString(c.Engine)),
				Detail: map[string]any{
					"cluster":                 aws.ToString(c.DBClusterIdentifier),
					"engine":                  aws.ToString(c.Engine),
					"endpoint":                writerEP,
					"reader_endpoint":         readerEP,
					"custom_endpoints":        c.CustomEndpoints,
					"port":                    port,
					"cluster_public_flag":     clusterPublic,
					"public_member_instances": publicMembers,
					"writer_tcp_reachable":    writerReachable,
					"reader_tcp_reachable":    readerReachable,
				},
			})
		}
	}
	return nil
}

func dialTCP(ctx context.Context, host string, port int32) bool {
	if host == "" || port <= 0 {
		return false
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	c.Close()
	return true
}
