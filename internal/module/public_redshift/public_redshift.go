// Package public_redshift flags Amazon Redshift clusters marked
// PubliclyAccessible, which places the cluster behind an internet-routable
// endpoint (<name>.<rand>.<region>.redshift.amazonaws.com). Combined with a
// permissive security group this exposes the database to the internet; the
// module confirms reachability with a TCP dial to the cluster endpoint.
package public_redshift

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "public_redshift" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"redshift:DescribeClusters"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := redshift.NewFromConfig(t.Config, func(o *redshift.Options) { o.Region = region })
		var marker *string
		for {
			out, err := cli.DescribeClusters(ctx, &redshift.DescribeClustersInput{Marker: marker})
			if err != nil {
				_ = sink.LogEvent(ctx, "public_redshift", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, c := range out.Clusters {
				if !aws.ToBool(c.PubliclyAccessible) {
					continue
				}
				id := aws.ToString(c.ClusterIdentifier)
				endpoint := ""
				port := int32(0)
				if c.Endpoint != nil {
					endpoint = aws.ToString(c.Endpoint.Address)
					port = aws.ToInt32(c.Endpoint.Port)
				}
				reachable := dialTCP(ctx, endpoint, port)
				sev := findings.SevHigh
				if reachable {
					sev = findings.SevCritical
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_redshift",
					Severity:    sev,
					ResourceARN: fmt.Sprintf("arn:aws:redshift:%s:%s:cluster:%s", region, t.AccountID, id),
					Title:       fmt.Sprintf("Public Redshift cluster %s", id),
					Detail: map[string]any{
						"cluster":             id,
						"endpoint":            endpoint,
						"port":                port,
						"publicly_accessible": true,
						"tcp_reachable":       reachable,
						"node_type":           aws.ToString(c.NodeType),
						"database":            aws.ToString(c.DBName),
						"master_username":     aws.ToString(c.MasterUsername),
						"encrypted":           aws.ToBool(c.Encrypted),
						"vpc_id":              aws.ToString(c.VpcId),
					},
				})
			}
			if out.Marker == nil {
				break
			}
			marker = out.Marker
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
