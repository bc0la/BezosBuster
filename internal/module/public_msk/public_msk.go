// Package public_msk flags Amazon MSK (managed Kafka) provisioned clusters
// that have public access enabled on their brokers, exposing the Kafka
// bootstrap brokers to the internet via service-provided EIPs.
package public_msk

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "public_msk" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"kafka:ListClustersV2"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := kafka.NewFromConfig(t.Config, func(o *kafka.Options) { o.Region = region })
		pager := kafka.NewListClustersV2Paginator(cli, &kafka.ListClustersV2Input{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "public_msk", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, c := range page.ClusterInfoList {
				if c.ClusterType != kafkatypes.ClusterTypeProvisioned || c.Provisioned == nil {
					continue // serverless clusters cannot be publicly exposed this way
				}
				bng := c.Provisioned.BrokerNodeGroupInfo
				if bng == nil || bng.ConnectivityInfo == nil || bng.ConnectivityInfo.PublicAccess == nil {
					continue
				}
				paType := aws.ToString(bng.ConnectivityInfo.PublicAccess.Type)
				if paType == "" || strings.EqualFold(paType, "DISABLED") {
					continue
				}
				kafkaVersion := ""
				if c.Provisioned.CurrentBrokerSoftwareInfo != nil {
					kafkaVersion = aws.ToString(c.Provisioned.CurrentBrokerSoftwareInfo.KafkaVersion)
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_msk",
					Severity:    findings.SevHigh,
					ResourceARN: aws.ToString(c.ClusterArn),
					Title:       fmt.Sprintf("Public MSK cluster %s (public access: %s)", aws.ToString(c.ClusterName), paType),
					Detail: map[string]any{
						"cluster":            aws.ToString(c.ClusterName),
						"public_access_type": paType,
						"kafka_version":      kafkaVersion,
						"broker_count":       aws.ToInt32(c.Provisioned.NumberOfBrokerNodes),
					},
				})
			}
		}
	}
	return nil
}
