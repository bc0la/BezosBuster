// Package public_mq flags Amazon MQ brokers (ActiveMQ / RabbitMQ) marked
// PubliclyAccessible, which exposes the broker's wire and web-console
// endpoints to the internet.
package public_mq

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "public_mq" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"mq:ListBrokers", "mq:DescribeBroker"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := mq.NewFromConfig(t.Config, func(o *mq.Options) { o.Region = region })
		var next *string
		for {
			list, err := cli.ListBrokers(ctx, &mq.ListBrokersInput{NextToken: next})
			if err != nil {
				_ = sink.LogEvent(ctx, "public_mq", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, b := range list.BrokerSummaries {
				desc, err := cli.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: b.BrokerId})
				if err != nil {
					_ = sink.LogEvent(ctx, "public_mq", t.AccountID, "warn", region+" "+aws.ToString(b.BrokerName)+": "+err.Error())
					continue
				}
				if !aws.ToBool(desc.PubliclyAccessible) {
					continue
				}
				var endpoints []string
				var consoles []string
				for _, inst := range desc.BrokerInstances {
					endpoints = append(endpoints, inst.Endpoints...)
					if c := aws.ToString(inst.ConsoleURL); c != "" {
						consoles = append(consoles, c)
					}
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_mq",
					Severity:    findings.SevHigh,
					ResourceARN: aws.ToString(desc.BrokerArn),
					Title:       fmt.Sprintf("Public Amazon MQ broker %s (%s)", aws.ToString(desc.BrokerName), string(desc.EngineType)),
					Detail: map[string]any{
						"broker":              aws.ToString(desc.BrokerName),
						"engine":              string(desc.EngineType),
						"engine_version":      aws.ToString(desc.EngineVersion),
						"publicly_accessible": true,
						"endpoints":           endpoints,
						"console_urls":        consoles,
					},
				})
			}
			if list.NextToken == nil {
				break
			}
			next = list.NextToken
		}
	}
	return nil
}
