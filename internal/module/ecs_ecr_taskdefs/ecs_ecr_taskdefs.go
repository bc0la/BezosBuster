package ecs_ecr_taskdefs

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "ecs_ecr_taskdefs" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	_ = sink.LogEvent(ctx, "ecs_ecr_taskdefs", t.AccountID, "info",
		fmt.Sprintf("scanning %d regions", len(regions)))

	totalDescribed := 0
	for ri, region := range regions {
		_ = sink.LogEvent(ctx, "ecs_ecr_taskdefs", t.AccountID, "info",
			fmt.Sprintf("region %d/%d %s: listing task definitions", ri+1, len(regions), region))

		cli := ecs.NewFromConfig(t.Config, func(o *ecs.Options) { o.Region = region })
		var token *string
		regionDescribed := 0
		page := 0
		for {
			page++
			list, err := cli.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
				NextToken: token,
				Status:    ecstypes.TaskDefinitionStatusActive,
			})
			if err != nil {
				_ = sink.LogEvent(ctx, "ecs_ecr_taskdefs", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			pageTotal := len(list.TaskDefinitionArns)
			for i, arn := range list.TaskDefinitionArns {
				if i%5 == 0 {
					_ = sink.LogEvent(ctx, "ecs_ecr_taskdefs", t.AccountID, "info",
						fmt.Sprintf("%s page %d: describing %d/%d", region, page, i+1, pageTotal))
				}
				desc, err := cli.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
					TaskDefinition: aws.String(arn),
				})
				if err != nil || desc.TaskDefinition == nil {
					continue
				}
				td := desc.TaskDefinition
				var containers []map[string]any
				for _, c := range td.ContainerDefinitions {
					env := map[string]string{}
					for _, kv := range c.Environment {
						env[aws.ToString(kv.Name)] = aws.ToString(kv.Value)
					}
					containers = append(containers, map[string]any{
						"name":  aws.ToString(c.Name),
						"image": aws.ToString(c.Image),
						"env":   env,
					})
				}
				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "ecs_ecr_taskdefs",
					Severity:    findings.SevInfo,
					ResourceARN: arn,
					Title:       "ECS task definition " + aws.ToString(td.Family),
					Detail: map[string]any{
						"family":     aws.ToString(td.Family),
						"revision":   td.Revision,
						"containers": containers,
						"task_role":  aws.ToString(td.TaskRoleArn),
						"exec_role":  aws.ToString(td.ExecutionRoleArn),
					},
				})
				regionDescribed++
				totalDescribed++
			}
			if list.NextToken == nil {
				break
			}
			token = list.NextToken
		}
		_ = sink.LogEvent(ctx, "ecs_ecr_taskdefs", t.AccountID, "info",
			fmt.Sprintf("region %s done: %d task definitions described", region, regionDescribed))
	}
	_ = sink.LogEvent(ctx, "ecs_ecr_taskdefs", t.AccountID, "info",
		fmt.Sprintf("complete: %d task definitions across %d regions", totalDescribed, len(regions)))
	return nil
}
