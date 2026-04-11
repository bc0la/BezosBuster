package ecs_ecr_taskdefs

import (
	"context"

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
	for _, region := range regions {
		cli := ecs.NewFromConfig(t.Config, func(o *ecs.Options) { o.Region = region })
		var token *string
		for {
			list, err := cli.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
				NextToken:    token,
				Status:       ecstypes.TaskDefinitionStatusActive,
			})
			if err != nil {
				_ = sink.LogEvent(ctx, "ecs_ecr_taskdefs", t.AccountID, "warn", region+": "+err.Error())
				break
			}
			for _, arn := range list.TaskDefinitionArns {
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
						"family":      aws.ToString(td.Family),
						"revision":    td.Revision,
						"containers":  containers,
						"task_role":   aws.ToString(td.TaskRoleArn),
						"exec_role":   aws.ToString(td.ExecutionRoleArn),
					},
				})
			}
			if list.NextToken == nil {
				break
			}
			token = list.NextToken
		}
	}
	return nil
}
