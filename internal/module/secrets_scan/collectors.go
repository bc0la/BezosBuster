package secrets_scan

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/you/bezosbuster/internal/creds"
)

// --- EC2 User Data ---

func collectEC2UserData(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := ec2.NewFromConfig(t.Config, func(o *ec2.Options) { o.Region = region })
		pager := ec2.NewDescribeInstancesPaginator(cli, &ec2.DescribeInstancesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, res := range page.Reservations {
				for _, inst := range res.Instances {
					if inst.State != nil && inst.State.Name == ec2types.InstanceStateNameTerminated {
						continue
					}
					id := aws.ToString(inst.InstanceId)
					attr, err := cli.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
						InstanceId: aws.String(id),
						Attribute:  ec2types.InstanceAttributeNameUserData,
					})
					if err != nil || attr.UserData == nil || aws.ToString(attr.UserData.Value) == "" {
						continue
					}
					decoded, err := base64.StdEncoding.DecodeString(aws.ToString(attr.UserData.Value))
					if err != nil {
						continue
					}
					out = append(out, sample{
						Source: "ec2_userdata/" + id, Region: region,
						Content:  string(decoded),
						Metadata: map[string]string{"arn": fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, t.AccountID, id), "instance_id": id},
					})
				}
			}
		}
	}
	return out
}

// --- Lambda Environment Variables ---

func collectLambdaEnv(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := lambda.NewFromConfig(t.Config, func(o *lambda.Options) { o.Region = region })
		var marker *string
		for {
			list, err := cli.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
			if err != nil {
				break
			}
			for _, fn := range list.Functions {
				if fn.Environment == nil || len(fn.Environment.Variables) == 0 {
					continue
				}
				var lines []string
				for k, v := range fn.Environment.Variables {
					lines = append(lines, k+"="+v)
				}
				out = append(out, sample{
					Source: "lambda_env/" + aws.ToString(fn.FunctionName), Region: region,
					Content:  strings.Join(lines, "\n"),
					Metadata: map[string]string{"arn": aws.ToString(fn.FunctionArn), "function": aws.ToString(fn.FunctionName)},
				})
			}
			if list.NextMarker == nil {
				break
			}
			marker = list.NextMarker
		}
	}
	return out
}

// --- Lambda Function Code ---

func collectLambdaCode(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := lambda.NewFromConfig(t.Config, func(o *lambda.Options) { o.Region = region })
		var marker *string
		for {
			list, err := cli.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
			if err != nil {
				break
			}
			for _, fn := range list.Functions {
				// Only download small functions (< 5MB code size).
				if fn.CodeSize > 5*1024*1024 {
					continue
				}
				get, err := cli.GetFunction(ctx, &lambda.GetFunctionInput{
					FunctionName: fn.FunctionArn,
				})
				if err != nil || get.Code == nil || get.Code.Location == nil {
					continue
				}
				// The location is a presigned URL. We write it as metadata
				// for kingfisher to potentially download, but for now we skip
				// actual download — the env vars are the main target.
				// TODO: download and extract zip for scanning.
			}
			if list.NextMarker == nil {
				break
			}
			marker = list.NextMarker
		}
	}
	return out
}

// --- ECS Task Definitions ---

func collectECSTaskDefs(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := ecs.NewFromConfig(t.Config, func(o *ecs.Options) { o.Region = region })
		var token *string
		for {
			list, err := cli.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
				NextToken: token, Status: ecstypes.TaskDefinitionStatusActive,
			})
			if err != nil {
				break
			}
			for _, arn := range list.TaskDefinitionArns {
				desc, err := cli.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
					TaskDefinition: aws.String(arn),
				})
				if err != nil || desc.TaskDefinition == nil {
					continue
				}
				var lines []string
				for _, c := range desc.TaskDefinition.ContainerDefinitions {
					for _, kv := range c.Environment {
						lines = append(lines, aws.ToString(kv.Name)+"="+aws.ToString(kv.Value))
					}
					// Also check command/entrypoint for embedded secrets.
					if len(c.Command) > 0 {
						lines = append(lines, "COMMAND="+strings.Join(c.Command, " "))
					}
					if len(c.EntryPoint) > 0 {
						lines = append(lines, "ENTRYPOINT="+strings.Join(c.EntryPoint, " "))
					}
				}
				if len(lines) == 0 {
					continue
				}
				out = append(out, sample{
					Source: "ecs_taskdef/" + aws.ToString(desc.TaskDefinition.Family), Region: region,
					Content:  strings.Join(lines, "\n"),
					Metadata: map[string]string{"arn": arn, "family": aws.ToString(desc.TaskDefinition.Family)},
				})
			}
			if list.NextToken == nil {
				break
			}
			token = list.NextToken
		}
	}
	return out
}

// --- CodeBuild Environment Variables ---

func collectCodeBuildEnv(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := codebuild.NewFromConfig(t.Config, func(o *codebuild.Options) { o.Region = region })
		var nextToken *string
		for {
			list, err := cli.ListProjects(ctx, &codebuild.ListProjectsInput{NextToken: nextToken})
			if err != nil || len(list.Projects) == 0 {
				break
			}
			for i := 0; i < len(list.Projects); i += 100 {
				end := i + 100
				if end > len(list.Projects) {
					end = len(list.Projects)
				}
				batch, err := cli.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: list.Projects[i:end]})
				if err != nil {
					continue
				}
				for _, proj := range batch.Projects {
					if proj.Environment == nil {
						continue
					}
					var lines []string
					for _, ev := range proj.Environment.EnvironmentVariables {
						if ev.Type == cbtypes.EnvironmentVariableTypePlaintext {
							lines = append(lines, aws.ToString(ev.Name)+"="+aws.ToString(ev.Value))
						}
					}
					if len(lines) == 0 {
						continue
					}
					out = append(out, sample{
						Source: "codebuild/" + aws.ToString(proj.Name), Region: region,
						Content:  strings.Join(lines, "\n"),
						Metadata: map[string]string{"arn": aws.ToString(proj.Arn), "project": aws.ToString(proj.Name)},
					})
				}
			}
			if list.NextToken == nil {
				break
			}
			nextToken = list.NextToken
		}
	}
	return out
}

// --- SSM Parameters (non-SecureString) ---

func collectSSMParams(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := ssm.NewFromConfig(t.Config, func(o *ssm.Options) { o.Region = region })
		pager := ssm.NewDescribeParametersPaginator(cli, &ssm.DescribeParametersInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			var names []string
			for _, p := range page.Parameters {
				if p.Type != ssmtypes.ParameterTypeSecureString {
					names = append(names, aws.ToString(p.Name))
				}
			}
			// GetParameters in batches of 10.
			for i := 0; i < len(names); i += 10 {
				end := i + 10
				if end > len(names) {
					end = len(names)
				}
				get, err := cli.GetParameters(ctx, &ssm.GetParametersInput{Names: names[i:end]})
				if err != nil {
					continue
				}
				for _, p := range get.Parameters {
					out = append(out, sample{
						Source: "ssm_param/" + aws.ToString(p.Name), Region: region,
						Content:  aws.ToString(p.Name) + "=" + aws.ToString(p.Value),
						Metadata: map[string]string{"arn": aws.ToString(p.ARN), "name": aws.ToString(p.Name), "type": string(p.Type)},
					})
				}
			}
		}
	}
	return out
}

// --- SSM Command Output ---

func collectSSMCommandOutput(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := ssm.NewFromConfig(t.Config, func(o *ssm.Options) { o.Region = region })
		pager := ssm.NewListCommandsPaginator(cli, &ssm.ListCommandsInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, cmd := range page.Commands {
				cmdID := aws.ToString(cmd.CommandId)
				// Fetch invocations with output.
				invPager := ssm.NewListCommandInvocationsPaginator(cli, &ssm.ListCommandInvocationsInput{
					CommandId: aws.String(cmdID),
					Details:   true,
				})
				for invPager.HasMorePages() {
					invPage, err := invPager.NextPage(ctx)
					if err != nil {
						break
					}
					for _, inv := range invPage.CommandInvocations {
						for _, p := range inv.CommandPlugins {
							output := aws.ToString(p.Output)
							if output == "" {
								continue
							}
							// Truncate at 50KB.
							if len(output) > 50*1024 {
								output = output[:50*1024]
							}
							instID := aws.ToString(inv.InstanceId)
							out = append(out, sample{
								Source: "ssm_output/" + cmdID + "/" + instID, Region: region,
								Content: output,
								Metadata: map[string]string{
									"arn":         fmt.Sprintf("arn:aws:ssm:%s:%s:command/%s", region, t.AccountID, cmdID),
									"command_id":  cmdID,
									"instance_id": instID,
									"document":    aws.ToString(cmd.DocumentName),
								},
							})
						}
					}
				}
			}
		}
	}
	return out
}

// --- CloudFormation ---

func collectCloudFormation(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := cloudformation.NewFromConfig(t.Config, func(o *cloudformation.Options) { o.Region = region })
		pager := cloudformation.NewListStacksPaginator(cli, &cloudformation.ListStacksInput{
			StackStatusFilter: []cftypes.StackStatus{
				cftypes.StackStatusCreateComplete, cftypes.StackStatusUpdateComplete,
				cftypes.StackStatusRollbackComplete, cftypes.StackStatusUpdateRollbackComplete,
			},
		})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, stack := range page.StackSummaries {
				stackName := aws.ToString(stack.StackName)
				stackARN := aws.ToString(stack.StackId)

				// Stack parameters and outputs.
				desc, err := cli.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
					StackName: aws.String(stackName),
				})
				if err == nil && len(desc.Stacks) > 0 {
					s := desc.Stacks[0]
					var lines []string
					for _, p := range s.Parameters {
						lines = append(lines, "PARAM:"+aws.ToString(p.ParameterKey)+"="+aws.ToString(p.ParameterValue))
					}
					for _, o := range s.Outputs {
						lines = append(lines, "OUTPUT:"+aws.ToString(o.OutputKey)+"="+aws.ToString(o.OutputValue))
					}
					if len(lines) > 0 {
						out = append(out, sample{
							Source: "cfn_params/" + stackName, Region: region,
							Content:  strings.Join(lines, "\n"),
							Metadata: map[string]string{"arn": stackARN, "stack": stackName},
						})
					}
				}

				// Template body.
				tmpl, err := cli.GetTemplate(ctx, &cloudformation.GetTemplateInput{
					StackName: aws.String(stackName),
				})
				if err == nil && tmpl.TemplateBody != nil {
					body := aws.ToString(tmpl.TemplateBody)
					// Skip very large templates.
					if len(body) < 1024*1024 {
						out = append(out, sample{
							Source: "cfn_template/" + stackName, Region: region,
							Content:  body,
							Metadata: map[string]string{"arn": stackARN, "stack": stackName},
						})
					}
				}
			}
		}
	}
	return out
}

// --- API Gateway Stage Variables ---

func collectAPIGWStageVars(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := apigateway.NewFromConfig(t.Config, func(o *apigateway.Options) { o.Region = region })
		apiPager := apigateway.NewGetRestApisPaginator(cli, &apigateway.GetRestApisInput{})
		for apiPager.HasMorePages() {
			page, err := apiPager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, api := range page.Items {
				apiID := aws.ToString(api.Id)
				apiName := aws.ToString(api.Name)
				stages, err := cli.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
				if err != nil {
					continue
				}
				for _, stage := range stages.Item {
					if len(stage.Variables) == 0 {
						continue
					}
					var lines []string
					for k, v := range stage.Variables {
						lines = append(lines, k+"="+v)
					}
					out = append(out, sample{
						Source: "apigw_vars/" + apiName + "/" + aws.ToString(stage.StageName), Region: region,
						Content: strings.Join(lines, "\n"),
						Metadata: map[string]string{
							"arn":   fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiID),
							"api":   apiName,
							"stage": aws.ToString(stage.StageName),
						},
					})
				}
			}
		}
	}
	return out
}

// --- S3 Targeted Secret File Scan ---

var secretFilePatterns = []string{
	".env", ".env.local", ".env.production", ".env.staging",
	"credentials", ".credentials", "config.json", "secrets.json",
	".htpasswd", "id_rsa", "id_ed25519",
	"terraform.tfstate", "docker-compose.yml", "docker-compose.yaml",
	".git/config", ".npmrc", ".pypirc", ".netrc",
}

const maxS3FileSize = 1024 * 1024     // 1MB
const maxS3ObjectsPerBucket = 100_000 // skip huge buckets

func collectS3Secrets(ctx context.Context, t creds.AccountTarget, _ []string) []sample {
	var out []sample
	s3Cli := s3.NewFromConfig(t.Config)
	buckets, err := s3Cli.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return out
	}
	for _, b := range buckets.Buckets {
		bName := aws.ToString(b.Name)
		// Determine bucket region.
		loc, err := s3Cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bName)})
		if err != nil {
			continue
		}
		bucketRegion := string(loc.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}
		regionCli := s3.NewFromConfig(t.Config, func(o *s3.Options) { o.Region = bucketRegion })

		// Quick object count check — list first page only.
		firstPage, err := regionCli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  aws.String(bName),
			MaxKeys: aws.Int32(1000),
		})
		if err != nil {
			continue
		}
		if aws.ToInt32(firstPage.KeyCount) >= 1000 && aws.ToBool(firstPage.IsTruncated) {
			// Large bucket — only scan objects matching secret patterns.
			for _, pattern := range secretFilePatterns {
				scanS3Prefix(ctx, regionCli, bName, bucketRegion, t.AccountID, pattern, &out)
			}
			continue
		}

		// Small bucket — check all objects against patterns.
		for _, obj := range firstPage.Contents {
			key := aws.ToString(obj.Key)
			if aws.ToInt64(obj.Size) > maxS3FileSize || aws.ToInt64(obj.Size) == 0 {
				continue
			}
			if matchesSecretPattern(key) {
				downloadS3Object(ctx, regionCli, bName, key, bucketRegion, t.AccountID, &out)
			}
		}
	}
	return out
}

func matchesSecretPattern(key string) bool {
	lower := strings.ToLower(key)
	base := lower
	if idx := strings.LastIndex(lower, "/"); idx >= 0 {
		base = lower[idx+1:]
	}
	for _, p := range secretFilePatterns {
		if base == p || strings.HasSuffix(base, p) {
			return true
		}
	}
	// Also check for common extensions.
	for _, ext := range []string{".pem", ".key", ".pfx", ".p12"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func scanS3Prefix(ctx context.Context, cli *s3.Client, bucket, region, accountID, pattern string, out *[]sample) {
	list, err := cli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(100),
	})
	if err != nil {
		return
	}
	for _, obj := range list.Contents {
		key := aws.ToString(obj.Key)
		if aws.ToInt64(obj.Size) > maxS3FileSize || aws.ToInt64(obj.Size) == 0 {
			continue
		}
		if matchesSecretPattern(key) {
			downloadS3Object(ctx, cli, bucket, key, region, accountID, out)
		}
	}
}

func downloadS3Object(ctx context.Context, cli *s3.Client, bucket, key, region, accountID string, out *[]sample) {
	get, err := cli.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return
	}
	defer get.Body.Close()
	body, err := io.ReadAll(io.LimitReader(get.Body, maxS3FileSize))
	if err != nil || len(body) == 0 {
		return
	}
	*out = append(*out, sample{
		Source: "s3/" + bucket + "/" + key, Region: region,
		Content: string(body),
		Metadata: map[string]string{
			"arn":    fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, key),
			"bucket": bucket,
			"key":    key,
		},
	})
}

// --- Step Functions ---

func collectStepFunctions(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := sfn.NewFromConfig(t.Config, func(o *sfn.Options) { o.Region = region })
		var nextToken *string
		for {
			list, err := cli.ListStateMachines(ctx, &sfn.ListStateMachinesInput{NextToken: nextToken})
			if err != nil {
				break
			}
			for _, sm := range list.StateMachines {
				smARN := aws.ToString(sm.StateMachineArn)
				desc, err := cli.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
					StateMachineArn: aws.String(smARN),
				})
				if err != nil {
					continue
				}
				def := aws.ToString(desc.Definition)
				if def == "" {
					continue
				}
				out = append(out, sample{
					Source: "stepfn/" + aws.ToString(sm.Name), Region: region,
					Content:  def,
					Metadata: map[string]string{"arn": smARN, "name": aws.ToString(sm.Name)},
				})
			}
			if list.NextToken == nil {
				break
			}
			nextToken = list.NextToken
		}
	}
	return out
}

// --- CloudWatch Logs (recent entries) ---

func collectCloudWatchLogs(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := cloudwatchlogs.NewFromConfig(t.Config, func(o *cloudwatchlogs.Options) { o.Region = region })
		var nextToken *string
		groupCount := 0
		for {
			groups, err := cli.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{NextToken: nextToken})
			if err != nil {
				break
			}
			for _, g := range groups.LogGroups {
				groupCount++
				if groupCount > 50 { // cap at 50 log groups per region
					break
				}
				groupName := aws.ToString(g.LogGroupName)
				// Get most recent stream.
				streams, err := cli.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
					LogGroupName: aws.String(groupName),
					OrderBy:      "LastEventTime",
					Descending:   aws.Bool(true),
					Limit:        aws.Int32(1),
				})
				if err != nil || len(streams.LogStreams) == 0 {
					continue
				}
				streamName := aws.ToString(streams.LogStreams[0].LogStreamName)
				events, err := cli.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
					LogGroupName:  aws.String(groupName),
					LogStreamName: aws.String(streamName),
					Limit:         aws.Int32(100),
					StartFromHead: aws.Bool(false),
				})
				if err != nil {
					continue
				}
				var lines []string
				for _, e := range events.Events {
					lines = append(lines, aws.ToString(e.Message))
				}
				if len(lines) == 0 {
					continue
				}
				out = append(out, sample{
					Source: "cwlogs/" + groupName, Region: region,
					Content: strings.Join(lines, "\n"),
					Metadata: map[string]string{
						"arn":    aws.ToString(g.Arn),
						"group":  groupName,
						"stream": streamName,
					},
				})
			}
			if groupCount > 50 || groups.NextToken == nil {
				break
			}
			nextToken = groups.NextToken
		}
	}
	return out
}

// --- IAM Access Keys ---

func collectIAMKeys(ctx context.Context, t creds.AccountTarget, _ []string) []sample {
	var out []sample
	cli := iam.NewFromConfig(t.Config)
	var marker *string
	for {
		users, err := cli.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			break
		}
		for _, u := range users.Users {
			userName := aws.ToString(u.UserName)
			keys, err := cli.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(userName)})
			if err != nil {
				continue
			}
			var lines []string
			for _, k := range keys.AccessKeyMetadata {
				lines = append(lines, fmt.Sprintf("AccessKeyId=%s Status=%s Created=%s",
					aws.ToString(k.AccessKeyId), string(k.Status),
					k.CreateDate.Format("2006-01-02")))
			}
			if len(lines) > 0 {
				out = append(out, sample{
					Source: "iam_keys/" + userName, Region: "global",
					Content: strings.Join(lines, "\n"),
					Metadata: map[string]string{
						"arn":  aws.ToString(u.Arn),
						"user": userName,
					},
				})
			}
		}
		if users.Marker == nil {
			break
		}
		marker = users.Marker
	}
	return out
}

// --- Glue Jobs + Connections ---

func collectGlue(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := glue.NewFromConfig(t.Config, func(o *glue.Options) { o.Region = region })

		// Jobs.
		jobs, err := cli.GetJobs(ctx, &glue.GetJobsInput{})
		if err == nil {
			for _, j := range jobs.Jobs {
				var lines []string
				for k, v := range j.DefaultArguments {
					lines = append(lines, k+"="+v)
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "glue_job/" + aws.ToString(j.Name), Region: region,
						Content: strings.Join(lines, "\n"),
						Metadata: map[string]string{
							"arn":  fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, t.AccountID, aws.ToString(j.Name)),
							"name": aws.ToString(j.Name),
						},
					})
				}
			}
		}

		// Connections.
		conns, err := cli.GetConnections(ctx, &glue.GetConnectionsInput{})
		if err == nil {
			for _, c := range conns.ConnectionList {
				var lines []string
				for k, v := range c.ConnectionProperties {
					lines = append(lines, k+"="+v)
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "glue_conn/" + aws.ToString(c.Name), Region: region,
						Content: strings.Join(lines, "\n"),
						Metadata: map[string]string{
							"arn":  fmt.Sprintf("arn:aws:glue:%s:%s:connection/%s", region, t.AccountID, aws.ToString(c.Name)),
							"name": aws.ToString(c.Name),
						},
					})
				}
			}
		}
	}
	return out
}

// --- CodePipeline ---

func collectCodePipeline(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := codepipeline.NewFromConfig(t.Config, func(o *codepipeline.Options) { o.Region = region })
		var nextToken *string
		for {
			list, err := cli.ListPipelines(ctx, &codepipeline.ListPipelinesInput{NextToken: nextToken})
			if err != nil {
				break
			}
			for _, p := range list.Pipelines {
				pName := aws.ToString(p.Name)
				get, err := cli.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: aws.String(pName)})
				if err != nil || get.Pipeline == nil {
					continue
				}
				var lines []string
				for _, stage := range get.Pipeline.Stages {
					for _, action := range stage.Actions {
						for k, v := range action.Configuration {
							lines = append(lines, fmt.Sprintf("%s/%s/%s=%s",
								aws.ToString(stage.Name), aws.ToString(action.Name), k, v))
						}
					}
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "codepipeline/" + pName, Region: region,
						Content: strings.Join(lines, "\n"),
						Metadata: map[string]string{
							"arn":  fmt.Sprintf("arn:aws:codepipeline:%s:%s:%s", region, t.AccountID, pName),
							"name": pName,
						},
					})
				}
			}
			if list.NextToken == nil {
				break
			}
			nextToken = list.NextToken
		}
	}
	return out
}

// --- Elastic Beanstalk ---

func collectBeanstalk(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := elasticbeanstalk.NewFromConfig(t.Config, func(o *elasticbeanstalk.Options) { o.Region = region })
		envs, err := cli.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
		if err != nil {
			continue
		}
		for _, env := range envs.Environments {
			envName := aws.ToString(env.EnvironmentName)
			appName := aws.ToString(env.ApplicationName)
			settings, err := cli.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
				ApplicationName: aws.String(appName),
				EnvironmentName: aws.String(envName),
			})
			if err != nil {
				continue
			}
			var lines []string
			for _, cs := range settings.ConfigurationSettings {
				for _, opt := range cs.OptionSettings {
					ns := aws.ToString(opt.Namespace)
					key := aws.ToString(opt.OptionName)
					val := aws.ToString(opt.Value)
					if ns == "aws:elasticbeanstalk:application:environment" && val != "" {
						lines = append(lines, key+"="+val)
					}
				}
			}
			if len(lines) > 0 {
				out = append(out, sample{
					Source: "beanstalk/" + envName, Region: region,
					Content: strings.Join(lines, "\n"),
					Metadata: map[string]string{
						"arn": aws.ToString(env.EnvironmentArn),
						"env": envName, "app": appName,
					},
				})
			}
		}
	}
	return out
}

// --- AppSync API Keys ---

func collectAppSync(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := appsync.NewFromConfig(t.Config, func(o *appsync.Options) { o.Region = region })
		apis, err := cli.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{})
		if err != nil {
			continue
		}
		for _, api := range apis.GraphqlApis {
			apiID := aws.ToString(api.ApiId)
			apiName := aws.ToString(api.Name)
			keys, err := cli.ListApiKeys(ctx, &appsync.ListApiKeysInput{ApiId: aws.String(apiID)})
			if err != nil || len(keys.ApiKeys) == 0 {
				continue
			}
			var lines []string
			for _, k := range keys.ApiKeys {
				lines = append(lines, fmt.Sprintf("APPSYNC_API_KEY=%s", aws.ToString(k.Id)))
			}
			out = append(out, sample{
				Source: "appsync/" + apiName, Region: region,
				Content: strings.Join(lines, "\n"),
				Metadata: map[string]string{
					"arn":  fmt.Sprintf("arn:aws:appsync:%s:%s:apis/%s", region, t.AccountID, apiID),
					"api":  apiName,
				},
			})
		}
	}
	return out
}
