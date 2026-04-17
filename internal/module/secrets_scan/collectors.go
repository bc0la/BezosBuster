package secrets_scan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/you/bezosbuster/internal/findings"

	"github.com/aws/aws-sdk-go-v2/service/amplify"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
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
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/you/bezosbuster/internal/creds"
)

const maxS3FileSize = 10 * 1024 * 1024 // 10MB

// scannable extensions for Lambda code zip extraction.
var scannableExts = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true, ".java": true,
	".rb": true, ".php": true, ".cs": true, ".sh": true, ".bash": true,
	".ps1": true, ".json": true, ".yml": true, ".yaml": true, ".xml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".env": true,
	".properties": true, ".tf": true, ".hcl": true, ".sql": true, ".txt": true,
	".md": true, ".html": true, ".htm": true, ".csv": true,
}

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

// --- Lambda Function Code (download zip, extract scannable files) ---

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
				// Skip large functions (> 50MB compressed).
				if fn.CodeSize > 50*1024*1024 {
					continue
				}
				get, err := cli.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: fn.FunctionArn})
				if err != nil || get.Code == nil || get.Code.Location == nil {
					continue
				}
				// Download the zip from the presigned URL.
				samples := downloadAndExtractLambdaZip(ctx, aws.ToString(get.Code.Location),
					aws.ToString(fn.FunctionName), aws.ToString(fn.FunctionArn), region)
				out = append(out, samples...)
			}
			if list.NextMarker == nil {
				break
			}
			marker = list.NextMarker
		}
	}
	return out
}

func downloadAndExtractLambdaZip(ctx context.Context, url, fnName, fnARN, region string) []sample {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read into memory (capped at 50MB).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil || len(body) == 0 {
		return nil
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil
	}

	var out []sample
	for _, f := range reader.File {
		if f.UncompressedSize64 > maxS3FileSize {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if !scannableExts[ext] {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, maxS3FileSize))
		rc.Close()
		if err != nil || len(content) == 0 {
			continue
		}
		out = append(out, sample{
			Source: "lambda_code/" + fnName + "/" + f.Name, Region: region,
			Content:  string(content),
			Metadata: map[string]string{"arn": fnARN, "function": fnName, "file": f.Name},
		})
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
				invPager := ssm.NewListCommandInvocationsPaginator(cli, &ssm.ListCommandInvocationsInput{
					CommandId: aws.String(cmdID), Details: true,
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
							if len(output) > 50*1024 {
								output = output[:50*1024]
							}
							instID := aws.ToString(inv.InstanceId)
							out = append(out, sample{
								Source: "ssm_output/" + cmdID + "/" + instID, Region: region,
								Content: output,
								Metadata: map[string]string{
									"arn": fmt.Sprintf("arn:aws:ssm:%s:%s:command/%s", region, t.AccountID, cmdID),
									"command_id": cmdID, "instance_id": instID,
									"document": aws.ToString(cmd.DocumentName),
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
				desc, err := cli.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(stackName)})
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
							Content: strings.Join(lines, "\n"),
							Metadata: map[string]string{"arn": stackARN, "stack": stackName},
						})
					}
				}
				tmpl, err := cli.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: aws.String(stackName)})
				if err == nil && tmpl.TemplateBody != nil {
					body := aws.ToString(tmpl.TemplateBody)
					if len(body) < 1024*1024 {
						out = append(out, sample{
							Source: "cfn_template/" + stackName, Region: region,
							Content: body,
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
							"arn": fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiID),
							"api": apiName, "stage": aws.ToString(stage.StageName),
						},
					})
				}
			}
		}
	}
	return out
}

// --- S3 per-bucket scan with cleanup ---

func scanS3PerBucket(ctx context.Context, kfPath string, t creds.AccountTarget, sink findings.Sink) {
	s3Cli := s3.NewFromConfig(t.Config, func(o *s3.Options) {
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	buckets, err := s3Cli.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return
	}
	totalBuckets := len(buckets.Buckets)
	_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
		fmt.Sprintf("S3: scanning %d buckets", totalBuckets))

	for bi, b := range buckets.Buckets {
		bName := aws.ToString(b.Name)
		_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
			fmt.Sprintf("S3: bucket %d/%d: %s", bi+1, totalBuckets, bName))
		loc, err := s3Cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bName)})
		if err != nil {
			continue
		}
		bucketRegion := string(loc.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}
		regionCli := s3.NewFromConfig(t.Config, func(o *s3.Options) {
			o.Region = bucketRegion
			o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		})

		// Create temp dir per bucket, scan, then clean up.
		tmpDir, err := os.MkdirTemp("", "bb-s3-*")
		if err != nil {
			continue
		}

		fileMap := map[string]*sample{}
		fileIdx := 0

		// Paginate all objects, download scannable ones.
		paginator := s3.NewListObjectsV2Paginator(regionCli, &s3.ListObjectsV2Input{Bucket: aws.String(bName)})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				break
			}
			for _, obj := range page.Contents {
				size := aws.ToInt64(obj.Size)
				if size == 0 || size > maxS3FileSize {
					continue
				}
				key := aws.ToString(obj.Key)
				// Skip binary-looking extensions.
				if isBinaryExt(key) {
					continue
				}

				get, err := regionCli.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(bName), Key: aws.String(key),
				})
				if err != nil {
					continue
				}
				body, err := io.ReadAll(io.LimitReader(get.Body, maxS3FileSize))
				get.Body.Close()
				if err != nil || len(body) == 0 {
					continue
				}
				// Skip binary content.
				if isBinaryContent(body) {
					continue
				}

				safe := strings.ReplaceAll(key, "/", "__")
				safe = strings.ReplaceAll(safe, ":", "_")
				fname := fmt.Sprintf("%04d_%s", fileIdx, safe)
				if len(fname) > 200 {
					fname = fmt.Sprintf("%04d_%s", fileIdx, safe[:190])
				}
				fpath := filepath.Join(tmpDir, fname)
				if err := os.WriteFile(fpath, body, 0600); err != nil {
					continue
				}
				s := &sample{
					Source: "s3/" + bName + "/" + key, Region: bucketRegion,
					Content: "", // not needed, file on disk
					Metadata: map[string]string{
						"arn": fmt.Sprintf("arn:aws:s3:::%s/%s", bName, key),
						"bucket": bName, "key": key,
					},
				}
				fileMap[fname] = s
				fileIdx++
			}
		}

		if fileIdx > 0 {
			_ = sink.LogEvent(ctx, "secrets_scan", t.AccountID, "info",
				fmt.Sprintf("S3: scanning %d files from %s with kingfisher", fileIdx, bName))
			kfFindings := runKingfisher(ctx, kfPath, tmpDir, "s3_"+bName, t, sink)
			emitFindings(kfFindings, fileMap, t, sink)
		}

		// Clean up this bucket's temp files.
		os.RemoveAll(tmpDir)
	}
}

// isBinaryExt returns true for file extensions that are definitely not text.
func isBinaryExt(key string) bool {
	ext := strings.ToLower(filepath.Ext(key))
	switch ext {
	case ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
		".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flv", ".wav", ".ogg",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib",
		".whl", ".egg", ".class", ".jar", ".war",
		".bin", ".dat", ".img", ".iso", ".dmg",
		".ttf", ".otf", ".woff", ".woff2", ".eot",
		".parquet", ".avro", ".orc",
		".sqlite", ".db", ".mdb":
		return true
	}
	return false
}

// isBinaryContent checks if the first 512 bytes look like binary data.
func isBinaryContent(data []byte) bool {
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	nullCount := 0
	for _, b := range check {
		if b == 0 {
			nullCount++
		}
	}
	return nullCount > 5
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
				desc, err := cli.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{StateMachineArn: aws.String(smARN)})
				if err != nil {
					continue
				}
				def := aws.ToString(desc.Definition)
				if def == "" {
					continue
				}
				out = append(out, sample{
					Source: "stepfn/" + aws.ToString(sm.Name), Region: region,
					Content: def,
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
				if groupCount > 50 {
					break
				}
				groupName := aws.ToString(g.LogGroupName)
				streams, err := cli.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
					LogGroupName: aws.String(groupName), OrderBy: "LastEventTime",
					Descending: aws.Bool(true), Limit: aws.Int32(1),
				})
				if err != nil || len(streams.LogStreams) == 0 {
					continue
				}
				streamName := aws.ToString(streams.LogStreams[0].LogStreamName)
				events, err := cli.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
					LogGroupName: aws.String(groupName), LogStreamName: aws.String(streamName),
					Limit: aws.Int32(100), StartFromHead: aws.Bool(false),
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
					Metadata: map[string]string{"arn": aws.ToString(g.Arn), "group": groupName, "stream": streamName},
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
					aws.ToString(k.AccessKeyId), string(k.Status), k.CreateDate.Format("2006-01-02")))
			}
			if len(lines) > 0 {
				out = append(out, sample{
					Source: "iam_keys/" + userName, Region: "global",
					Content: strings.Join(lines, "\n"),
					Metadata: map[string]string{"arn": aws.ToString(u.Arn), "user": userName},
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
						Metadata: map[string]string{"arn": fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, t.AccountID, aws.ToString(j.Name)), "name": aws.ToString(j.Name)},
					})
				}
			}
		}
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
						Metadata: map[string]string{"arn": fmt.Sprintf("arn:aws:glue:%s:%s:connection/%s", region, t.AccountID, aws.ToString(c.Name)), "name": aws.ToString(c.Name)},
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
							lines = append(lines, fmt.Sprintf("%s/%s/%s=%s", aws.ToString(stage.Name), aws.ToString(action.Name), k, v))
						}
					}
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "codepipeline/" + pName, Region: region,
						Content: strings.Join(lines, "\n"),
						Metadata: map[string]string{"arn": fmt.Sprintf("arn:aws:codepipeline:%s:%s:%s", region, t.AccountID, pName), "name": pName},
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
				ApplicationName: aws.String(appName), EnvironmentName: aws.String(envName),
			})
			if err != nil {
				continue
			}
			var lines []string
			for _, cs := range settings.ConfigurationSettings {
				for _, opt := range cs.OptionSettings {
					if aws.ToString(opt.Namespace) == "aws:elasticbeanstalk:application:environment" && aws.ToString(opt.Value) != "" {
						lines = append(lines, aws.ToString(opt.OptionName)+"="+aws.ToString(opt.Value))
					}
				}
			}
			if len(lines) > 0 {
				out = append(out, sample{
					Source: "beanstalk/" + envName, Region: region,
					Content: strings.Join(lines, "\n"),
					Metadata: map[string]string{"arn": aws.ToString(env.EnvironmentArn), "env": envName, "app": appName},
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
				Metadata: map[string]string{"arn": fmt.Sprintf("arn:aws:appsync:%s:%s:apis/%s", region, t.AccountID, apiID), "api": apiName},
			})
		}
	}
	return out
}

// --- App Runner ---

func collectAppRunner(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := apprunner.NewFromConfig(t.Config, func(o *apprunner.Options) { o.Region = region })
		var nextToken *string
		for {
			list, err := cli.ListServices(ctx, &apprunner.ListServicesInput{NextToken: nextToken})
			if err != nil {
				break
			}
			for _, svc := range list.ServiceSummaryList {
				svcARN := aws.ToString(svc.ServiceArn)
				desc, err := cli.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: aws.String(svcARN)})
				if err != nil || desc.Service == nil {
					continue
				}
				var lines []string
				if desc.Service.SourceConfiguration != nil &&
					desc.Service.SourceConfiguration.ImageRepository != nil &&
					desc.Service.SourceConfiguration.ImageRepository.ImageConfiguration != nil {
					for k, v := range desc.Service.SourceConfiguration.ImageRepository.ImageConfiguration.RuntimeEnvironmentVariables {
						lines = append(lines, k+"="+v)
					}
				}
				if desc.Service.SourceConfiguration != nil &&
					desc.Service.SourceConfiguration.CodeRepository != nil &&
					desc.Service.SourceConfiguration.CodeRepository.CodeConfiguration != nil &&
					desc.Service.SourceConfiguration.CodeRepository.CodeConfiguration.CodeConfigurationValues != nil {
					for k, v := range desc.Service.SourceConfiguration.CodeRepository.CodeConfiguration.CodeConfigurationValues.RuntimeEnvironmentVariables {
						lines = append(lines, k+"="+v)
					}
				}
				if len(lines) == 0 {
					continue
				}
				out = append(out, sample{
					Source: "apprunner/" + aws.ToString(svc.ServiceName), Region: region,
					Content: strings.Join(lines, "\n"),
					Metadata: map[string]string{"arn": svcARN, "service": aws.ToString(svc.ServiceName)},
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

// --- Lightsail ---
// Lightsail GetInstances does not expose user data on running instances.
func collectLightsail(_ context.Context, _ creds.AccountTarget, _ []string) []sample {
	return nil
}

// --- Redshift Cluster Parameters ---

func collectRedshift(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := redshift.NewFromConfig(t.Config, func(o *redshift.Options) { o.Region = region })
		clusters, err := cli.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
		if err != nil {
			continue
		}
		// Collect unique parameter group names.
		seen := map[string]bool{}
		for _, c := range clusters.Clusters {
			for _, pg := range c.ClusterParameterGroups {
				pgName := aws.ToString(pg.ParameterGroupName)
				if pgName == "" || seen[pgName] {
					continue
				}
				seen[pgName] = true
				pager := redshift.NewDescribeClusterParametersPaginator(cli,
					&redshift.DescribeClusterParametersInput{ParameterGroupName: aws.String(pgName)})
				var lines []string
				for pager.HasMorePages() {
					page, err := pager.NextPage(ctx)
					if err != nil {
						break
					}
					for _, p := range page.Parameters {
						val := aws.ToString(p.ParameterValue)
						if val != "" {
							lines = append(lines, aws.ToString(p.ParameterName)+"="+val)
						}
					}
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "redshift_params/" + pgName, Region: region,
						Content: strings.Join(lines, "\n"),
						Metadata: map[string]string{
							"arn":             fmt.Sprintf("arn:aws:redshift:%s:%s:parametergroup:%s", region, t.AccountID, pgName),
							"parameter_group": pgName,
						},
					})
				}
			}
		}
	}
	return out
}

// --- SageMaker Notebook Lifecycle Configs ---

func collectSageMaker(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := sagemaker.NewFromConfig(t.Config, func(o *sagemaker.Options) { o.Region = region })
		notebooks, err := cli.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{})
		if err != nil {
			continue
		}
		// Collect unique lifecycle config names.
		seen := map[string]bool{}
		for _, nb := range notebooks.NotebookInstances {
			lcName := aws.ToString(nb.NotebookInstanceLifecycleConfigName)
			if lcName == "" || seen[lcName] {
				continue
			}
			seen[lcName] = true
			lc, err := cli.DescribeNotebookInstanceLifecycleConfig(ctx,
				&sagemaker.DescribeNotebookInstanceLifecycleConfigInput{
					NotebookInstanceLifecycleConfigName: aws.String(lcName),
				})
			if err != nil {
				continue
			}
			var lines []string
			for _, s := range lc.OnCreate {
				decoded, err := base64.StdEncoding.DecodeString(aws.ToString(s.Content))
				if err == nil {
					lines = append(lines, "# OnCreate\n"+string(decoded))
				}
			}
			for _, s := range lc.OnStart {
				decoded, err := base64.StdEncoding.DecodeString(aws.ToString(s.Content))
				if err == nil {
					lines = append(lines, "# OnStart\n"+string(decoded))
				}
			}
			if len(lines) > 0 {
				out = append(out, sample{
					Source: "sagemaker_lc/" + lcName, Region: region,
					Content: strings.Join(lines, "\n---\n"),
					Metadata: map[string]string{
						"arn":  aws.ToString(lc.NotebookInstanceLifecycleConfigArn),
						"name": lcName,
					},
				})
			}
		}
	}
	return out
}

// --- EMR Cluster Configurations ---

func collectEMR(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := emr.NewFromConfig(t.Config, func(o *emr.Options) { o.Region = region })
		var marker *string
		for {
			list, err := cli.ListClusters(ctx, &emr.ListClustersInput{Marker: marker})
			if err != nil {
				break
			}
			for _, c := range list.Clusters {
				clusterID := aws.ToString(c.Id)
				desc, err := cli.DescribeCluster(ctx, &emr.DescribeClusterInput{ClusterId: aws.String(clusterID)})
				if err != nil || desc.Cluster == nil {
					continue
				}
				var lines []string
				// Bootstrap actions.
				bsActions, err := cli.ListBootstrapActions(ctx, &emr.ListBootstrapActionsInput{ClusterId: aws.String(clusterID)})
				if err == nil {
					for _, bs := range bsActions.BootstrapActions {
						lines = append(lines, "BOOTSTRAP:"+aws.ToString(bs.Name)+"="+aws.ToString(bs.ScriptPath))
						for _, arg := range bs.Args {
							lines = append(lines, "  ARG="+arg)
						}
					}
				}
				// Configurations.
				if desc.Cluster.Configurations != nil {
					for _, cfg := range desc.Cluster.Configurations {
						for k, v := range cfg.Properties {
							lines = append(lines, "CONFIG:"+aws.ToString(cfg.Classification)+"/"+k+"="+v)
						}
					}
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "emr/" + aws.ToString(c.Name), Region: region,
						Content: strings.Join(lines, "\n"),
						Metadata: map[string]string{
							"arn":     aws.ToString(desc.Cluster.ClusterArn),
							"cluster": aws.ToString(c.Name),
						},
					})
				}
			}
			if list.Marker == nil {
				break
			}
			marker = list.Marker
		}
	}
	return out
}

// --- Amplify ---

func collectAmplify(ctx context.Context, t creds.AccountTarget, regions []string) []sample {
	var out []sample
	for _, region := range regions {
		cli := amplify.NewFromConfig(t.Config, func(o *amplify.Options) { o.Region = region })
		apps, err := cli.ListApps(ctx, &amplify.ListAppsInput{})
		if err != nil {
			continue
		}
		for _, app := range apps.Apps {
			var lines []string
			for k, v := range app.EnvironmentVariables {
				lines = append(lines, k+"="+v)
			}
			// Also check branch-level env vars.
			branches, err := cli.ListBranches(ctx, &amplify.ListBranchesInput{AppId: app.AppId})
			if err == nil {
				for _, br := range branches.Branches {
					for k, v := range br.EnvironmentVariables {
						lines = append(lines, "BRANCH:"+aws.ToString(br.BranchName)+"/"+k+"="+v)
					}
				}
			}
			if len(lines) == 0 {
				continue
			}
			out = append(out, sample{
				Source: "amplify/" + aws.ToString(app.Name), Region: region,
				Content: strings.Join(lines, "\n"),
				Metadata: map[string]string{
					"arn":  aws.ToString(app.AppArn),
					"app":  aws.ToString(app.Name),
				},
			})
		}
	}
	return out
}
