package codebuild_env

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "codebuild_env" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"codebuild:ListProjects", "codebuild:BatchGetProjects"}
}

var secretKeys = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"aws_access_key", "aws_secret", "credential", "private_key",
	"auth", "database_url", "connection_string", "jdbc",
}

func looksLikeSecret(key string) bool {
	k := strings.ToLower(key)
	for _, s := range secretKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "codebuild_env", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := codebuild.NewFromConfig(t.Config, func(o *codebuild.Options) { o.Region = region })

	var nextToken *string
	for {
		list, err := cli.ListProjects(ctx, &codebuild.ListProjectsInput{NextToken: nextToken})
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}
		if len(list.Projects) == 0 {
			break
		}

		// BatchGetProjects accepts up to 100 names.
		for i := 0; i < len(list.Projects); i += 100 {
			end := i + 100
			if end > len(list.Projects) {
				end = len(list.Projects)
			}
			batch, err := cli.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
				Names: list.Projects[i:end],
			})
			if err != nil {
				_ = sink.LogEvent(ctx, "codebuild_env", t.AccountID, "warn", region+": batch get: "+err.Error())
				continue
			}
			for _, proj := range batch.Projects {
				if proj.Environment == nil || len(proj.Environment.EnvironmentVariables) == 0 {
					continue
				}
				projName := aws.ToString(proj.Name)
				projARN := aws.ToString(proj.Arn)

				var plaintext []map[string]string
				var secretHits []string
				for _, ev := range proj.Environment.EnvironmentVariables {
					name := aws.ToString(ev.Name)
					val := aws.ToString(ev.Value)
					evType := string(ev.Type)
					if ev.Type == "" {
						evType = string(cbtypes.EnvironmentVariableTypePlaintext)
					}

					if ev.Type == cbtypes.EnvironmentVariableTypePlaintext {
						plaintext = append(plaintext, map[string]string{
							"name":  name,
							"value": val,
							"type":  evType,
						})
						if looksLikeSecret(name) {
							secretHits = append(secretHits, name)
						}
					}
				}

				if len(plaintext) == 0 {
					continue
				}

				sev := findings.SevInfo
				title := "CodeBuild " + projName + ": plaintext env vars"
				if len(secretHits) > 0 {
					sev = findings.SevHigh
					title += " — potential secrets: " + strings.Join(secretHits, ", ")
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "codebuild_env",
					Severity:    sev,
					ResourceARN: projARN,
					Title:       title,
					Detail: map[string]any{
						"project":          projName,
						"plaintext_vars":   plaintext,
						"secret_matches":   secretHits,
						"service_role":     aws.ToString(proj.ServiceRole),
						"source_type":      string(proj.Source.Type),
						"source_location":  aws.ToString(proj.Source.Location),
					},
				})
			}
		}

		if list.NextToken == nil {
			break
		}
		nextToken = list.NextToken
	}
	return nil
}
