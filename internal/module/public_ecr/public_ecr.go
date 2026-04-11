package public_ecr

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "public_ecr" }
func (Module) Kind() module.Kind  { return module.KindNative }
func (Module) Requires() []string { return []string{"ecr-public:DescribeRepositories", "ecr-public:DescribeImages"} }

// ECR Public is only in us-east-1.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	cli := ecrpublic.NewFromConfig(t.Config, func(o *ecrpublic.Options) { o.Region = "us-east-1" })
	repos, err := cli.DescribeRepositories(ctx, &ecrpublic.DescribeRepositoriesInput{})
	if err != nil {
		_ = sink.LogEvent(ctx, "public_ecr", t.AccountID, "warn", err.Error())
		return nil
	}
	for _, r := range repos.Repositories {
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      "us-east-1",
			Module:      "public_ecr",
			Severity:    findings.SevMedium,
			ResourceARN: aws.ToString(r.RepositoryArn),
			Title:       "Public ECR repository: " + aws.ToString(r.RepositoryName),
			Detail: map[string]any{
				"repository":   aws.ToString(r.RepositoryName),
				"uri":          aws.ToString(r.RepositoryUri),
				"created_at":   r.CreatedAt,
				"registry_id":  aws.ToString(r.RegistryId),
			},
		})
	}
	return nil
}
