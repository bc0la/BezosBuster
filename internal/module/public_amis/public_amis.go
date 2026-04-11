package public_amis

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "public_amis" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"ec2:DescribeImages", "ec2:DescribeRegions"}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := ec2.NewFromConfig(t.Config, func(o *ec2.Options) { o.Region = region })
		// Only images owned by this account that are executable by "all".
		out, err := cli.DescribeImages(ctx, &ec2.DescribeImagesInput{
			Owners:          []string{"self"},
			ExecutableUsers: []string{"all"},
		})
		if err != nil {
			_ = sink.LogEvent(ctx, "public_amis", t.AccountID, "warn", region+": "+err.Error())
			continue
		}
		for _, img := range out.Images {
			f := findings.Finding{
				AccountID:   t.AccountID,
				Region:      region,
				Module:      "public_amis",
				Severity:    findings.SevHigh,
				ResourceARN: "arn:aws:ec2:" + region + ":" + t.AccountID + ":image/" + aws.ToString(img.ImageId),
				Title:       "Public AMI: " + aws.ToString(img.Name),
				Detail: map[string]any{
					"image_id":     aws.ToString(img.ImageId),
					"name":         aws.ToString(img.Name),
					"description":  aws.ToString(img.Description),
					"creation":     aws.ToString(img.CreationDate),
					"architecture": string(img.Architecture),
					"public":       img.Public,
				},
			}
			if err := sink.Write(ctx, f); err != nil {
				return err
			}
		}
	}
	return nil
}
