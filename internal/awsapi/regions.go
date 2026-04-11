package awsapi

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EnabledRegions returns the list of regions enabled for the account backing cfg.
// Falls back to a sensible commercial-region default if DescribeRegions fails.
func EnabledRegions(ctx context.Context, cfg aws.Config) []string {
	client := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.Region = "us-east-1"
	})
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil || len(out.Regions) == 0 {
		return []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"}
	}
	var regions []string
	for _, r := range out.Regions {
		if r.OptInStatus != nil && *r.OptInStatus == "not-opted-in" {
			continue
		}
		regions = append(regions, aws.ToString(r.RegionName))
	}
	return regions
}

// unused-import guard
var _ ec2types.Region
