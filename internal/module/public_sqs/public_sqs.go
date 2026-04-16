package public_sqs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "public_sqs" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"sqs:ListQueues", "sqs:GetQueueAttributes"}
}

type policyDoc struct {
	Statement []policyStmt `json:"Statement"`
}

type policyStmt struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Condition json.RawMessage `json:"Condition"`
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "public_sqs", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

func isAnonymousPrincipal(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	if s == `"*"` {
		return true
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err == nil {
		for _, v := range m {
			vs := strings.TrimSpace(string(v))
			if vs == `"*"` || vs == `["*"]` {
				return true
			}
		}
	}
	return false
}

func hasCondition(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "{}" && s != "null"
}

func asList(raw json.RawMessage) []string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err == nil {
		return ss
	}
	return nil
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := sqs.NewFromConfig(t.Config, func(o *sqs.Options) { o.Region = region })

	var nextToken *string
	for {
		list, err := cli.ListQueues(ctx, &sqs.ListQueuesInput{NextToken: nextToken})
		if err != nil {
			return fmt.Errorf("list queues: %w", err)
		}
		for _, queueURL := range list.QueueUrls {
			attrs, err := cli.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: aws.String(queueURL),
				AttributeNames: []sqstypes.QueueAttributeName{
					sqstypes.QueueAttributeNamePolicy,
					sqstypes.QueueAttributeNameQueueArn,
				},
			})
			if err != nil {
				continue
			}
			policyStr := attrs.Attributes["Policy"]
			queueARN := attrs.Attributes["QueueArn"]
			if policyStr == "" {
				continue
			}

			var doc policyDoc
			if err := json.Unmarshal([]byte(policyStr), &doc); err != nil {
				continue
			}

			for _, st := range doc.Statement {
				if !strings.EqualFold(st.Effect, "Allow") {
					continue
				}
				if !isAnonymousPrincipal(st.Principal) {
					continue
				}

				actions := asList(st.Action)
				cond := hasCondition(st.Condition)

				sev := findings.SevHigh
				if cond {
					sev = findings.SevMedium
				}

				// Extract queue name from URL for display.
				parts := strings.Split(queueURL, "/")
				queueName := parts[len(parts)-1]

				title := fmt.Sprintf("SQS queue %s: public access (%s)", queueName, strings.Join(actions, ", "))
				if cond {
					title += " (conditional)"
				}

				// Build copyable AWS CLI commands.
				var cliCmds []string
				for _, a := range actions {
					switch {
					case strings.Contains(a, "ReceiveMessage") || a == "sqs:*" || a == "SQS:*":
						cliCmds = append(cliCmds,
							fmt.Sprintf("aws sqs receive-message --queue-url '%s' --max-number-of-messages 10 --wait-time-seconds 20 --region %s", queueURL, region))
					case strings.Contains(a, "SendMessage"):
						cliCmds = append(cliCmds,
							fmt.Sprintf("aws sqs send-message --queue-url '%s' --message-body 'test' --region %s", queueURL, region))
					case strings.Contains(a, "GetQueueAttributes"):
						cliCmds = append(cliCmds,
							fmt.Sprintf("aws sqs get-queue-attributes --queue-url '%s' --attribute-names All --region %s", queueURL, region))
					}
				}
				// Always include a receive command for wildcard actions.
				if len(cliCmds) == 0 {
					cliCmds = append(cliCmds,
						fmt.Sprintf("aws sqs receive-message --queue-url '%s' --max-number-of-messages 10 --wait-time-seconds 20 --region %s", queueURL, region))
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_sqs",
					Severity:    sev,
					ResourceARN: queueARN,
					Title:       title,
					Detail: map[string]any{
						"queue_name":    queueName,
						"queue_url":     queueURL,
						"actions":       actions,
						"has_condition": cond,
						"statement":     st,
						"curl":          cliCmds,
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
