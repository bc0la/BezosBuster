package public_sns

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "public_sns" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"sns:ListTopics", "sns:GetTopicAttributes", "sns:ListSubscriptionsByTopic"}
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

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "public_sns", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := sns.NewFromConfig(t.Config, func(o *sns.Options) { o.Region = region })

	var nextToken *string
	for {
		list, err := cli.ListTopics(ctx, &sns.ListTopicsInput{NextToken: nextToken})
		if err != nil {
			return fmt.Errorf("list topics: %w", err)
		}
		for _, topic := range list.Topics {
			topicARN := aws.ToString(topic.TopicArn)

			attrs, err := cli.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: aws.String(topicARN),
			})
			if err != nil {
				continue
			}
			policyStr := attrs.Attributes["Policy"]
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

				// Extract topic name from ARN.
				topicName := topicARN
				if idx := strings.LastIndex(topicARN, ":"); idx >= 0 {
					topicName = topicARN[idx+1:]
				}

				title := fmt.Sprintf("SNS topic %s: public access (%s)", topicName, strings.Join(actions, ", "))
				if cond {
					title += " (conditional)"
				}

				// List existing subscriptions.
				var subs []map[string]string
				subList, err := cli.ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{
					TopicArn: aws.String(topicARN),
				})
				if err == nil {
					for _, sub := range subList.Subscriptions {
						subs = append(subs, map[string]string{
							"protocol":     aws.ToString(sub.Protocol),
							"endpoint":     aws.ToString(sub.Endpoint),
							"subscription": aws.ToString(sub.SubscriptionArn),
						})
					}
				}

				// Build copyable AWS CLI commands.
				var cliCmds []string
				for _, a := range actions {
					switch {
					case strings.Contains(a, "Subscribe") || a == "sns:*" || a == "SNS:*":
						cliCmds = append(cliCmds,
							fmt.Sprintf("aws sns subscribe --topic-arn '%s' --protocol email --notification-endpoint 'your@email.com' --region %s", topicARN, region))
						cliCmds = append(cliCmds,
							fmt.Sprintf("aws sns subscribe --topic-arn '%s' --protocol https --notification-endpoint 'https://your-webhook.example.com' --region %s", topicARN, region))
					case strings.Contains(a, "Publish"):
						cliCmds = append(cliCmds,
							fmt.Sprintf("aws sns publish --topic-arn '%s' --message 'test' --region %s", topicARN, region))
					case strings.Contains(a, "GetTopicAttributes"):
						cliCmds = append(cliCmds,
							fmt.Sprintf("aws sns get-topic-attributes --topic-arn '%s' --region %s", topicARN, region))
					}
				}
				if len(cliCmds) == 0 {
					cliCmds = append(cliCmds,
						fmt.Sprintf("aws sns subscribe --topic-arn '%s' --protocol email --notification-endpoint 'your@email.com' --region %s", topicARN, region))
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_sns",
					Severity:    sev,
					ResourceARN: topicARN,
					Title:       title,
					Detail: map[string]any{
						"topic_name":     topicName,
						"topic_arn":      topicARN,
						"actions":        actions,
						"has_condition":  cond,
						"subscriptions":  subs,
						"statement":      st,
						"curl":           cliCmds,
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
