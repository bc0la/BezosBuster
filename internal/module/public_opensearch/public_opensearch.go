// Package public_opensearch flags Amazon OpenSearch Service / Elasticsearch
// domains that are reachable from the internet with a permissive access
// policy. AWS exposes public domains at `search-<name>-<rand>.<region>.
// es.amazonaws.com` and VPC-only domains at `vpc-...`; a domain with a public
// endpoint whose resource policy allows an anonymous principal ("*") lets
// anyone reach the cluster's HTTP API (read/search, and often write).
package public_opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"

	"github.com/bc0la/BezosBuster/internal/awsapi"
	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "public_opensearch" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"es:ListDomainNames", "es:DescribeDomains"}
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		cli := opensearch.NewFromConfig(t.Config, func(o *opensearch.Options) { o.Region = region })

		names, err := cli.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
		if err != nil {
			_ = sink.LogEvent(ctx, "public_opensearch", t.AccountID, "warn", region+": "+err.Error())
			continue
		}
		var domainNames []string
		for _, d := range names.DomainNames {
			domainNames = append(domainNames, aws.ToString(d.DomainName))
		}
		// DescribeDomains accepts at most 5 domain names per call.
		for i := 0; i < len(domainNames); i += 5 {
			end := i + 5
			if end > len(domainNames) {
				end = len(domainNames)
			}
			desc, err := cli.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{
				DomainNames: domainNames[i:end],
			})
			if err != nil {
				_ = sink.LogEvent(ctx, "public_opensearch", t.AccountID, "warn", region+": "+err.Error())
				continue
			}
			for _, d := range desc.DomainStatusList {
				anon, conditioned := policyAllowsAnon(aws.ToString(d.AccessPolicies))
				if !anon {
					continue
				}
				// VPCOptions present => the domain has no public endpoint.
				vpcOnly := d.VPCOptions != nil && aws.ToString(d.VPCOptions.VPCId) != ""
				endpoint := aws.ToString(d.Endpoint)
				if endpoint == "" {
					for _, ep := range d.Endpoints {
						endpoint = ep
						break
					}
				}

				sev := findings.SevCritical
				reason := "access policy allows anonymous principal (\"*\") on a public endpoint — reachable by anyone on the internet"
				switch {
				case vpcOnly:
					sev = findings.SevMedium
					reason = "access policy allows anonymous principal (\"*\") but the domain is VPC-only — open to anyone with VPC network reach"
				case conditioned:
					sev = findings.SevHigh
					reason = "access policy allows anonymous principal (\"*\") on a public endpoint, gated by a Condition (e.g. source-IP) — verify the allow-list is tight"
				}

				detail := map[string]any{
					"domain":                 aws.ToString(d.DomainName),
					"endpoint":               endpoint,
					"vpc_only":               vpcOnly,
					"anonymous_principal":    true,
					"condition_restricted":   conditioned,
					"engine_version":         aws.ToString(d.EngineVersion),
					"encryption_at_rest":     d.EncryptionAtRestOptions != nil && aws.ToBool(d.EncryptionAtRestOptions.Enabled),
					"node_to_node_encrypted": d.NodeToNodeEncryptionOptions != nil && aws.ToBool(d.NodeToNodeEncryptionOptions.Enabled),
					"access_policy":          aws.ToString(d.AccessPolicies),
				}
				if endpoint != "" && !vpcOnly {
					detail["curl"] = fmt.Sprintf("curl -s 'https://%s/_cat/indices?v'", endpoint)
				}

				_ = sink.Write(ctx, findings.Finding{
					AccountID:   t.AccountID,
					Region:      region,
					Module:      "public_opensearch",
					Severity:    sev,
					ResourceARN: aws.ToString(d.ARN),
					Title:       "Public OpenSearch domain " + aws.ToString(d.DomainName) + " — " + reason,
					Detail:      detail,
				})
			}
		}
	}
	return nil
}

// policyAllowsAnon parses an OpenSearch access policy and reports whether any
// Allow statement grants an anonymous principal ("*"), and whether that
// statement carries a Condition (which may narrow the exposure).
func policyAllowsAnon(doc string) (anon bool, conditioned bool) {
	if strings.TrimSpace(doc) == "" {
		return false, false
	}
	if dec, err := url.QueryUnescape(doc); err == nil {
		doc = dec
	}
	var p struct {
		Statement []struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Condition json.RawMessage `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return false, false
	}
	for _, st := range p.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if !principalIsAnon(st.Principal) {
			continue
		}
		anon = true
		if len(st.Condition) > 0 && strings.TrimSpace(string(st.Condition)) != "{}" {
			conditioned = true
		} else {
			// A single unconditioned anonymous Allow is the worst case; stop
			// looking so we don't let a later conditioned one mask it.
			return true, false
		}
	}
	return anon, conditioned
}

func principalIsAnon(raw json.RawMessage) bool {
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
