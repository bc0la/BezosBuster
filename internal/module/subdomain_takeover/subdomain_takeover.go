// Package subdomain_takeover scans Route53 hosted zones for records that
// point at AWS or third-party resources which no longer exist and could be
// re-registered by an attacker.
//
// Fingerprint data in fingerprints.json is sourced from
// https://github.com/EdOverflow/can-i-take-over-xyz under CC-BY-4.0.
package subdomain_takeover

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cf "github.com/aws/aws-sdk-go-v2/service/cloudfront"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
)

//go:embed fingerprints.json
var fingerprintsJSON []byte

const (
	probeTimeout = 10 * time.Second
	maxBodyBytes = 64 << 10
)

// anonClient does not follow redirects — the takeover fingerprint is usually
// on the first response, before any CDN-side redirect to a real site.
var anonClient = &http.Client{
	Timeout: probeTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "subdomain_takeover" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"route53:ListHostedZones",
		"route53:ListResourceRecordSets",
		"cloudfront:ListDistributions",
		"elasticloadbalancing:DescribeLoadBalancers",
	}
}

type fingerprint struct {
	Service     string   `json:"service"`
	CNAME       []string `json:"cname"`
	Fingerprint string   `json:"fingerprint"`
	HTTPStatus  *int     `json:"http_status"`
	NXDomain    bool     `json:"nxdomain"`
	Vulnerable  bool     `json:"vulnerable"`
}

func loadFingerprints() []fingerprint {
	var fps []fingerprint
	_ = json.Unmarshal(fingerprintsJSON, &fps)
	return fps
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	fps := loadFingerprints()
	r53 := route53.NewFromConfig(t.Config, func(o *route53.Options) { o.Region = "us-east-1" })

	zones, err := listAllHostedZones(ctx, r53)
	if err != nil {
		return fmt.Errorf("list hosted zones: %w", err)
	}
	_ = sink.LogEvent(ctx, "subdomain_takeover", t.AccountID, "info",
		fmt.Sprintf("scanning %d hosted zones", len(zones)))

	idx := newAliasIndex(t.Config)

	for _, z := range zones {
		zoneName := strings.TrimSuffix(aws.ToString(z.Name), ".")
		records, err := listAllRecords(ctx, r53, aws.ToString(z.Id))
		if err != nil {
			_ = sink.LogEvent(ctx, "subdomain_takeover", t.AccountID, "warn",
				fmt.Sprintf("zone %s: %v", zoneName, err))
			continue
		}
		_ = sink.LogEvent(ctx, "subdomain_takeover", t.AccountID, "info",
			fmt.Sprintf("zone %s: %d records", zoneName, len(records)))
		for _, rec := range records {
			checkRecord(ctx, t, sink, zoneName, rec, fps, idx)
		}
	}
	return nil
}

func listAllHostedZones(ctx context.Context, cli *route53.Client) ([]r53types.HostedZone, error) {
	var out []r53types.HostedZone
	p := route53.NewListHostedZonesPaginator(cli, &route53.ListHostedZonesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.HostedZones...)
	}
	return out, nil
}

func listAllRecords(ctx context.Context, cli *route53.Client, zoneID string) ([]r53types.ResourceRecordSet, error) {
	var out []r53types.ResourceRecordSet
	p := route53.NewListResourceRecordSetsPaginator(cli, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.ResourceRecordSets...)
	}
	return out, nil
}

func checkRecord(
	ctx context.Context,
	t creds.AccountTarget,
	sink findings.Sink,
	zoneName string,
	rec r53types.ResourceRecordSet,
	fps []fingerprint,
	idx *aliasIndex,
) {
	name := strings.TrimSuffix(aws.ToString(rec.Name), ".")

	if rec.AliasTarget != nil {
		target := strings.TrimSuffix(aws.ToString(rec.AliasTarget.DNSName), ".")
		if target == "" {
			return
		}
		result := idx.check(ctx, target)
		if !result.dangling {
			return
		}
		// Cross-account aliases are legal — only fire when we can also
		// observe externally that the resource is unreachable.
		if !confirmDangling(ctx, target, result.service) {
			return
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Module:      "subdomain_takeover",
			Severity:    findings.SevCritical,
			ResourceARN: "arn:aws:route53:::record/" + name,
			Title: fmt.Sprintf("Dangling Route53 alias: %s → %s (%s gone)",
				name, target, result.service),
			Detail: map[string]any{
				"record_name":  name,
				"zone":         zoneName,
				"record_type":  string(rec.Type),
				"alias_target": target,
				"service":      result.service,
				"reason":       result.reason,
			},
		})
		return
	}

	if rec.Type != r53types.RRTypeCname {
		return
	}
	if len(rec.ResourceRecords) == 0 {
		return
	}
	target := strings.TrimSuffix(aws.ToString(rec.ResourceRecords[0].Value), ".")
	if target == "" {
		return
	}

	nx, body, status := probeCNAME(ctx, target)

	if nx {
		if fp, ok := matchNXDomainFingerprint(target, fps); ok && fp.Vulnerable {
			_ = sink.Write(ctx, findings.Finding{
				AccountID:   t.AccountID,
				Module:      "subdomain_takeover",
				Severity:    findings.SevCritical,
				ResourceARN: "arn:aws:route53:::record/" + name,
				Title: fmt.Sprintf("Subdomain takeover (NXDOMAIN): %s → %s [%s]",
					name, target, fp.Service),
				Detail: map[string]any{
					"record_name": name,
					"zone":        zoneName,
					"cname":       target,
					"service":     fp.Service,
					"signal":      "nxdomain",
				},
			})
			return
		}
		if isKnownSafeNX(target, fps) {
			return
		}
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Module:      "subdomain_takeover",
			Severity:    findings.SevHigh,
			ResourceARN: "arn:aws:route53:::record/" + name,
			Title: fmt.Sprintf("Dangling CNAME (NXDOMAIN, unverified): %s → %s",
				name, target),
			Detail: map[string]any{
				"record_name": name,
				"zone":        zoneName,
				"cname":       target,
				"signal":      "nxdomain",
			},
		})
		return
	}

	if fp, ok := matchHTTPFingerprint(target, body, status, fps); ok && fp.Vulnerable {
		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Module:      "subdomain_takeover",
			Severity:    findings.SevCritical,
			ResourceARN: "arn:aws:route53:::record/" + name,
			Title: fmt.Sprintf("Subdomain takeover: %s → %s [%s]",
				name, target, fp.Service),
			Detail: map[string]any{
				"record_name": name,
				"zone":        zoneName,
				"cname":       target,
				"service":     fp.Service,
				"fingerprint": fp.Fingerprint,
				"http_status": status,
				"signal":      "http_body_match",
			},
		})
	}
}

// probeCNAME resolves target and, if it resolves, makes an anonymous HTTP GET.
// Returns nxdomain=true when DNS resolution fails with a not-found error.
func probeCNAME(ctx context.Context, target string) (nxdomain bool, body string, status int) {
	if _, err := net.DefaultResolver.LookupHost(ctx, target); err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true, "", 0
		}
		return false, "", 0
	}
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+"/", nil)
		if err != nil {
			continue
		}
		resp, err := anonClient.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()
		return false, string(b), resp.StatusCode
	}
	return false, "", 0
}

func suffixMatches(host string, patterns []string) bool {
	h := strings.ToLower(host)
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.Contains(h, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func matchNXDomainFingerprint(host string, fps []fingerprint) (fingerprint, bool) {
	for _, fp := range fps {
		if !fp.NXDomain {
			continue
		}
		if suffixMatches(host, fp.CNAME) {
			return fp, true
		}
	}
	return fingerprint{}, false
}

func isKnownSafeNX(host string, fps []fingerprint) bool {
	for _, fp := range fps {
		if fp.NXDomain && !fp.Vulnerable && suffixMatches(host, fp.CNAME) {
			return true
		}
	}
	return false
}

func matchHTTPFingerprint(host, body string, status int, fps []fingerprint) (fingerprint, bool) {
	for _, fp := range fps {
		if fp.NXDomain || fp.Fingerprint == "" {
			continue
		}
		if len(fp.CNAME) > 0 && !suffixMatches(host, fp.CNAME) {
			continue
		}
		if fp.HTTPStatus != nil && status != *fp.HTTPStatus {
			continue
		}
		if strings.Contains(body, fp.Fingerprint) {
			return fp, true
		}
	}
	return fingerprint{}, false
}

// --- alias-target existence ---

type aliasCheckResult struct {
	dangling bool
	service  string
	reason   string
}

type aliasIndex struct {
	cfg aws.Config

	cfOnce    sync.Once
	cfDomains map[string]bool

	elbMu    sync.Mutex
	elbCache map[string]map[string]bool
}

func newAliasIndex(cfg aws.Config) *aliasIndex {
	return &aliasIndex{
		cfg:      cfg,
		elbCache: map[string]map[string]bool{},
	}
}

func (i *aliasIndex) check(ctx context.Context, target string) aliasCheckResult {
	host := strings.ToLower(target)
	switch {
	case strings.HasSuffix(host, ".cloudfront.net"):
		return i.checkCloudFront(ctx, host)
	case strings.Contains(host, ".elb.amazonaws.com"):
		return i.checkELB(ctx, host)
	}
	return aliasCheckResult{}
}

func (i *aliasIndex) checkCloudFront(ctx context.Context, host string) aliasCheckResult {
	i.cfOnce.Do(func() {
		i.cfDomains = map[string]bool{}
		cli := cf.NewFromConfig(i.cfg, func(o *cf.Options) { o.Region = "us-east-1" })
		p := cf.NewListDistributionsPaginator(cli, &cf.ListDistributionsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return
			}
			if page.DistributionList == nil {
				continue
			}
			for _, d := range page.DistributionList.Items {
				if d.DomainName != nil {
					i.cfDomains[strings.ToLower(*d.DomainName)] = true
				}
			}
		}
	})
	if i.cfDomains[host] {
		return aliasCheckResult{}
	}
	return aliasCheckResult{
		dangling: true,
		service:  "CloudFront",
		reason:   "alias target not among account's CloudFront distributions",
	}
}

func (i *aliasIndex) checkELB(ctx context.Context, host string) aliasCheckResult {
	region := parseELBRegion(host)
	if region == "" {
		return aliasCheckResult{}
	}
	i.elbMu.Lock()
	cache, ok := i.elbCache[region]
	if !ok {
		cache = map[string]bool{}
		cli := elbv2.NewFromConfig(i.cfg, func(o *elbv2.Options) { o.Region = region })
		p := elbv2.NewDescribeLoadBalancersPaginator(cli, &elbv2.DescribeLoadBalancersInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				break
			}
			for _, lb := range page.LoadBalancers {
				if lb.DNSName != nil {
					cache[strings.ToLower(*lb.DNSName)] = true
				}
			}
		}
		i.elbCache[region] = cache
	}
	i.elbMu.Unlock()

	if cache[normalizeELBHost(host)] {
		return aliasCheckResult{}
	}
	return aliasCheckResult{
		dangling: true,
		service:  "ELB",
		reason:   "alias target not among account's load balancers in " + region,
	}
}

func parseELBRegion(host string) string {
	idx := strings.Index(host, ".elb.amazonaws.com")
	if idx < 0 {
		return ""
	}
	before := host[:idx]
	j := strings.LastIndex(before, ".")
	if j < 0 {
		return ""
	}
	return before[j+1:]
}

// Route53 aliases for dualstack ELBs prefix the DNS name with "dualstack." —
// DescribeLoadBalancers reports the un-prefixed hostname.
func normalizeELBHost(host string) string {
	return strings.TrimPrefix(host, "dualstack.")
}

// confirmDangling does a low-cost external probe to rule out cross-account
// aliases. NXDOMAIN on the alias target is a strong signal nobody owns it;
// for CloudFront, the canonical "distribution not configured" body counts too.
func confirmDangling(ctx context.Context, target, service string) bool {
	if _, err := net.DefaultResolver.LookupHost(ctx, target); err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true
		}
	}
	if service != "CloudFront" {
		return false
	}
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+"/", nil)
		if err != nil {
			continue
		}
		resp, err := anonClient.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()
		s := string(b)
		if strings.Contains(s, "could not be satisfied") ||
			strings.Contains(s, "Bad Request: ERROR") {
			return true
		}
	}
	return false
}
