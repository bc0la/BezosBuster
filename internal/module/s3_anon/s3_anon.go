package s3_anon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "s3_anon" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketLocation",
		"s3:GetBucketPolicy",
		"s3:GetBucketPolicyStatus",
		"s3:GetPublicAccessBlock",
		"s3:GetBucketAcl",
		"s3:ListBucket",
	}
}

const (
	maxDepth         = 3
	objectsPerFolder = 10
	probeTimeout     = 10 * time.Second
)

var anonClient = &http.Client{Timeout: probeTimeout}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	// ListBuckets is global; pin to us-east-1.
	s3Cli := s3.NewFromConfig(t.Config, func(o *s3.Options) { o.Region = "us-east-1" })
	out, err := s3Cli.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("list buckets: %w", err)
	}
	total := len(out.Buckets)
	_ = sink.LogEvent(ctx, "s3_anon", t.AccountID, "info",
		fmt.Sprintf("scanning %d buckets", total))

	for i, b := range out.Buckets {
		bName := aws.ToString(b.Name)
		_ = sink.LogEvent(ctx, "s3_anon", t.AccountID, "info",
			fmt.Sprintf("bucket %d/%d: %s", i+1, total, bName))

		region, err := bucketRegion(ctx, s3Cli, bName)
		if err != nil {
			continue
		}
		regCli := s3.NewFromConfig(t.Config, func(o *s3.Options) { o.Region = region })

		exposure := assessExposure(ctx, regCli, bName)
		if !exposure.looksPublic() {
			continue
		}

		_ = sink.LogEvent(ctx, "s3_anon", t.AccountID, "info",
			fmt.Sprintf("%s: %s — probing objects", bName, exposure.reason))

		candidates := walkBucket(ctx, regCli, bName)
		var hits []anonHit
		for _, key := range candidates {
			if h, ok := probeAnon(ctx, bName, region, key); ok {
				hits = append(hits, h)
			}
		}
		if len(hits) == 0 {
			continue
		}

		curls := make([]string, 0, len(hits))
		objs := make([]map[string]any, 0, len(hits))
		for _, h := range hits {
			curls = append(curls, h.curl)
			objs = append(objs, map[string]any{
				"key":          h.key,
				"url":          h.url,
				"status":       h.status,
				"content_type": h.contentType,
				"size_hint":    h.sizeHint,
			})
		}

		sev := findings.SevHigh
		if exposure.policyStatusPublic || exposure.policyAnon {
			sev = findings.SevCritical
		}

		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      region,
			Module:      "s3_anon",
			Severity:    sev,
			ResourceARN: "arn:aws:s3:::" + bName,
			Title: fmt.Sprintf("S3 bucket %s: %d anonymously-readable object(s)",
				bName, len(hits)),
			Detail: map[string]any{
				"bucket":               bName,
				"region":               region,
				"exposure":             exposure.reason,
				"public_access_block":  exposure.pab,
				"policy_status_public": exposure.policyStatusPublic,
				"policy_anon_get":      exposure.policyAnon,
				"acl_public":           exposure.aclPublic,
				"objects_probed":       len(candidates),
				"objects_public":       objs,
				"curl":                 curls,
				"walk_limits": map[string]int{
					"max_depth":          maxDepth,
					"objects_per_folder": objectsPerFolder,
				},
			},
		})
	}
	return nil
}

// --- exposure assessment ---

type exposureInfo struct {
	reason             string
	pab                map[string]bool
	policyStatusPublic bool
	policyAnon         bool
	aclPublic          bool
}

func (e exposureInfo) looksPublic() bool { return e.reason != "" }

func assessExposure(ctx context.Context, cli *s3.Client, bucket string) exposureInfo {
	var e exposureInfo

	// PublicAccessBlock — if all 4 flags are set, S3 short-circuits public
	// access at every layer below, so further checks are moot.
	pab, err := cli.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})
	if err == nil && pab.PublicAccessBlockConfiguration != nil {
		c := pab.PublicAccessBlockConfiguration
		e.pab = map[string]bool{
			"BlockPublicAcls":       aws.ToBool(c.BlockPublicAcls),
			"IgnorePublicAcls":      aws.ToBool(c.IgnorePublicAcls),
			"BlockPublicPolicy":     aws.ToBool(c.BlockPublicPolicy),
			"RestrictPublicBuckets": aws.ToBool(c.RestrictPublicBuckets),
		}
		if e.pab["BlockPublicAcls"] && e.pab["IgnorePublicAcls"] &&
			e.pab["BlockPublicPolicy"] && e.pab["RestrictPublicBuckets"] {
			return e
		}
	}

	if ps, err := cli.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
		Bucket: aws.String(bucket),
	}); err == nil && ps.PolicyStatus != nil {
		if aws.ToBool(ps.PolicyStatus.IsPublic) {
			e.policyStatusPublic = true
		}
	}

	if pol, err := cli.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket),
	}); err == nil && pol.Policy != nil {
		if policyHasAnonGet(aws.ToString(pol.Policy)) {
			e.policyAnon = true
		}
	} else if !isExpectedMissing(err) && err != nil {
		_ = err
	}

	if acl, err := cli.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucket),
	}); err == nil {
		for _, g := range acl.Grants {
			if g.Grantee == nil || g.Grantee.Type != s3types.TypeGroup {
				continue
			}
			uri := aws.ToString(g.Grantee.URI)
			if uri != "http://acs.amazonaws.com/groups/global/AllUsers" {
				continue
			}
			if g.Permission == s3types.PermissionRead || g.Permission == s3types.PermissionFullControl {
				e.aclPublic = true
			}
		}
	}

	switch {
	case e.policyStatusPublic || e.policyAnon:
		e.reason = "wide-open policy"
	case e.aclPublic:
		e.reason = "AllUsers ACL grant"
	}
	return e
}

func policyHasAnonGet(doc string) bool {
	var p struct {
		Statement []struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Action    json.RawMessage `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return false
	}
	for _, st := range p.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if !principalAnon(st.Principal) {
			continue
		}
		if actionAllowsGet(st.Action) {
			return true
		}
	}
	return false
}

func principalAnon(raw json.RawMessage) bool {
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

func actionAllowsGet(raw json.RawMessage) bool {
	for _, a := range asActions(raw) {
		a = strings.ToLower(a)
		if a == "*" || a == "s3:*" || a == "s3:get*" || a == "s3:getobject" {
			return true
		}
	}
	return false
}

func asActions(raw json.RawMessage) []string {
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

func isExpectedMissing(err error) bool {
	if err == nil {
		return true
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration":
			return true
		}
	}
	return false
}

func bucketRegion(ctx context.Context, cli *s3.Client, bucket string) (string, error) {
	loc, err := cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return "", err
	}
	r := string(loc.LocationConstraint)
	if r == "" {
		return "us-east-1", nil
	}
	return r, nil
}

// --- bucket walking ---

func walkBucket(ctx context.Context, cli *s3.Client, bucket string) []string {
	var keys []string
	walkPrefix(ctx, cli, bucket, "", 0, &keys)
	return keys
}

func walkPrefix(ctx context.Context, cli *s3.Client, bucket, prefix string, depth int, out *[]string) {
	if depth > maxDepth {
		return
	}
	page, err := cli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
		// Pull a few extra so "folder placeholder" keys don't starve us.
		MaxKeys: aws.Int32(int32(objectsPerFolder + 50)),
	})
	if err != nil {
		return
	}
	picked := 0
	for _, obj := range page.Contents {
		key := aws.ToString(obj.Key)
		if strings.HasSuffix(key, "/") && aws.ToInt64(obj.Size) == 0 {
			continue
		}
		*out = append(*out, key)
		picked++
		if picked >= objectsPerFolder {
			break
		}
	}
	for _, cp := range page.CommonPrefixes {
		walkPrefix(ctx, cli, bucket, aws.ToString(cp.Prefix), depth+1, out)
	}
}

// --- anonymous validation ---

type anonHit struct {
	key         string
	url         string
	status      int
	contentType string
	sizeHint    string
	curl        string
}

func probeAnon(ctx context.Context, bucket, region, key string) (anonHit, bool) {
	u := s3ObjectURL(bucket, region, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return anonHit{}, false
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := anonClient.Do(req)
	if err != nil {
		return anonHit{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return anonHit{}, false
	}
	size := resp.Header.Get("Content-Range")
	if size == "" {
		size = resp.Header.Get("Content-Length")
	}
	return anonHit{
		key:         key,
		url:         u,
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		sizeHint:    size,
		curl:        fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' '%s'", u),
	}, true
}

func s3ObjectURL(bucket, region, key string) string {
	enc := encodeKey(key)
	// Virtual-hosted style is the natural attacker URL, but bucket names
	// with dots break TLS hostname matching — fall back to path-style.
	if strings.Contains(bucket, ".") {
		return fmt.Sprintf("https://s3.%s.amazonaws.com/%s/%s", region, bucket, enc)
	}
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, region, enc)
}

func encodeKey(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}
