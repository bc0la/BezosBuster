package apigw_lambda

import "strings"

// ExecuteAPIARN represents a parsed execute-api ARN of the shape
//
//	arn:aws:execute-api:region:account-id:api-id/stage/METHOD/resource-path
//
// The resource-path may contain additional "/" segments.
type ExecuteAPIARN struct {
	Region    string
	AccountID string
	APIID     string
	Stage     string
	Method    string
	Path      string // the rest of the resource, may contain "/"
}

// ParseExecuteAPIARN parses an execute-api ARN. Returns ok=false on malformed input.
func ParseExecuteAPIARN(arn string) (ExecuteAPIARN, bool) {
	// arn:aws:execute-api:region:acct:api-id/stage/method/path...
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "execute-api" {
		return ExecuteAPIARN{}, false
	}
	resource := parts[5]
	segs := strings.SplitN(resource, "/", 4)
	if len(segs) < 3 {
		return ExecuteAPIARN{}, false
	}
	out := ExecuteAPIARN{
		Region:    parts[3],
		AccountID: parts[4],
		APIID:     segs[0],
		Stage:     segs[1],
		Method:    segs[2],
	}
	if len(segs) == 4 {
		out.Path = segs[3]
	}
	return out, true
}

// WildcardRisk represents a pattern where a `*` segment can consume additional
// "/" characters and thus match paths the author didn't intend.
type WildcardRisk struct {
	Pattern      string
	Segment      string // the wildcard segment (e.g. "*" or "admin*")
	SegmentIndex int
	Example      string // a concrete string that matches the pattern but is almost certainly unintended
	Explanation  string
}

// AnalyzePattern inspects an execute-api ARN pattern and returns any wildcard
// segments that can cross a "/" boundary.
//
// IAM wildcards are NOT path-aware: `*` in an IAM resource string matches any
// sequence of characters including "/". So any segment that contains `*` is a
// potential crossing risk — but the risk is only meaningful if there are
// further segments after it (otherwise `*` already legitimately matches the
// tail).
func AnalyzePattern(arnPattern string) []WildcardRisk {
	parts := strings.SplitN(arnPattern, ":", 6)
	if len(parts) < 6 {
		return nil
	}
	resource := parts[5]
	segs := strings.Split(resource, "/")
	var risks []WildcardRisk
	for i, seg := range segs {
		if !strings.Contains(seg, "*") {
			continue
		}
		if i == len(segs)-1 {
			// trailing wildcard — typical and usually intended
			continue
		}
		// Build a bypass example: replace the wildcard segment with one that
		// contains a "/" crossing into something dangerous.
		ex := append([]string(nil), segs...)
		// e.g. segment "*" -> "GET/admin" so the next literal becomes part of
		// an unexpected path.
		if seg == "*" {
			ex[i] = "GET/admin"
		} else {
			// replace the trailing * with "x/admin"
			ex[i] = strings.ReplaceAll(seg, "*", "x/admin")
		}
		example := strings.Join(parts[:5], ":") + ":" + strings.Join(ex, "/")
		risks = append(risks, WildcardRisk{
			Pattern:      arnPattern,
			Segment:      seg,
			SegmentIndex: i,
			Example:      example,
			Explanation:  "IAM `*` is not path-aware and crosses `/` boundaries. A wildcard in a non-terminal segment can consume additional `/`-separated segments, reaching routes the author did not intend to expose.",
		})
	}
	return risks
}
