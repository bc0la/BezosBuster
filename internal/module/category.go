package module

// Category groups modules into the top-level sections shown in the report UI.
// It is the single source of truth for that grouping: the report server reads
// it via CategoryOf/Categories so a module can never appear in the nav without
// a home. Adding a module without adding it to moduleCategory below drops it
// into the "other" bucket (surfaced in the UI), which is the loud-failure we
// want rather than a silently missing tab.
type Category struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// categoryOrder is the display order of sections in the report nav.
var categoryOrder = []Category{
	{Key: "best_practices", Label: "Best Practices"},
	{Key: "secrets", Label: "Secrets Management"},
	{Key: "iam", Label: "IAM & Access"},
	{Key: "exposure", Label: "Public Exposure"},
}

// moduleCategory maps each registered module's Name() to a category key.
var moduleCategory = map[string]string{
	// Best Practices / posture — benchmark scanners and config hygiene.
	"scoutsuite":          "best_practices",
	"steampipe_perimeter": "best_practices",
	"ec2_imdsv1":          "best_practices",
	"bedrock":             "best_practices",

	// Secrets management — exposed credentials/secrets.
	"secrets_scan":     "secrets",
	"lambda_env":       "secrets",
	"codebuild_env":    "secrets",
	"ec2_userdata":     "secrets",
	"ecs_ecr_taskdefs": "secrets",
	"ssm_commands":     "secrets",

	// IAM & access — overly-permissive trust, privilege escalation, identity.
	"iam_integrations": "iam",
	"bluecloudpeass":   "iam",
	"cognito":          "iam",
	"pacu_cognito":     "iam",

	// Public exposure / attack surface.
	"s3_anon":            "exposure",
	"public_rds":         "exposure",
	"public_redshift":    "exposure",
	"public_opensearch":  "exposure",
	"public_ecr":         "exposure",
	"public_amis":        "exposure",
	"public_snapshots":   "exposure",
	"public_sns":         "exposure",
	"public_sqs":         "exposure",
	"apigw_lambda":       "exposure",
	"subdomain_takeover": "exposure",
}

// CategoryOf returns the category key for a module name, or "other" if the
// module has not been assigned one.
func CategoryOf(name string) string {
	if c, ok := moduleCategory[name]; ok {
		return c
	}
	return "other"
}

// Categories returns the ordered list of sections for the report nav.
func Categories() []Category {
	return append([]Category(nil), categoryOrder...)
}
