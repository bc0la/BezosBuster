package module

// moduleRating is the realistic worst-case severity a module can produce — its
// "potential severity", independent of what any given engagement actually
// finds. The report UI stamps this onto every section/module/check filter so an
// analyst can triage which filters are worth looking at first.
//
// Ratings are deliberately conservative-realistic, not theoretical-maximum:
//   - critical: a single finding here is typically a direct breach or full
//     account compromise (anonymous data access, internet-reachable database,
//     live credentials, internet-assumable admin role).
//   - high: serious exposure that usually needs one more step (valid creds, a
//     restore, an SSRF) or leaks sensitive material.
//   - medium: real weakness, but impact is bounded or commonly non-sensitive.
//   - low/info: hygiene / informational.
var moduleRating = map[string]string{
	// --- critical: direct breach / full compromise ---
	"s3_anon":           "critical", // anonymous bucket listing / public objects = data breach
	"public_rds":        "critical", // internet-reachable DB (TCP-confirmed) → weak-cred data theft
	"public_opensearch": "critical", // wildcard access policy = anonymous index read/write
	"secrets_scan":      "critical", // live credentials in code/config/logs = full compromise
	"iam_integrations":  "critical", // wildcard trust / OIDC no-sub = internet role takeover
	"bluecloudpeass":    "critical", // AWSPEAS surfaces privilege-escalation paths to admin

	// --- high: serious exposure, usually one step from breach ---
	"apigw_lambda":        "high", // anonymous API reach / no-auth function URLs
	"ecr_repo_policy":     "high", // private images pullable by anyone (source/secret leak)
	"public_amis":         "high", // public AMI may embed secrets / baked snapshots
	"public_snapshots":    "high", // public EBS/RDS snapshot = restorable full disk/DB copy
	"public_redshift":     "high", // internet-reachable data warehouse
	"public_documentdb":   "high", // internet-reachable document DB
	"public_neptune":      "high", // internet-reachable graph DB
	"public_mq":           "high", // exposed message broker
	"public_msk":          "high", // exposed Kafka brokers
	"kms_key_exposure":    "high", // key policy grants "*"/external principal
	"subdomain_takeover":  "high", // dangling Route53 record → takeover/phishing
	"lambda_env":          "high", // secrets in Lambda env vars
	"ec2_userdata":        "high", // secrets in EC2 user data
	"codebuild_env":       "high", // plaintext secrets in build env
	"ecs_ecr_taskdefs":    "high", // secrets in ECS task definitions
	"cognito":             "high", // anonymous identity pool / weak auth config
	"scoutsuite":          "high", // broad benchmark; can surface critical posture issues
	"steampipe_perimeter": "high", // perimeter-exposure benchmark

	// --- medium: real weakness, bounded/commonly non-sensitive impact ---
	"public_ecr":   "medium", // ECR Public gallery repos (public by design; image leak)
	"public_sns":   "medium", // public topic subscribe/publish
	"public_sqs":   "medium", // public queue read/send
	"ssm_commands": "medium", // secrets in Run Command output history
	"ec2_imdsv1":   "medium", // IMDSv1 enabled (SSRF → cred theft prerequisite)
	"bedrock":      "medium", // Bedrock guardrail/model-access misconfig
}

// RatingOf returns the potential-severity rating for a module, defaulting to
// "medium" for any module not explicitly rated (so a new module surfaces with
// a visible, non-alarming default rather than nothing).
func RatingOf(name string) string {
	if r, ok := moduleRating[name]; ok {
		return r
	}
	return "medium"
}
