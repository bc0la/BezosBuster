# BezosBuster

Automated AWS whitebox pentest workflow. A single static Go binary (with an optional batteries-included Docker image for the heavier external tools) that drives ScoutSuite / Blue-CloudPEASS / Steampipe mods plus a set of native follow-up checks in parallel across one or many AWS accounts, writes findings into a per-engagement SQLite DB for the web report, and stashes raw tool output into per-module/per-account subdirectories so you can read it directly.

## Why

Whitebox AWS engagements repeat the same toolchain and follow-ups every time. Credentials are usually short-lived (8h SSO) and you sometimes have Organizations access across many accounts. BezosBuster removes the manual orchestration, survives token expiry mid-scan, and produces one artifact per engagement you can diff between runs.

## Features

- **Auto-detects credential mode** — single profile, profile list, or Organizations (enumerate accounts + assume role). Works in every environment.
- **SSO expiry handling** — scheduler detects `ExpiredToken` errors, warns, and a `resume` subcommand picks up where it left off.
- **Parallel orchestration** — per-account + global semaphores; failing modules never abort the run.
- **`scan` / `collect` split** — `scan` runs native `aws-sdk-go-v2` checks (fast, in-process); `collect` runs external tools (slow, subprocess). Same flags, same engagement dir.
- **Wraps existing tools**: ScoutSuite, Blue-CloudPEASS, `steampipe-mod-aws-insights`, `steampipe-mod-aws-perimeter`.
- **Native follow-up checks** via `aws-sdk-go-v2`:
  - **Public-exposure family**: public AMIs; public EBS **and RDS** snapshots; publicly-accessible RDS, Redshift, DocumentDB, Neptune (all TCP-probed); public ECR gallery repos **and private ECR repos with a wildcard/external repository policy**; public SNS/SQS; anonymously-readable S3; OpenSearch/Elasticsearch domains with wildcard access policies; Amazon MQ brokers and MSK (Kafka) clusters with public access; KMS keys whose key policy grants `*`/external-account access.
  - Lambda environment variables (all functions, secret-like key/value regex).
  - ECS / ECR task definitions.
  - Roles with `AssumeRoleWithWebIdentity` and their trust policies/conditions.
  - **API Gateway / Lambda anonymous-reach analyzer**, including the wildcard-bypass logic (a rule like `arn:aws:execute-api:...:api-id/prod/*/dashboard/*` matching `prod/GET/admin/dashboard/createAdmin`).
  - **IAM integrations / federation review** — SAML + OIDC providers, role trust policies, **deep GitHub Actions `:sub` claim analysis** (catches `repo:*` wildcards, org-wide subjects, wildcard owners, missing `:aud`, pull-request subjects), Cognito identity pools with anonymous access, wildcard principals.
- **Engagement directory per run** — `engagements/<ts>-<acct>/` holds `engagement.db` (normalized findings, powers the report) plus per-tool subdirs (`scoutsuite/<acct>/report.html`, `steampipe_insights/<acct>/results.json`, `bluecloudpeass/<acct>/results.json`, …) readable straight off the host mount.
- **Bubble Tea TUI** — tabs for accounts, modules, logs, live progress.
- **Local web report** — `bezosbuster report <dir>` serves a tabbed offline dashboard with deep-links to each tool's raw output via `/raw/...`.
- **Multi-account Steampipe dashboard** — `bezosbuster steampipe` generates one Steampipe `aws` connection per detected account plus an `aws_bb_all` aggregator, then launches the dashboard for live queries across every account.

## Install

BezosBuster ships two ways. The **binary** is the daily driver — it's a single
static, CGO-free file (SQLite via `modernc.org/sqlite`, no cgo) and needs no
Docker flags. The **Docker image** is the batteries-included option that bundles
the external tools the heavier commands shell out to.

| Command | Binary | Docker |
|---|---|---|
| `scan` (native checks) | ✅ works standalone | ✅ |
| `report` / `resume` / `modules` | ✅ works standalone | ✅ |
| `secrets_scan` (runs inside `scan`) | needs `kingfisher` on PATH, else skips with a warning | ✅ baked in |
| `collect` (ScoutSuite / Blue-CloudPEASS / Steampipe mods) | needs each tool on PATH, else skips | ✅ baked in |
| `steampipe` (dashboard) | needs `steampipe` + AWS plugin on PATH | ✅ baked in |

### Binary (recommended for scan/report)

```bash
# Download the release for your platform from GitHub Releases, e.g.
tar -xzf bezosbuster_*_linux_amd64.tar.gz
sudo install bezosbuster /usr/local/bin/

# or install the latest tagged release straight from source (Go 1.25+):
go install github.com/bc0la/BezosBuster/cmd/bezosbuster@latest
#   → drops `bezosbuster` in $(go env GOBIN) (usually ~/go/bin — put it on PATH).
#   Pin a version with @v0.2.10 instead of @latest.

# or build from a local clone:
go build -o bezosbuster ./cmd/bezosbuster

bezosbuster scan --profile my-sso-profile
```

No volume mounts, no `-p`, no `--addr 0.0.0.0` — `~/.aws` is already visible,
output lands in `./engagements`, and `report` binds `127.0.0.1:7979` directly.
For a fully self-contained `scan` with no external tools at all, add
`--no-secrets` (or install `kingfisher` for secret scanning).

Releases are cut by [GoReleaser](.goreleaser.yaml) on `v*` tags
(linux/darwin × amd64/arm64). `bezosbuster --version` prints the build.

### Docker (batteries-included, for collect/steampipe)

```bash
docker build -t bezosbuster .
# or pull:
docker pull ghcr.io/bc0la/bezosbuster:latest
```

The image bakes in the Go binary + ScoutSuite + Steampipe + Powerpipe +
Kingfisher + `steampipe-mod-aws-perimeter` + Blue-CloudPEASS. Runs as non-root
user `bb` (uid 1000) because Steampipe refuses to run as root. Reach for it when
you want `collect` or the multi-account `steampipe` dashboard without installing
that toolchain on your host.

### Shell aliases for the Docker path

```bash
alias bb='docker run --rm -it -v ~/.aws:/root/.aws:ro -v "$PWD/engagements:/data" ghcr.io/bc0la/bezosbuster:latest'
alias bb-report='docker run --rm -it -v "$PWD/engagements:/data" -p 7979:7979 ghcr.io/bc0la/bezosbuster:latest report --addr 0.0.0.0:7979'
alias bb-steampipe='docker run --rm -it -v ~/.aws:/root/.aws:ro -p 9194:9194 ghcr.io/bc0la/bezosbuster:latest steampipe'
```

(With the binary you don't need these — just run `bezosbuster ...` directly.)

---

## Quickstart

Every example uses the native binary. `scan` is the fast, self-contained path;
swap in the `bb` Docker alias if you want the bundled external tools for
`collect` / `steampipe`. All credential modes below work identically on `scan`,
`collect`, `resume`, and `steampipe`.

### Credential modes

```bash
# 1. Ambient default chain — env vars / `default` profile / EC2 instance role.
#    Nothing to pass; the AWS SDK resolves whatever's already configured.
bezosbuster scan

# 2. Static access keys — export them, then run. Good for short-lived keys.
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...          # only if they're temporary creds
bezosbuster scan --region us-east-1

# 3. Named profile from ~/.aws/config or ~/.aws/credentials.
bezosbuster scan --profile dev

# 4. SSO profile — log in first, then scan (token lives ~8h).
aws sso login --profile my-sso
bezosbuster scan --profile my-sso

# 5. Several profiles in one run — one scan target per profile.
bezosbuster scan --profiles dev,staging,prod

# 6. Cross-account assume-role — hop from a hub identity into a customer account.
#    You assume FROM --profile (or the ambient chain); you assume INTO the ARN.
bezosbuster scan --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --external-id "acme-2026-Xf9..."

# 7. Multiple customer roles at once — repeat the flag, or comma-join the ARNs.
bezosbuster scan --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --assume-role-arn arn:aws:iam::444455556666:role/SecurityAudit \
  --external-id "acme-2026-Xf9..." \
  --role-session-name pentest-jane

# 8. Whole AWS Organization — enumerate accounts and assume-role into each.
bezosbuster scan --profile mgmt --org
bezosbuster scan --profile mgmt --org --assume-role OrganizationAccountAccessRole
```

### Selecting modules

`scan` runs **every native module** by default; `collect` runs every external
module. List what's registered (with its report section and potential-severity
rating) before you narrow things down:

```bash
bezosbuster modules
# MODULE                 KIND      SECTION          RATING
# public_opensearch      native    exposure         critical
# public_rds             native    exposure         critical
# s3_anon                native    exposure         critical
# public_mq              native    exposure         high
# ...
```

Two ways to narrow the run — they compose, and both work with **every**
credential mode above (including the cross-account assume-role flow):

```bash
# Inclusion — run ONLY these modules.
bezosbuster scan --profile dev --modules s3_anon,public_rds,iam_integrations

# Exclusion — run everything EXCEPT these (applied after --modules / the default).
bezosbuster scan --profile dev --exclude public_sns,public_sqs,bedrock

# Shortcut for the big, slow one:
bezosbuster scan --profile dev --no-secrets          # == --exclude secrets_scan
```

Cross-account assume-role, excluding the noisy/low-value checks for a customer run:

```bash
bezosbuster scan --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --external-id "acme-2026-Xf9..." \
  --role-session-name pentest-jane \
  --exclude secrets_scan,public_sns,public_sqs,bedrock,ec2_imdsv1
```

`--modules` and `--exclude` are repeatable or comma-separated, are validated
against the registry (unknown names are ignored), and are recorded in the
engagement's `meta` so `resume` reproduces the same selection.

### Tuning `secrets_scan`

The S3 sweep samples object contents for secrets. Buckets with millions of
objects would otherwise paginate for hours, so it's capped:

```bash
bezosbuster scan --profile dev --s3-max-pages 25   # default: ~25k objects/bucket
bezosbuster scan --profile dev --s3-max-pages 0    # unlimited (old behavior)
bezosbuster scan --profile dev --no-s3             # skip S3 entirely
```

Hitting the cap is logged at `warn` (so it lands in `--error-log`): coverage of
that bucket was partial. Raise the cap or target the bucket separately if needed.
See also `--secrets-timeout` (per-collector minutes) and `--no-secrets`.

By default the sweep is a flat, key-ordered listing, so a large early-sorting
prefix (e.g. `archive/`) can spend the whole page budget before later folders
(`config/`, `secrets/`) are reached. `--s3-fair` instead walks the bucket
**breadth-first per folder** so every prefix is touched:

```bash
bezosbuster scan --profile dev --s3-fair                    # breadth over depth
bezosbuster scan --profile dev --s3-fair --s3-max-pages 0   # touch every folder, no cap
```

`--s3-fair` fully lists each folder's immediate level (enqueuing all sub-folders)
before descending, with `--s3-max-pages` bounding total list pages. To *guarantee*
every folder in a large bucket is reached, pair it with `--s3-max-pages 0`.

**Secret values are stored unredacted by default** — the full match is written
to the engagement DB and shown in the report UI (`detail.match`), so you can use
a found credential straight away. This means `engagement.db` contains live
secrets in plaintext; treat the engagement dir as sensitive. To keep only a
short preview (`AKIA12…3456`) instead:

```bash
bezosbuster scan --profile dev --redact-secrets
```

### Log files

The TUI (and the report's Logs tab) show live progress, but they're awkward to
scroll back through. Both `scan` and `collect` can additionally mirror every log
event to a plaintext file you can `tail -f` / `grep`:

```bash
# Full log + an errors-only file, dropped inside the engagement dir.
bezosbuster scan --profile dev --log-file auto --error-log auto
#   → engagements/<run>/run.log        (everything)
#   → engagements/<run>/errors.log     (warnings/errors only — quick triage)

# Or point them anywhere:
bezosbuster scan --profile dev --log-file /tmp/bb.log --error-log /tmp/bb-err.log

tail -f engagements/<run>/run.log
```

- `--log-file PATH` — every event. `--error-log PATH` — only warn/error/fatal
  (module failures like `AccessDenied` are logged at `warn`, so they land here).
- Either can be used alone; both are optional and off by default.
- Lines look like `2026-08-12T20:08:42Z [WARN ] public_rds 1111…: us-east-1: AccessDenied`.
- Files are opened for **append**, so `--engagement` re-runs accumulate history.
- `auto` resolves to `<engagement>/run.log` / `errors.log` — and because the
  engagement dir is the mount used by the Docker `collect` path, `auto` is the
  value that works when `collect` delegates into the container (a bespoke host
  path would only be written inside the container).

#### All modules

Names below are exactly what you pass to `--modules` / `--exclude`. **Kind**:
`native` runs under `scan`, `external` under `collect`. **Section** is the
report-UI grouping; **rating** is the realistic worst-case potential severity.

| Module | Kind | Section | Rating | What it flags |
|---|---|---|---|---|
| `scoutsuite` | external | Best Practices | high | ScoutSuite multi-service benchmark (full HTML/JSON report bundle) |
| `steampipe_perimeter` | external | Best Practices | high | `steampipe-mod-aws-perimeter` internet-exposure benchmarks |
| `ec2_imdsv1` | native | Best Practices | medium | EC2 instances that still allow IMDSv1 (SSRF → credential-theft prerequisite) |
| `bedrock` | native | Best Practices | medium | Amazon Bedrock misconfigurations exposing GenAI resources / weak guardrails |
| `s3_anon` | native | Public Exposure | critical | S3 buckets anonymously listable / public objects, confirmed with unauthenticated probes |
| `public_rds` | native | Public Exposure | critical | RDS instances & clusters `PubliclyAccessible` (TCP-probed) |
| `public_opensearch` | native | Public Exposure | critical | OpenSearch/Elasticsearch domains with a wildcard access policy on a public endpoint |
| `apigw_lambda` | native | Public Exposure | high | API Gateway (v1/v2) + Lambda anonymous reach: no-auth methods/routes/function URLs, `*` resource policy, wildcard-ARN bypass analyzer |
| `ecr_repo_policy` | native | Public Exposure | high | Private ECR repos whose repository policy grants `*`/external accounts (images pullable by anyone) |
| `kms_key_exposure` | native | Public Exposure | high | Customer-managed KMS keys whose key policy grants `*`/external accounts |
| `public_amis` | native | Public Exposure | high | AMIs shared publicly (`--executable-users all`) |
| `public_snapshots` | native | Public Exposure | high | Public EBS snapshots + manual RDS DB/cluster snapshots shared with `all` |
| `public_redshift` | native | Public Exposure | high | Redshift clusters `PubliclyAccessible` (TCP-probed) |
| `public_documentdb` | native | Public Exposure | high | DocumentDB instances `PubliclyAccessible` (TCP-probed) |
| `public_neptune` | native | Public Exposure | high | Neptune instances `PubliclyAccessible` (TCP-probed) |
| `public_mq` | native | Public Exposure | high | Amazon MQ brokers `PubliclyAccessible` |
| `public_msk` | native | Public Exposure | high | MSK/Kafka provisioned clusters with broker public access enabled |
| `subdomain_takeover` | native | Public Exposure | high | Dangling Route53 records pointing at unclaimed resources (fingerprint-based) |
| `public_ecr` | native | Public Exposure | medium | ECR Public gallery repositories (public by design) |
| `public_sns` | native | Public Exposure | medium | SNS topics with an anonymous (`*`) access policy |
| `public_sqs` | native | Public Exposure | medium | SQS queues with an anonymous (`*`) access policy |
| `iam_integrations` | native | IAM & Access | critical | SAML/OIDC providers + role trust policies: GitHub/GitLab/EKS OIDC `:sub` analysis, cross-account confused-deputy, Cognito identity pools, wildcard principals |
| `bluecloudpeass` | external | IAM & Access | critical | Blue-AWSPEAS privilege-escalation path enumeration (raw JSON output) |
| `cognito` | native | IAM & Access | high | Cognito user-pool misconfig (self-signup, risky Lambda triggers, weak policies) |
| `secrets_scan` | native | Secrets Management | critical | Kingfisher secret sweep across ~20 sources (S3, Lambda code, CloudFormation, CloudWatch Logs, Glue, …) |
| `lambda_env` | native | Secrets Management | high | Secrets in Lambda environment variables |
| `ec2_userdata` | native | Secrets Management | high | Secrets in EC2 instance user data |
| `codebuild_env` | native | Secrets Management | high | Plaintext secrets in CodeBuild project environment variables |
| `ecs_ecr_taskdefs` | native | Secrets Management | high | ECS task definitions — env vars/commands (and image refs) flagged for secrets |
| `ssm_commands` | native | Secrets Management | medium | Secrets in SSM Run Command output history |

### A full engagement, end to end

```bash
# Fast native checks (fully self-contained; add --no-secrets to skip kingfisher).
bezosbuster scan --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --external-id "acme-2026-Xf9..."
# → prints the engagement dir, e.g. engagements/2026-08-10-143022-111122223333

# Heavy external tools into the SAME engagement dir. If the tools aren't
# installed locally, `collect` transparently runs itself inside the Docker
# image — pulling it and wiring up ~/.aws + the engagements mount for you.
bezosbuster collect --engagement engagements/2026-08-10-143022-111122223333 \
  --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --external-id "acme-2026-Xf9..."

# Browse findings in a local web report (binds 127.0.0.1:7979).
bezosbuster report engagements/2026-08-10-143022-111122223333

# SSO/role session died mid-scan? Re-auth and resume — flags are remembered.
aws sso login --profile hub
bezosbuster resume engagements/2026-08-10-143022-111122223333

# Live multi-account Steampipe dashboard. Same deal — delegates into the
# image (publishing :9194 and mounting ~/.aws) when steampipe isn't local.
bezosbuster steampipe --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --external-id "acme-2026-Xf9..."

# Scope a run to specific checks.
bezosbuster scan --profile dev --modules apigw_lambda,iam_integrations
bezosbuster modules            # list every registered module + its kind
```

---

## Subcommands

All subcommands share the same credential-detection logic:

| Flag | Effect |
|---|---|
| `--profile NAME` | Single account using the named AWS profile. |
| `--profiles a,b,c` | Explicit list of profiles. One target per profile. |
| *(none)* | Uses the default `AWS_PROFILE` / env vars / instance metadata. |
| `--org` | Enumerate AWS Organizations and assume-role into every active account. |
| `--assume-role NAME` | Role *name* to assume in org mode (default `OrganizationAccountAccessRole`). |
| `--assume-role-arn ARN` | Cross-account role ARN to assume from `--profile`. Repeatable (one target per ARN). No Organizations access needed — works from outside the target's org. |
| `--external-id ID` | `ExternalId` passed to `sts:AssumeRole`. Required by most third-party/customer trust policies. |
| `--role-session-name NAME` | Session name for assumed-role sessions (default `bezosbuster`); shows up in the customer's CloudTrail. |
| `--region us-east-1` | Region for IAM + Organizations API calls. |

### Cross-account / customer-environment access

The common consulting pattern: you hold **one** hub identity (an SSO profile or an
IAM user/role in your own account), and each customer has created a role that
trusts you — usually gated by an **external ID**. BezosBuster hops from your hub
identity into each customer role. It does **not** need Organizations access, so it
works even though you're outside the customer's org.

**Option A — first-class flags (ad-hoc, nothing to configure):**

```bash
# One customer account
bezosbuster scan \
  --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --external-id "acme-2026-Xf9..."

# Several customer accounts in one run (repeat the flag)
bezosbuster scan --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --assume-role-arn arn:aws:iam::444455556666:role/SecurityAudit \
  --external-id "acme-2026-Xf9..."
```

You assume **from** whatever `--profile` resolves to (your hub identity) — there's
no separate "from-ARN" flag; the source is always the profile's credentials, or
the ambient default chain if you omit `--profile`. You assume **into** each
`--assume-role-arn`. That flag is a list: repeat it, or comma-join the ARNs
(`--assume-role-arn arnA,arnB`) since ARNs contain no commas. One scan target per
ARN.

Each ARN is probed with `sts:GetCallerIdentity` before the scan starts, so a bad
ARN, wrong external ID, or missing trust fails loudly and immediately instead of
mid-scan. The chosen options are saved to the engagement so `resume` re-assumes
the same roles without re-typing anything. These flags work on `scan`, `collect`,
and `steampipe` alike.

**Option B — profile chaining in `~/.aws/config` (stable customer roster):**

The AWS SDK resolves role chains natively, so you can also just describe each
customer as a profile and use the existing `--profile` / `--profiles` flags:

```ini
# ~/.aws/config
[profile hub]
sso_start_url = https://your-org.awsapps.com/start
sso_account_id = 999988887777
sso_role_name = Engagements
region = us-east-1

[profile acme]
role_arn       = arn:aws:iam::111122223333:role/SecurityAudit
source_profile = hub
external_id     = acme-2026-Xf9...
region         = us-east-1

[profile globex]
role_arn       = arn:aws:iam::444455556666:role/SecurityAudit
source_profile = hub
external_id     = globex-2026-Qk2...
```

```bash
aws sso login --profile hub          # refresh the hub SSO token
bezosbuster scan --profiles acme,globex
```

Use flags for one-off targets, profile chaining when the customer list is stable.
Either way, when the assumed-role session expires mid-scan the usual
`resume` flow applies (re-login on the hub, then `bezosbuster resume <dir>`).

### 1. `scan` — native AWS-SDK checks

The fast path. Everything runs in-process against the AWS SDK; typical run is seconds to minutes. This is what you want first on any engagement.

**What runs** (every module where `Kind() == native` — 26 of them; the report UI groups them into four sections: Best Practices, Secrets Management, IAM & Access, Public Exposure). Highlights:
- `apigw_lambda` — API Gateway + Lambda anonymous-reach + wildcard-crossing ARN analyzer.
- **Public-exposure family** — `public_amis`, `public_snapshots` (public EBS **and** manual RDS DB/cluster snapshots shared with `all`), `public_rds`, `public_redshift`, `public_documentdb`, `public_neptune` (all TCP-probed), `public_ecr` (ECR Public gallery), `ecr_repo_policy` (private ECR repos with a wildcard/external repository policy), `public_sns`, `public_sqs`, `s3_anon`, `public_opensearch` (OpenSearch/ES domains with a wildcard access policy on a public endpoint), `public_mq` (Amazon MQ brokers), `public_msk` (MSK/Kafka public access), `kms_key_exposure` (key policies granting `*`/external-account access).
- `secrets_scan` + env collectors (`lambda_env`, `ec2_userdata`, `codebuild_env`, `ecs_ecr_taskdefs`, `ssm_commands`) — Kingfisher-backed secret detection across ~20 sources.
- `iam_integrations` — comprehensive identity federation review. Enumerates SAML + OIDC providers; cross-references them against role trust policies; condition-aware analysis of every `sts:AssumeRole` / `sts:AssumeRoleWithWebIdentity` / `sts:AssumeRoleWithSAML` statement; **deep GitHub Actions `:sub` claim analysis** (catches `repo:*` / `repo:org/*` / wildcard owners / missing `:aud` / missing `:sub` / pull-request subjects); SAML metadata expiry; orphaned providers; Cognito identity pools with `AllowUnauthenticatedIdentities=true` or classic flow; wildcard principals.

**Order of operations:**
1. Parse flags, signal-notify context (Ctrl-C stops cleanly).
2. `creds.Detect` — probes STS `GetCallerIdentity` to validate creds; if `--org`, calls `organizations:ListAccounts` then `sts:AssumeRole` into each active account (broken assumes are logged and skipped, not fatal).
3. `selectModules("native", ...)` — resolves the final module name list (all native modules unless `--modules` subset given).
4. Open/create the engagement dir (`engagements/<ts>-<primary-acct>/` by default, or `--engagement DIR` to append to an existing one). Initializes `engagement.db` (SQLite) and writes the scan options to `meta` (`opt.kind=native`, `opt.profile`, …) so `resume` can reproduce them.
5. Start the Bubble Tea TUI (unless `--no-tui`).
6. Scheduler fans modules out across all detected accounts. Two semaphores:
   - **Per-account**: 4 concurrent modules per account.
   - **Global**: 16 concurrent module runs total.
7. For each `(account, module)` pair:
   - Marks `module_runs` row `running` in SQLite.
   - Calls `module.Run(ctx, target, sink)`. Module uses `sink.Write(Finding{...})` to record findings.
   - Native modules often loop regions — `awsapi.EnabledRegions` calls `ec2:DescribeRegions` (filtered to opted-in regions) to know which regions to hit.
   - Marks `completed` / `failed` / `skipped`.
   - Emits an event to the TUI via a channel.
8. When creds expire mid-run, the scheduler's `ExpiryWatcher` trips; remaining pairs get `skipped` with "creds expired"; `scan` exits with a warning telling you to `aws sso login` and then `bezosbuster resume <dir>`.
9. Prints the engagement dir path on exit.

**Typical invocations:**
```bash
# Single account
bb scan --profile dev

# Whole org
bb scan --profile mgmt --org

# Only the API Gateway analyzer
bb scan --profile dev --modules apigw_lambda

# Append to an existing engagement dir instead of creating a new one
bb scan --profile dev --engagement /data/2026-04-11-143022-111122223333
```

---

### 2. `collect` — external tools (slow)

Identical flags to `scan`, but runs modules where `Kind() == external`: ScoutSuite, Blue-CloudPEASS, `steampipe_perimeter`. These subprocess out to the real tools and can take minutes to hours. Each is bounded by a timeout (Blue-CloudPEASS 30 min) and group-killed on expiry, so a stuck tool can't wedge the run.

**Auto-delegates to Docker.** `collect` is the external-tool "zoo", and those
tools are a pain to install natively. So when the flagship tool (`scout`) isn't
on your `PATH`, `collect` re-runs *itself* inside the batteries-included image —
pulling the image if needed and wiring up the flags you'd otherwise type by hand:
`~/.aws` mounted read-only, the engagements dir bind-mounted at `/data`, your
`AWS_*` env forwarded, and an interactive TTY for the progress UI. You just run:

```bash
bezosbuster collect --profile hub \
  --assume-role-arn arn:aws:iam::111122223333:role/SecurityAudit \
  --external-id "acme-2026-Xf9..."
```

| Flag | Effect |
|---|---|
| *(default)* | **auto** — delegate to Docker only if `scout` isn't installed locally and `docker` is available; otherwise run in-process. |
| `--docker` | Force delegation into the image. |
| `--docker=false` | Never delegate; run in-process (missing tools are skipped with a warning). |
| `--docker-image REF` | Override the image (default `ghcr.io/bc0la/bezosbuster:latest`). |
| `--docker-pull` | `docker pull` before running (otherwise pulled only if absent). |

The credential flags (`--profile`, `--assume-role-arn`, `--external-id`, …) are
forwarded into the container, so your hub-into-customer assume-role flow works
identically whether or not it runs in Docker. Recursion is guarded by a
`BB_IN_DOCKER=1` env marker set on the delegated run. The `steampipe` subcommand
delegates the same way (additionally publishing `:9194`).

**Where output goes:** not the SQLite DB. Each wrapper writes directly to `<engagement-dir>/<module>/<account>/`:

```
scoutsuite/111122223333/          ← full ScoutSuite HTML+JSON report bundle
  report.html
  scoutsuite-report/*
  stdout.log
  stderr.log
steampipe_insights/111122223333/
  results.json                    ← steampipe check all --export json=results.json
  stdout.log
  stderr.log
bluecloudpeass/111122223333/
  results.json                    ← Blue-CloudPEASS findings
  stdout.log                      ← whatever Blue-CloudPEASS prints
  stderr.log
```

A single summary `Finding` per `(module, account)` is written to `engagement.db` with `raw_output_path` pointing at the subdir; the report UI shows a "browse" link per row that opens `/raw/<module>/<account>/` via the static file handler.

**Order of operations:**
1. Same credential detection + engagement dir open + meta-writing as `scan` — but `opt.kind=external`.
2. `selectModules("external", ...)` resolves external modules only.
3. Scheduler fans out identically.
4. Each external module's `Run()` delegates to `exttool.Run()`:
   1. `exec.LookPath(binary)` — if the tool isn't on `PATH`, logs a warning finding and returns (no error, so other tools keep going).
   2. `sink.RawDir(module, accountID)` creates `<engagement-dir>/<module>/<account>/` and returns its absolute path.
   3. Retrieves concrete AWS creds from the target's SDK config, builds an env list (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `HOME=/home/bb`).
   4. Calls the wrapper's `ArgBuilder(rawDir)` to template the raw dir into tool-specific flags (e.g. `--report-dir /data/.../scoutsuite/111122223333` for ScoutSuite, `--export json=.../results.json` for Steampipe).
   5. Opens `stdout.log` and `stderr.log` in the raw dir and wires them to the child process via `io.MultiWriter`.
   6. Runs the child, writes a summary `Finding` referencing the raw dir.
5. Returns; the TUI updates each module's status cell.

**Typical invocations:**
```bash
# Just the collect step, single account
bb collect --profile dev

# Scan first, then collect into the same engagement dir
bb scan --profile dev
bb collect --profile dev --engagement /data/2026-04-11-143022-111122223333

# Only ScoutSuite
bb collect --profile dev --modules scoutsuite
```

---

### 3. `report` — local web UI

Embedded SPA served over HTTP. Reads `<dir>/engagement.db` for findings and serves `<dir>/` as a static file tree rooted at `/raw/`. Pure offline, no external assets.

**Order of operations:**
1. Parse args: `bezosbuster report <engagement-dir>`.
2. Verify `<dir>/engagement.db` exists.
3. `sql.Open("sqlite", dbPath)`.
4. Register routes:
   - `GET /` → embedded `index.html`.
   - `GET /api/summary` → `{"modules":[{module,count,category}], "severity":{...}, "categories":[{key,label}]}` grouped over the `findings` table. `category` maps each module to one of the four UI sections (single source of truth: `internal/module/category.go`).
   - `GET /api/findings?module=X` → flattened finding rows with parsed `detail`. `raw_output_path` is rewritten from the absolute path stored in the DB to a `/raw/<rel>/` URL (via `filepath.Rel`) so the link resolves under the static handler.
   - `GET /raw/...` → `http.FileServer(http.Dir(<engagement-dir>))` with `/raw/` stripped. Traversal outside the engagement dir is blocked by `http.Dir`.
5. `http.ListenAndServe(addr, mux)`.

**Docker needs two things** to make the UI reachable from your host browser:
- `-p 7979:7979` to publish the port.
- `--addr 0.0.0.0:7979` on the binary — the default `127.0.0.1` is only reachable from inside the container.

```bash
docker run --rm -it \
  -v "$PWD/engagements:/data" \
  -p 7979:7979 \
  ghcr.io/bc0la/bezosbuster:latest \
  report /data/2026-04-11-143022-111122223333 --addr 0.0.0.0:7979
# open http://127.0.0.1:7979
```

With the `bb-report` alias above: `bb-report /data/<dir>`.

**What the UI shows:**
- **Four category sections** — Best Practices, Secrets Management, IAM & Access, Public Exposure — plus an "All" tab and a **False Positives** tab. Selecting a section reveals its module chips for further narrowing. Section/module/severity counts are computed client-side (findings are loaded once), so switching tabs is instant and the counts never drift.
- **False Positives workflow** — the `x` on a row moves the finding into the False Positives tab (localStorage-backed, per-analyst, non-destructive) rather than hiding it; each row there has a **Restore** button, plus **Restore-all** for the current view.
- **Per-check filter** — a `checks:` toggle bar (present in every view including False Positives) splits modules that emit several sub-checks (e.g. `iam_integrations`, `apigw_lambda`, `public_snapshots`) so you can filter noisy checks out fast. It also drives what the **export** buttons emit.
- Severity chips reflecting the current section/module.
- Sortable/filterable table with resizable columns: severity, account, region, module, title, resource, raw, detail.
- "raw" column has a `browse` link for findings with raw output (tool wrappers) — opens `/raw/<module>/<account>/` so you can navigate ScoutSuite's HTML bundle or download `results.json`.
- "detail" column is a collapsible `<details>` block with the full `detail_json`.
- Export buttons (curls / JSON / assets) that honor the current section, module, check filter, and text filter (and always exclude false positives).
- **Report / Utils** top-level tabs. **Utils → SQS Monitor** lists the public queues found by `public_sqs`, lets you select the relevant ones, and — with **Monitor filtered queues** — live-streams each queue's messages into per-queue tabs while writing them to `<engagement>/sqs-monitor/<queue>.jsonl`. It reads queues **anonymously and unsigned** (no AWS creds — the report server stays credential-less), with `VisibilityTimeout=0` and no deletes, so it's a **non-disruptive tap**: the real consumer still receives everything. Only queues present as `public_sqs` findings can be streamed (SSRF guard); a conditioned policy that denies anonymous access shows an error on its tab.

---

### 4. `resume` — continue an interrupted run

Re-runs whatever `scan`/`collect` didn't finish. Reads the original options from the engagement's `meta` table so you don't have to re-type flags.

**Order of operations:**
1. Parse args: `bezosbuster resume <engagement-dir>`.
2. Verify `<dir>/engagement.db` exists; if not, bail. Prevents silently creating an empty new engagement.
3. Open the engagement.
4. `readScanOpts(eng)` reads from `meta`:
   - `opt.profile`, `opt.profiles`, `opt.org`, `opt.assume_role`, `opt.region` → rebuilds `creds.Options`.
   - `opt.kind` (`native` or `external`) → which module set.
   - `opt.modules` → optional user subset.
5. `creds.Detect(...)` with the same options. If the SSO token has expired, fails with a hint: `run aws sso login then retry`.
6. `eng.CompletedModules()` → pulls the set of `(account, module)` pairs with status `completed` from `module_runs`.
7. `selectModules(opts.kind, opts.modules)` → rebuilds the target module list from the current registry (so if you add a new native module after the original scan, resume picks it up).
8. Computes "pairs remaining" = (targets × modules) − completed, prints a one-line summary, exits early if zero.
9. Starts a fresh scheduler run with `Done` populated from step 6 — completed pairs are skipped silently (no event, no DB write).
10. Same TUI / event loop as scan/collect.

**`failed`, `skipped`, and in-flight `running` rows are all re-run** — only `completed` is preserved. That's deliberate: skipped rows are the ones the expiry watcher stopped mid-run, and those need to redo their work.

```bash
# SSO died mid-scan:
aws sso login --profile dev
bb resume /data/2026-04-11-143022-111122223333
# or in Docker:
bb resume /data/2026-04-11-143022-111122223333 --no-tui
```

---

### 5. `steampipe` — live multi-account dashboard

Starts `steampipe dashboard` in the foreground for interactive querying. Unlike `collect`, this is not a batch run — it keeps going until you Ctrl-C, and you explore via browser or `steampipe query`.

**Order of operations:**
1. Parse flags (same cred options as `scan`/`collect` plus `--mod`, default `/home/bb/mods/steampipe-mod-aws-insights`).
2. `creds.Detect(...)` → list of targets.
3. `exec.LookPath("steampipe")` — hard fail if not on `PATH`.
4. `writeSteampipeAWSConfig(targets)`:
   1. `os.UserHomeDir()` → typically `/home/bb` in the container.
   2. `mkdir -p ~/.steampipe/config`.
   3. For each target: `target.Config.Credentials.Retrieve(ctx)` → concrete `AccessKeyID`, `SecretAccessKey`, `SessionToken`.
   4. Emits an HCL block per account:
      ```hcl
      connection "aws_bb_111122223333" {
        plugin        = "aws"
        access_key    = "AKIA…"
        secret_key    = "…"
        session_token = "…"
        regions       = ["*"]
      }
      ```
   5. Appends an aggregator connection:
      ```hcl
      connection "aws_bb_all" {
        plugin      = "aws"
        type        = "aggregator"
        connections = ["aws_bb_*"]
      }
      ```
   6. Writes to `~/.steampipe/config/bezosbuster-aws.spc` with mode `0600`.
5. Prints the generated connections + the aggregator name.
6. `exec.Command("steampipe", "dashboard", "--mod-location", mod, "--dashboard-listen", "network", "--dashboard-port", "9194")` wired to stdin/stdout/stderr of the parent, inheriting env.
7. Steampipe auto-starts its own PostgreSQL service on first dashboard launch (`steampipe service start` is implicit), then serves HTML on `:9194`.
8. On Ctrl-C, the context cancels and the child is killed.

**Caveats:**
- Assumed-role sessions default to 1h. When they expire, `steampipe` keeps running but queries start failing with `ExpiredToken`. Restart `bezosbuster steampipe` to refresh.
- Credentials are written to disk inside the container at `~/.steampipe/config/bezosbuster-aws.spc`. Container is `--rm` so they die with it, but if you run natively the file persists — `chmod 600` is applied, be aware.
- Aggregator connections require every child to use the same plugin. All are `aws`, so fine.

**Typical invocations:**
```bash
# Whole org
docker run --rm -it \
  -v ~/.aws:/root/.aws:ro \
  -p 9194:9194 \
  ghcr.io/bc0la/bezosbuster:latest \
  steampipe --profile mgmt --org
# open http://127.0.0.1:9194
```

**Queries you probably want:**
```sql
-- Public S3 buckets across every account in the org
select account_id, name, region
from aws_bb_all.aws_s3_bucket
where bucket_policy_is_public = true;

-- Security groups with 0.0.0.0/0 ingress on non-web ports
select account_id, region, group_id, group_name
from aws_bb_all.aws_vpc_security_group_rule
where cidr_ipv4 = '0.0.0.0/0'
  and from_port not in (80, 443)
  and type = 'ingress';

-- All IAM users with console access and no MFA
select account_id, name, create_date
from aws_bb_all.aws_iam_user
where password_last_used is not null
  and mfa_enabled = false;
```

---

### 6. `modules` — list registered modules

```bash
bb modules
```

Prints one line per registered module with its `Kind` (`native` or `external`). Useful for picking a `--modules` subset.

---

## Engagement directory layout

```
engagements/
  2026-04-11-143022-111122223333/
    engagement.db                      ← SQLite (findings, logs, meta, module_runs)
    scoutsuite/
      111122223333/
        report.html                    ← ScoutSuite's full HTML report
        scoutsuite-report/*
        stdout.log
        stderr.log
    steampipe_insights/
      111122223333/
        results.json                   ← steampipe check output
        stdout.log
        stderr.log
    steampipe_perimeter/
      111122223333/
        results.json
        stdout.log
        stderr.log
    bluecloudpeass/
      111122223333/
        results.json
        stdout.log
        stderr.log
```

The `.db` is small (findings + metadata). The bulk of disk usage is under `scoutsuite/` (the HTML bundle can be 10+ MB). In org mode you get one subdirectory per account under each tool.

## Data model

`engagement.db` schema (`internal/engagement/sqlite.go`):

- **`meta`** — `key`/`value` pairs. Holds `opt.profile`, `opt.profiles`, `opt.org`, `opt.assume_role`, `opt.region`, `opt.kind`, `opt.modules`, `started_at`, `targets`. Used by `resume`.
- **`accounts`** — one row per target, status (`pending`/`running`/`completed`), aliases, timings.
- **`module_runs`** — one row per `(account_id, module)`, status (`pending`/`running`/`completed`/`failed`/`skipped`), powers `resume`.
- **`findings`** — normalized: `account_id`, `region`, `module`, `severity`, `resource_arn`, `title`, `detail_json`, `raw_output_path`, `created_at`. Powers the web report.
- **`logs`** — scheduler warnings (`sink.LogEvent`), e.g. "binary not found on PATH", "region xyz: throttled".

## Module interface

```go
type Module interface {
    Name() string
    Kind() Kind                 // native | external
    Requires() []string         // IAM actions / binaries
    Run(ctx context.Context, target AccountTarget, sink Sink) error
}
```

Modules use `Sink` for output:

```go
type Sink interface {
    Write(ctx context.Context, f Finding) error                       // normalized findings → SQLite
    RawDir(module, accountID string) (string, error)                  // mkdir + return path for raw tool output
    LogEvent(ctx context.Context, module, accountID, level, msg string) error
}
```

Add a new check: drop a package under `internal/module/<name>/`, put `func init() { module.Register(Module{}) }` at package level, and add a `_ "github.com/bc0la/BezosBuster/internal/module/<name>"` side-effect import in `cmd/bezosbuster/main.go`.

## Layout

```
cmd/bezosbuster/          main, cobra commands
internal/
  engagement/             SQLite lifecycle + schema + Sink impl
  creds/                  credential detection, SSO refresh, org enumeration
  orchestrator/           scheduler, per-account + global semaphores
  module/                 Module interface + registry
    category.go           module -> UI section map (single source of truth)
    apigw_lambda/         API Gateway wildcard analyzer (canonical native check)
    iam_integrations/     SAML/OIDC providers, trust policies, Cognito pools
    public_amis/ public_snapshots/ public_rds/ public_redshift/
    public_documentdb/ public_neptune/ public_mq/ public_msk/
    public_opensearch/ public_ecr/ public_sns/ public_sqs/ s3_anon/
    kms_key_exposure/
    lambda_env/ ecs_ecr_taskdefs/ secrets_scan/
    exttool/              shared helper for external-tool wrappers
    scoutsuite/ bluecloudpeass/ steampipe_perimeter/
  findings/               Finding + Sink types
  tui/                    Bubble Tea app
  report/                 embedded SPA + /api/summary + /api/findings + /raw/
  awsapi/                 EnabledRegions helper
Dockerfile                multi-stage: Go 1.25 + steampipe + scoutsuite + bluecloudpeass
.github/workflows/
  docker.yml              build + push ghcr.io/bc0la/bezosbuster on tag v*
                          (skips builds when only *.md / docs/** change)
```

## Verification

1. Unit: module registry loads, APIGW wildcard analyzer (`internal/module/apigw_lambda/wildcard_test.go`) covers the canonical `prod/*/dashboard/*` → `prod/GET/admin/dashboard/createAdmin` bypass case; GitHub OIDC `:sub` analyzer (`internal/module/iam_integrations/github_oidc_test.go`) covers the 12 known takeover patterns.
2. Smoke against a throwaway account:
   - `bb scan --profile test` → TUI runs, `engagement.db` populated.
   - `bb collect --profile test --engagement <dir>` → external tool output lands under `<dir>/<tool>/<acct>/`.
   - `bb-report /data/<dir>` → browser UI loads, raw links resolve.
   - Revoke SSO, confirm `scan` warns and `resume` continues.
3. Org mode: run against an account with `organizations:ListAccounts`. Confirms per-account fan-out and that failed assume-roles are logged not fatal.
4. Docker: `docker build -t bezosbuster .` then `docker run --rm bezosbuster modules` lists 14 modules.
5. Multi-account steampipe: `bb-steampipe --profile mgmt --org` generates `bezosbuster-aws.spc` with one connection per account, dashboard serves on `:9194`, `select * from aws_bb_all.aws_account` returns a row per target.
