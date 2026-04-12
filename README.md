# BezosBuster

Automated AWS whitebox pentest workflow. Single Go binary, ships as a Docker image, drives ScoutSuite / Blue-CloudPEASS / Steampipe mods / Pacu plus a set of native follow-up checks in parallel across one or many AWS accounts, writes findings into a per-engagement SQLite DB for the web report, and stashes raw tool output into per-module/per-account subdirectories on the mount so you can read it directly.

## Why

Whitebox AWS engagements repeat the same toolchain and follow-ups every time. Credentials are usually short-lived (8h SSO) and you sometimes have Organizations access across many accounts. BezosBuster removes the manual orchestration, survives token expiry mid-scan, and produces one artifact per engagement you can diff between runs.

## Features

- **Auto-detects credential mode** — single profile, profile list, or Organizations (enumerate accounts + assume role). Works in every environment.
- **SSO expiry handling** — scheduler detects `ExpiredToken` errors, warns, and a `resume` subcommand picks up where it left off.
- **Parallel orchestration** — per-account + global semaphores; failing modules never abort the run.
- **`scan` / `collect` split** — `scan` runs native `aws-sdk-go-v2` checks (fast, in-process); `collect` runs external tools (slow, subprocess). Same flags, same engagement dir.
- **Wraps existing tools**: ScoutSuite, Blue-CloudPEASS, `steampipe-mod-aws-insights`, `steampipe-mod-aws-perimeter`, Pacu cognito enum.
- **Native follow-up checks** via `aws-sdk-go-v2`:
  - Public AMIs, public EBS snapshots, public RDS (with TCP probe), public ECR.
  - Lambda environment variables (all functions, secret-like key/value regex).
  - ECS / ECR task definitions.
  - Roles with `AssumeRoleWithWebIdentity` and their trust policies/conditions.
  - **API Gateway / Lambda anonymous-reach analyzer**, including the wildcard-bypass logic (a rule like `arn:aws:execute-api:...:api-id/prod/*/dashboard/*` matching `prod/GET/admin/dashboard/createAdmin`).
- **Engagement directory per run** — `engagements/<ts>-<acct>/` holds `engagement.db` (normalized findings, powers the report) plus per-tool subdirs (`scoutsuite/<acct>/report.html`, `steampipe_insights/<acct>/results.json`, `pacu_cognito/<acct>/stdout.log`, …) readable straight off the host mount.
- **Bubble Tea TUI** — tabs for accounts, modules, logs, live progress.
- **Local web report** — `bezosbuster report <dir>` serves a tabbed offline dashboard with deep-links to each tool's raw output via `/raw/...`.
- **Multi-account Steampipe dashboard** — `bezosbuster steampipe` generates one Steampipe `aws` connection per detected account plus an `aws_bb_all` aggregator, then launches the dashboard for live queries across every account.

## Install

### Docker (recommended)

```bash
docker build -t bezosbuster .
# or pull:
docker pull ghcr.io/bc0la/bezosbuster:latest
```

The image bakes in Go binary + ScoutSuite + Pacu + Steampipe + `steampipe-mod-aws-insights` + `steampipe-mod-aws-perimeter` + Blue-CloudPEASS. Runs as non-root user `bb` (uid 1000) because Steampipe refuses to run as root.

### Native

```bash
go build -o bezosbuster ./cmd/bezosbuster
./bezosbuster scan --profile my-sso-profile
```

For `collect` and `steampipe` subcommands you'll also need `scout`, `pacu`, `steampipe`, and the Steampipe AWS plugin on `PATH`. The Docker image is strictly easier.

### Shell aliases for less typing

```bash
alias bb='docker run --rm -it -v ~/.aws:/root/.aws:ro -v "$PWD/engagements:/data" ghcr.io/bc0la/bezosbuster:latest'
alias bb-report='docker run --rm -it -v "$PWD/engagements:/data" -p 7979:7979 ghcr.io/bc0la/bezosbuster:latest report --addr 0.0.0.0:7979'
alias bb-steampipe='docker run --rm -it -v ~/.aws:/root/.aws:ro -p 9194:9194 ghcr.io/bc0la/bezosbuster:latest steampipe'
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
| `--assume-role NAME` | Role name to assume in org mode (default `OrganizationAccountAccessRole`). |
| `--region us-east-1` | Region for IAM + Organizations API calls. |

### 1. `scan` — native AWS-SDK checks

The fast path. Everything runs in-process against the AWS SDK; typical run is seconds to minutes. This is what you want first on any engagement.

**What runs** (all modules where `Kind() == native`):
- `apigw_lambda` — API Gateway + Lambda anonymous-reach + wildcard-crossing ARN analyzer.
- `public_amis` — `DescribeImages --executable-users all`, filtered to `Owners=self`.
- `public_snapshots` — `DescribeSnapshots --restorable-by-user-ids all`, filtered to `Owners=self`.
- `public_rds` — `DescribeDBInstances` + TCP connect probe to the endpoint.
- `public_ecr` — `ecr-public:DescribeRepositories` (us-east-1 only, that's where public ECR lives).
- `lambda_env` — dumps all Lambda env vars, flags secret-like keys/values.
- `ecs_ecr_taskdefs` — active ECS task definitions with containers, images, env, task/exec roles.
- `web_identity` — IAM roles trusting `sts:AssumeRoleWithWebIdentity`, flagged critical if the trust policy has no `Condition`.

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

Identical flags to `scan`, but runs modules where `Kind() == external`: ScoutSuite, Blue-CloudPEASS, Pacu cognito, `steampipe_insights`, `steampipe_perimeter`. These subprocess out to the real tools and can take minutes to hours.

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
  stdout.log                      ← whatever Blue-CloudPEASS prints
  stderr.log
pacu_cognito/111122223333/
  stdout.log                      ← pacu's output
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
   - `GET /api/summary` → `{"modules":[{module,count}], "severity":{...}}` grouped over the `findings` table.
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
- Severity chips at the top (critical/high/medium/low/info counts).
- One tab per module plus an "All" tab.
- Sortable/filterable table: severity, account, region, module, title, resource, raw, detail.
- "raw" column has a `browse` link for findings with raw output (tool wrappers) — opens `/raw/<module>/<account>/` so you can navigate ScoutSuite's HTML bundle or download `results.json`.
- "detail" column is a collapsible `<details>` block with the full `detail_json`.

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
        stdout.log
        stderr.log
    pacu_cognito/
      111122223333/
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

Add a new check: drop a package under `internal/module/<name>/`, put `func init() { module.Register(Module{}) }` at package level, and add a `_ "github.com/you/bezosbuster/internal/module/<name>"` side-effect import in `cmd/bezosbuster/main.go`.

## Layout

```
cmd/bezosbuster/          main, cobra commands
internal/
  engagement/             SQLite lifecycle + schema + Sink impl
  creds/                  credential detection, SSO refresh, org enumeration
  orchestrator/           scheduler, per-account + global semaphores
  module/                 Module interface + registry
    apigw_lambda/         API Gateway wildcard analyzer (canonical native check)
    public_amis/ public_snapshots/ public_rds/ public_ecr/
    lambda_env/ ecs_ecr_taskdefs/ web_identity/
    exttool/              shared helper for external-tool wrappers
    scoutsuite/ bluecloudpeass/ steampipe_insights/ steampipe_perimeter/
    pacu_cognito/
  findings/               Finding + Sink types
  tui/                    Bubble Tea app
  report/                 embedded SPA + /api/summary + /api/findings + /raw/
  awsapi/                 EnabledRegions helper
Dockerfile                multi-stage: Go 1.25 + steampipe + scoutsuite + pacu + bluecloudpeass
.github/workflows/
  docker.yml              build + push ghcr.io/bc0la/bezosbuster on tag v*
```

## Verification

1. Unit: module registry loads, APIGW wildcard analyzer (`internal/module/apigw_lambda/wildcard_test.go`) covers the canonical `prod/*/dashboard/*` → `prod/GET/admin/dashboard/createAdmin` bypass case.
2. Smoke against a throwaway account:
   - `bb scan --profile test` → TUI runs, `engagement.db` populated.
   - `bb collect --profile test --engagement <dir>` → external tool output lands under `<dir>/<tool>/<acct>/`.
   - `bb-report /data/<dir>` → browser UI loads, raw links resolve.
   - Revoke SSO, confirm `scan` warns and `resume` continues.
3. Org mode: run against an account with `organizations:ListAccounts`. Confirms per-account fan-out and that failed assume-roles are logged not fatal.
4. Docker: `docker build -t bezosbuster .` then `docker run --rm bezosbuster modules` lists 13 modules.
5. Multi-account steampipe: `bb-steampipe --profile mgmt --org` generates `bezosbuster-aws.spc` with one connection per account, dashboard serves on `:9194`, `select * from aws_bb_all.aws_account` returns a row per target.
