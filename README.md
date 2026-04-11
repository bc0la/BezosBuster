# BezosBuster

Automated AWS whitebox pentest workflow. Single Go binary, ships as a Docker image, drives ScoutSuite / Blue-CloudPEASS / Steampipe mods / Pacu and a set of native follow-up checks in parallel across one or many AWS accounts, writes everything into a per-engagement SQLite database, and renders a local tabbed web report.

## Why

Whitebox AWS engagements repeat the same toolchain and follow-ups every time. Credentials are usually short-lived (8h SSO) and you sometimes have Organizations access across many accounts. BezosBuster removes the manual orchestration, survives token expiry mid-scan, and produces one artifact per engagement you can diff between runs.

## Features

- **Auto-detects credential mode** — single profile, profile list, or Organizations (enumerate accounts + assume role). Works in every environment.
- **SSO expiry handling** — background watcher pauses the scheduler when tokens expire, prints a re-login hint, and resumes on keypress.
- **Parallel orchestration** — per-account and global semaphores; failing modules never abort the run.
- **Wraps existing tools**: ScoutSuite, Blue-CloudPEASS, steampipe-mod-aws-insights, mod-aws-perimeter, Pacu cognito enum.
- **Native follow-up checks** via `aws-sdk-go-v2`:
  - Public AMIs, public EBS snapshots, public RDS, public ECR.
  - Lambda environment variables (all functions).
  - ECS / ECR task definitions.
  - Roles with `AssumeRoleWithWebIdentity` and their trust policies.
  - **API Gateway / Lambda anonymous-reach analyzer**, including the wildcard-bypass logic (a rule like `arn:aws:execute-api:...:api-id/prod/*/dashboard/*` matching `prod/GET/admin/dashboard/createAdmin`).
- **Engagement directory per run** — `engagements/<ts>-<acct>/` holds `engagement.db` (normalized findings, for the report) plus per-tool subdirs (`scoutsuite/<acct>/report.html`, `steampipe_insights/<acct>/results.json`, `pacu_cognito/<acct>/stdout.log`, …) that you read directly off the host mount.
- **Bubble Tea TUI** — tabs for accounts, modules, findings, logs, live progress.
- **Local web report** — `bezosbuster report <engagement-dir>` opens a tabbed offline dashboard with deep-links to each tool's raw output via `/raw/...`.
- **Steampipe live dashboard** — `bezosbuster steampipe --profile X` runs `steampipe dashboard` in-container against the aws-insights mod on `:9194` for interactive browsing.

## Install

### Docker (recommended)

```bash
docker build -t bezosbuster .
docker run --rm -it \
  -v ~/.aws:/root/.aws \
  -v "$PWD/engagements:/data" \
  bezosbuster scan --profile my-sso-profile
```

### Native

```bash
go build -o bezosbuster ./cmd/bezosbuster
./bezosbuster scan --profile my-sso-profile
```

You'll also need `scoutsuite`, `pacu`, `steampipe`, and `Blue-CloudPEASS` on `PATH` if you're not using the Docker image.

## Usage

```bash
# Single profile
bezosbuster scan --profile dev

# Explicit profile list
bezosbuster scan --profiles dev,staging,prod

# Organization auto-enumerate (assume-role into every account)
bezosbuster scan --profile mgmt --org --assume-role OrganizationAccountAccessRole

# Resume an interrupted engagement
bezosbuster resume engagements/2026-04-11-143022-123456789012

# Open the report
bezosbuster report engagements/2026-04-11-143022-123456789012

# Live Steampipe dashboard (map -p 9194:9194 on docker run)
bezosbuster steampipe --profile my-sso-profile
```

## Layout

```
cmd/bezosbuster/          main, cobra commands
internal/
  engagement/             SQLite lifecycle + schema
  creds/                  credential detection, SSO refresh, org enumeration
  orchestrator/           scheduler, module registry
  module/                 module interface + implementations
    scoutsuite/ bluecloudpeass/ steampipe_insights/ steampipe_perimeter/
    pacu_cognito/ public_amis/ public_snapshots/ apigw_lambda/
    web_identity/ public_rds/ public_ecr/ lambda_env/ ecs_ecr_taskdefs/
  findings/               normalized finding schema + writer
  tui/                    Bubble Tea app
  report/                 embedded SPA + JSON API
  awsapi/                 aws-sdk-go-v2 client factory
Dockerfile
```

## Module interface

```go
type Module interface {
    Name() string
    Kind() Kind                 // external-tool | native-check
    Requires() []string
    Run(ctx context.Context, target AccountTarget, sink Sink) error
}
```

Add a new check by dropping a package under `internal/module/` and registering it in `internal/module/registry.go`.

## Data model

Findings are written to SQLite with the shape:

```
account_id, region, module, severity, resource_arn,
title, detail_json, raw_output_ref, created_at
```

Raw tool output (ScoutSuite JSON, steampipe results, pacu stdout) is stored as blobs in the same DB and referenced by `raw_output_ref`. One `.db` per engagement — no loose artifacts.

## Verification

1. Unit: module registry, finding round-trip, APIGW wildcard analyzer table-driven tests.
2. Smoke against a throwaway account: `scan` populates SQLite, `report` renders, SSO expiry triggers pause + resume.
3. Org mode: run against an account with Organizations access, confirm per-account fan-out.
4. Docker: `docker build && docker run ... scan` reproduces native run.
