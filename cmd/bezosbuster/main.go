package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/engagement"
	"github.com/you/bezosbuster/internal/module"
	"github.com/you/bezosbuster/internal/orchestrator"
	"github.com/you/bezosbuster/internal/report"
	"github.com/you/bezosbuster/internal/tui"

	// Side-effect imports to register modules.
	_ "github.com/you/bezosbuster/internal/module/apigw_lambda"
	_ "github.com/you/bezosbuster/internal/module/bluecloudpeass"
	_ "github.com/you/bezosbuster/internal/module/ecs_ecr_taskdefs"
	_ "github.com/you/bezosbuster/internal/module/iam_integrations"
	_ "github.com/you/bezosbuster/internal/module/lambda_env"
	_ "github.com/you/bezosbuster/internal/module/pacu_cognito"
	_ "github.com/you/bezosbuster/internal/module/public_amis"
	_ "github.com/you/bezosbuster/internal/module/public_ecr"
	_ "github.com/you/bezosbuster/internal/module/public_rds"
	_ "github.com/you/bezosbuster/internal/module/public_snapshots"
	_ "github.com/you/bezosbuster/internal/module/scoutsuite"
	_ "github.com/you/bezosbuster/internal/module/steampipe_perimeter"
	_ "github.com/you/bezosbuster/internal/module/web_identity"
)

func main() {
	root := &cobra.Command{
		Use:   "bezosbuster",
		Short: "Automated AWS whitebox pentest workflow",
	}
	root.AddCommand(
		runCmd("scan", "Run native AWS-SDK checks (fast, in-process)", "native"),
		runCmd("collect", "Run external tools (ScoutSuite, Steampipe mods, Pacu, Blue-CloudPEASS)", "external"),
		reportCmd(), modulesCmd(), resumeCmd(), steampipeCmd(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runCmd builds either the `scan` (kind=native) or `collect` (kind=external)
// subcommand. They share all flags; only the kind filter differs.
func runCmd(use, short, kind string) *cobra.Command {
	var (
		profile    string
		profiles   []string
		org        bool
		assumeRole string
		region     string
		outDir     string
		engDir     string
		moduleList []string
		noTUI      bool
	)
	c := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			targets, err := creds.Detect(ctx, creds.Options{
				Profile:    profile,
				Profiles:   profiles,
				Org:        org,
				AssumeRole: assumeRole,
				Region:     region,
			})
			if err != nil {
				return fmt.Errorf("detect creds: %w", err)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no accounts detected")
			}

			// Resolve final module list using the kind filter + user subset.
			modules := selectModules(kind, moduleList)
			if len(modules) == 0 {
				return fmt.Errorf("no %s modules to run", kind)
			}

			// Engagement directory: existing one if --engagement was given,
			// otherwise a new timestamped one.
			finalDir := engDir
			if finalDir == "" {
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return err
				}
				finalDir = filepath.Join(outDir, fmt.Sprintf("%s-%s", time.Now().UTC().Format("2006-01-02-150405"), targets[0].AccountID))
			}
			eng, err := engagement.Open(finalDir)
			if err != nil {
				return err
			}
			defer eng.Close()
			_ = eng.SetMeta(ctx, "started_at", time.Now().UTC().Format(time.RFC3339))
			_ = eng.SetMeta(ctx, "targets", strings.Join(targetIDs(targets), ","))
			_ = eng.SetMeta(ctx, "opt.profile", profile)
			_ = eng.SetMeta(ctx, "opt.profiles", strings.Join(profiles, ","))
			_ = eng.SetMeta(ctx, "opt.org", boolStr(org))
			_ = eng.SetMeta(ctx, "opt.assume_role", assumeRole)
			_ = eng.SetMeta(ctx, "opt.region", region)
			_ = eng.SetMeta(ctx, "opt.kind", kind)
			_ = eng.SetMeta(ctx, "opt.modules", strings.Join(moduleList, ","))

			return runEngagement(ctx, eng, targets, modules, nil, noTUI)
		},
	}
	c.Flags().StringVar(&profile, "profile", "", "AWS profile (single-account mode)")
	c.Flags().StringSliceVar(&profiles, "profiles", nil, "Comma-separated profile list")
	c.Flags().BoolVar(&org, "org", false, "Auto-enumerate Organizations and assume-role into each account")
	c.Flags().StringVar(&assumeRole, "assume-role", "OrganizationAccountAccessRole", "Role name to assume in org mode")
	c.Flags().StringVar(&region, "region", "us-east-1", "Default region for IAM/org calls")
	c.Flags().StringVar(&outDir, "out", "engagements", "Parent dir for new engagements")
	c.Flags().StringVar(&engDir, "engagement", "", "Existing engagement dir to append to (default: create new)")
	c.Flags().StringSliceVar(&moduleList, "modules", nil, "Subset of modules to run (default: all of this kind)")
	c.Flags().BoolVar(&noTUI, "no-tui", false, "Disable TUI; stream events as text")
	return c
}

// selectModules returns the final list of module names to run given a kind
// filter ("native", "external", or "" for all) and an optional explicit
// user subset. If subset is non-empty, it wins (intersected with registry).
func selectModules(kind string, subset []string) []string {
	all := module.All()
	allowedKind := func(k module.Kind) bool {
		switch kind {
		case "native":
			return k == module.KindNative
		case "external":
			return k == module.KindExternal
		default:
			return true
		}
	}
	if len(subset) > 0 {
		var out []string
		for _, name := range subset {
			if m, ok := module.Get(name); ok && allowedKind(m.Kind()) {
				out = append(out, name)
			}
		}
		return out
	}
	var out []string
	for _, m := range all {
		if allowedKind(m.Kind()) {
			out = append(out, m.Name())
		}
	}
	return out
}

func targetIDs(ts []creds.AccountTarget) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.AccountID)
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// runEngagement wires up the scheduler and TUI/non-TUI runners. Shared by
// `scan` and `resume`. `done` is a set of "account|module" pairs to skip.
func runEngagement(ctx context.Context, eng *engagement.Engagement, targets []creds.AccountTarget, moduleList []string, done map[string]bool, noTUI bool) error {
	watcher := &creds.ExpiryWatcher{}
	sched := orchestrator.New(eng, orchestrator.Options{Modules: moduleList, Done: done}, watcher)

	if noTUI {
		go func() {
			for ev := range sched.Events {
				fmt.Printf("[%s] %s/%s %s\n", ev.Status, ev.AccountID, ev.Module, ev.Err)
			}
		}()
		if err := sched.Run(ctx, targets); err != nil {
			return err
		}
		fmt.Printf("engagement dir: %s\n", eng.Dir)
		if watcher.Tripped() {
			fmt.Fprintln(os.Stderr, "WARN: credentials expired mid-scan. Re-login and run `bezosbuster resume "+eng.Dir+"`.")
		}
		return nil
	}

	prog := tea.NewProgram(tui.New(sched.Events))
	errCh := make(chan error, 1)
	go func() { errCh <- sched.Run(ctx, targets) }()
	if _, err := prog.Run(); err != nil {
		return err
	}
	if err := <-errCh; err != nil {
		return err
	}
	fmt.Printf("engagement dir: %s\n", eng.Dir)
	if watcher.Tripped() {
		fmt.Fprintln(os.Stderr, "WARN: credentials expired mid-scan. Re-login and run `bezosbuster resume "+eng.Dir+"`.")
	}
	return nil
}

func reportCmd() *cobra.Command {
	var addr string
	c := &cobra.Command{
		Use:   "report <engagement-dir>",
		Short: "Serve a local web report for an engagement directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return report.Serve(addr, args[0])
		},
	}
	c.Flags().StringVar(&addr, "addr", "127.0.0.1:7979", "Listen address")
	return c
}

func modulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "modules",
		Short: "List registered modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, m := range module.All() {
				fmt.Printf("%-22s %s\n", m.Name(), m.Kind())
			}
			return nil
		},
	}
}

// steampipeCmd runs `steampipe dashboard` in the foreground against the
// aws-insights mod. It accepts the same credential options as scan/collect
// (single profile, profile list, or full org enumerate) and generates a
// steampipe aws plugin connection config with one connection per detected
// account plus an aggregator connection (aws_bb_all) that lets you query
// every account in one statement, e.g.
//
//	select account_id, name from aws_bb_all.aws_s3_bucket where bucket_policy_is_public;
//
// The dashboard listens on 0.0.0.0:9194 inside the container; map it with
// `docker run -p 9194:9194`.
func steampipeCmd() *cobra.Command {
	var (
		profile    string
		profiles   []string
		org        bool
		assumeRole string
		region     string
		mod        string
	)
	c := &cobra.Command{
		Use:   "steampipe",
		Short: "Run steampipe dashboard in-container for live multi-account browsing",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			targets, err := creds.Detect(ctx, creds.Options{
				Profile:    profile,
				Profiles:   profiles,
				Org:        org,
				AssumeRole: assumeRole,
				Region:     region,
			})
			if err != nil {
				return fmt.Errorf("detect creds: %w", err)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no accounts detected")
			}

			binary, err := exec.LookPath("steampipe")
			if err != nil {
				return fmt.Errorf("steampipe not on PATH — run inside the bezosbuster Docker image: %w", err)
			}

			cfgPath, err := writeSteampipeAWSConfig(ctx, targets)
			if err != nil {
				return fmt.Errorf("write steampipe config: %w", err)
			}
			fmt.Printf("wrote steampipe aws config: %s\n", cfgPath)
			for _, t := range targets {
				fmt.Printf("  connection aws_bb_%s  (%s)\n", t.AccountID, t.Alias)
			}
			fmt.Println("aggregator: aws_bb_all  — e.g. select * from aws_bb_all.aws_account")
			fmt.Println("starting steampipe dashboard on :9194 (open http://127.0.0.1:9194)")

			scmd := exec.CommandContext(ctx, binary, "dashboard",
				"--mod-location", mod,
				"--dashboard-listen", "network",
				"--dashboard-port", "9194",
			)
			scmd.Stdout = os.Stdout
			scmd.Stderr = os.Stderr
			scmd.Env = os.Environ()
			return scmd.Run()
		},
	}
	c.Flags().StringVar(&profile, "profile", "", "AWS profile (single-account mode)")
	c.Flags().StringSliceVar(&profiles, "profiles", nil, "Comma-separated profile list")
	c.Flags().BoolVar(&org, "org", false, "Auto-enumerate Organizations and assume-role into each account")
	c.Flags().StringVar(&assumeRole, "assume-role", "OrganizationAccountAccessRole", "Role name to assume in org mode")
	c.Flags().StringVar(&region, "region", "us-east-1", "Default region for IAM/org calls")
	c.Flags().StringVar(&mod, "mod", "/home/bb/mods/steampipe-mod-aws-perimeter", "Steampipe mod location")
	return c
}

// writeSteampipeAWSConfig emits one steampipe aws plugin connection per
// target plus an aggregator. Concrete credentials (including session
// tokens for assumed roles) are resolved now and embedded in the config.
// The file is written to ~/.steampipe/config/bezosbuster-aws.spc with
// 0600 permissions.
func writeSteampipeAWSConfig(ctx context.Context, targets []creds.AccountTarget) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	cfgDir := filepath.Join(home, ".steampipe", "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return "", err
	}
	cfgPath := filepath.Join(cfgDir, "bezosbuster-aws.spc")

	var b strings.Builder
	b.WriteString("# generated by bezosbuster steampipe — do not edit\n\n")
	for _, t := range targets {
		v, err := t.Config.Credentials.Retrieve(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip account %s: %v\n", t.AccountID, err)
			continue
		}
		fmt.Fprintf(&b, "connection \"aws_bb_%s\" {\n", t.AccountID)
		b.WriteString("  plugin        = \"aws\"\n")
		fmt.Fprintf(&b, "  access_key    = %q\n", v.AccessKeyID)
		fmt.Fprintf(&b, "  secret_key    = %q\n", v.SecretAccessKey)
		if v.SessionToken != "" {
			fmt.Fprintf(&b, "  session_token = %q\n", v.SessionToken)
		}
		b.WriteString("  regions       = [\"*\"]\n")
		b.WriteString("}\n\n")
	}
	b.WriteString("connection \"aws_bb_all\" {\n")
	b.WriteString("  plugin      = \"aws\"\n")
	b.WriteString("  type        = \"aggregator\"\n")
	b.WriteString("  connections = [\"aws_bb_*\"]\n")
	b.WriteString("}\n")

	if err := os.WriteFile(cfgPath, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return cfgPath, nil
}

func resumeCmd() *cobra.Command {
	var noTUI bool
	c := &cobra.Command{
		Use:   "resume <engagement-dir>",
		Short: "Resume an engagement whose scan was paused or interrupted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			dbFile := filepath.Join(args[0], engagement.DBFileName)
			if _, err := os.Stat(dbFile); err != nil {
				return fmt.Errorf("engagement db not found at %s: %w", dbFile, err)
			}
			eng, err := engagement.Open(args[0])
			if err != nil {
				return err
			}
			defer eng.Close()

			opts, err := readScanOpts(ctx, eng)
			if err != nil {
				return err
			}

			targets, err := creds.Detect(ctx, opts.cred)
			if err != nil {
				return fmt.Errorf("detect creds: %w (hint: run `aws sso login` then retry)", err)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no accounts detected on resume")
			}

			done, err := eng.CompletedModules(ctx)
			if err != nil {
				return err
			}

			modules := selectModules(opts.kind, opts.modules)
			remaining := 0
			for _, t := range targets {
				for _, name := range modules {
					if !done[t.AccountID+"|"+name] {
						remaining++
					}
				}
			}
			fmt.Printf("resume (%s): %d targets × %d modules, %d pairs already complete, %d to run\n",
				orDefault(opts.kind, "all"), len(targets), len(modules), len(done), remaining)
			if remaining == 0 {
				fmt.Println("nothing to do.")
				return nil
			}

			return runEngagement(ctx, eng, targets, modules, done, noTUI)
		},
	}
	c.Flags().BoolVar(&noTUI, "no-tui", false, "Disable TUI; stream events as text")
	return c
}

type scanOpts struct {
	cred    creds.Options
	kind    string
	modules []string
}

func readScanOpts(ctx context.Context, eng *engagement.Engagement) (scanOpts, error) {
	get := func(k string) string {
		v, _, _ := eng.GetMeta(ctx, k)
		return v
	}
	var out scanOpts
	out.cred.Profile = get("opt.profile")
	if v := get("opt.profiles"); v != "" {
		out.cred.Profiles = strings.Split(v, ",")
	}
	out.cred.Org = get("opt.org") == "true"
	out.cred.AssumeRole = get("opt.assume_role")
	out.cred.Region = get("opt.region")
	out.kind = get("opt.kind")
	if v := get("opt.modules"); v != "" {
		out.modules = strings.Split(v, ",")
	}
	return out, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
