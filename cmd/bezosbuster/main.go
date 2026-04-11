package main

import (
	"context"
	"fmt"
	"os"
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
	_ "github.com/you/bezosbuster/internal/module/lambda_env"
	_ "github.com/you/bezosbuster/internal/module/pacu_cognito"
	_ "github.com/you/bezosbuster/internal/module/public_amis"
	_ "github.com/you/bezosbuster/internal/module/public_ecr"
	_ "github.com/you/bezosbuster/internal/module/public_rds"
	_ "github.com/you/bezosbuster/internal/module/public_snapshots"
	_ "github.com/you/bezosbuster/internal/module/scoutsuite"
	_ "github.com/you/bezosbuster/internal/module/steampipe_insights"
	_ "github.com/you/bezosbuster/internal/module/steampipe_perimeter"
	_ "github.com/you/bezosbuster/internal/module/web_identity"
)

func main() {
	root := &cobra.Command{
		Use:   "bezosbuster",
		Short: "Automated AWS whitebox pentest workflow",
	}
	root.AddCommand(scanCmd(), reportCmd(), modulesCmd(), resumeCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var (
		profile    string
		profiles   []string
		org        bool
		assumeRole string
		region     string
		outDir     string
		moduleList []string
		noTUI      bool
	)
	c := &cobra.Command{
		Use:   "scan",
		Short: "Run all modules against one or more AWS accounts",
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

			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			dbPath := filepath.Join(outDir, fmt.Sprintf("%s-%s.db", time.Now().UTC().Format("2006-01-02-150405"), targets[0].AccountID))
			eng, err := engagement.Open(dbPath)
			if err != nil {
				return err
			}
			defer eng.Close()
			_ = eng.SetMeta(ctx, "started_at", time.Now().UTC().Format(time.RFC3339))
			_ = eng.SetMeta(ctx, "targets", strings.Join(targetIDs(targets), ","))

			// Persist scan options so `resume` can reuse them.
			_ = eng.SetMeta(ctx, "opt.profile", profile)
			_ = eng.SetMeta(ctx, "opt.profiles", strings.Join(profiles, ","))
			_ = eng.SetMeta(ctx, "opt.org", boolStr(org))
			_ = eng.SetMeta(ctx, "opt.assume_role", assumeRole)
			_ = eng.SetMeta(ctx, "opt.region", region)
			_ = eng.SetMeta(ctx, "opt.modules", strings.Join(moduleList, ","))

			return runEngagement(ctx, eng, targets, moduleList, nil, noTUI)
		},
	}
	c.Flags().StringVar(&profile, "profile", "", "AWS profile (single-account mode)")
	c.Flags().StringSliceVar(&profiles, "profiles", nil, "Comma-separated profile list")
	c.Flags().BoolVar(&org, "org", false, "Auto-enumerate Organizations and assume-role into each account")
	c.Flags().StringVar(&assumeRole, "assume-role", "OrganizationAccountAccessRole", "Role name to assume in org mode")
	c.Flags().StringVar(&region, "region", "us-east-1", "Default region for IAM/org calls")
	c.Flags().StringVar(&outDir, "out", "engagements", "Engagement output directory")
	c.Flags().StringSliceVar(&moduleList, "modules", nil, "Subset of modules to run (default: all)")
	c.Flags().BoolVar(&noTUI, "no-tui", false, "Disable TUI; stream events as text")
	return c
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
		fmt.Printf("engagement db: %s\n", eng.Path)
		if watcher.Tripped() {
			fmt.Fprintln(os.Stderr, "WARN: credentials expired mid-scan. Re-login and run `bezosbuster resume "+eng.Path+"`.")
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
	fmt.Printf("engagement db: %s\n", eng.Path)
	if watcher.Tripped() {
		fmt.Fprintln(os.Stderr, "WARN: credentials expired mid-scan. Re-login and run `bezosbuster resume "+eng.Path+"`.")
	}
	return nil
}

func reportCmd() *cobra.Command {
	var addr string
	c := &cobra.Command{
		Use:   "report <engagement.db>",
		Short: "Serve a local web report for an engagement SQLite file",
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

func resumeCmd() *cobra.Command {
	var noTUI bool
	c := &cobra.Command{
		Use:   "resume <engagement.db>",
		Short: "Resume an engagement whose scan was paused or interrupted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			if _, err := os.Stat(args[0]); err != nil {
				return fmt.Errorf("engagement db not found: %w", err)
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
			remaining := 0
			modCount := len(module.All())
			if len(opts.modules) > 0 {
				modCount = len(opts.modules)
			}
			for _, t := range targets {
				for _, m := range module.All() {
					if len(opts.modules) > 0 && !contains(opts.modules, m.Name()) {
						continue
					}
					if !done[t.AccountID+"|"+m.Name()] {
						remaining++
					}
				}
			}
			fmt.Printf("resume: %d targets × %d modules, %d pairs already complete, %d to run\n",
				len(targets), modCount, len(done), remaining)
			if remaining == 0 {
				fmt.Println("nothing to do.")
				return nil
			}

			return runEngagement(ctx, eng, targets, opts.modules, done, noTUI)
		},
	}
	c.Flags().BoolVar(&noTUI, "no-tui", false, "Disable TUI; stream events as text")
	return c
}

type scanOpts struct {
	cred    creds.Options
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
