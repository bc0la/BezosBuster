package steampipe_insights

import (
	"context"
	"path/filepath"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
	"github.com/you/bezosbuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "steampipe_insights" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"powerpipe"} }

// Runs `powerpipe benchmark run all` against steampipe-mod-aws-insights,
// exporting the full JSON results to <rawDir>/results.json alongside
// stdout/stderr.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "steampipe_insights", t, sink, "powerpipe",
		func(rawDir string) []string {
			return []string{
				"benchmark", "run", "all",
				"--mod-location", "/home/bb/mods/steampipe-mod-aws-insights",
				"--export", filepath.Join(rawDir, "results.json"),
			}
		})
}
