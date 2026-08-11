package steampipe_perimeter

import (
	"context"
	"path/filepath"

	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
	"github.com/bc0la/BezosBuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "steampipe_perimeter" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"powerpipe-run"} }

// Runs the mod-aws-perimeter benchmarks and exports results to
// <rawDir>/results.json.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "steampipe_perimeter", t, sink, "powerpipe-run",
		func(rawDir string) []string {
			return []string{
				"benchmark", "run", "all",
				"--mod-location", "/home/bb/mods/steampipe-mod-aws-perimeter",
				"--export", filepath.Join(rawDir, "results.json"),
			}
		})
}
