package steampipe_insights

import (
	"context"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
	"github.com/you/bezosbuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "steampipe_insights" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"steampipe"} }

// Runs `steampipe check all` against the aws-insights mod. The image is
// expected to have the mod installed under /root/.steampipe/mods.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "steampipe_insights", t, sink, "steampipe",
		[]string{"check", "all", "--mod-location", "/home/bb/mods/steampipe-mod-aws-insights", "--output", "json"})
}
