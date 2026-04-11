package steampipe_perimeter

import (
	"context"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
	"github.com/you/bezosbuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "steampipe_perimeter" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"steampipe"} }

// Runs the mod-aws-perimeter benchmarks, focused on external attack surface.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "steampipe_perimeter", t, sink, "steampipe",
		[]string{"check", "all", "--mod-location", "/root/mods/steampipe-mod-aws-perimeter", "--output", "json"})
}
