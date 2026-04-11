package scoutsuite

import (
	"context"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
	"github.com/you/bezosbuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "scoutsuite" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"scout"} }

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "scoutsuite", t, sink, "scout",
		[]string{"aws", "--no-browser", "--force", "--report-dir", "/tmp/scoutsuite-" + t.AccountID})
}
