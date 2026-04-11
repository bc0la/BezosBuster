package pacu_cognito

import (
	"context"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
	"github.com/you/bezosbuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "pacu_cognito" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"pacu"} }

// Invokes pacu in non-interactive mode to run the cognito__enum module.
// pacu is not truly non-interactive, but the Docker image ships with a helper
// script `pacu-run` that wraps it.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "pacu_cognito", t, sink, "pacu-run",
		[]string{"--module", "cognito__enum"})
}
