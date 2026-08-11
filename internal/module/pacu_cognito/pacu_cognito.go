package pacu_cognito

import (
	"context"

	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
	"github.com/bc0la/BezosBuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "pacu_cognito" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"pacu"} }

// pacu-run is a wrapper shell script baked into the Docker image. It
// invokes pacu non-interactively against the named module. Session state
// lives in pacu's own home; we capture stdout/stderr to rawDir.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "pacu_cognito", t, sink, "pacu-run",
		func(_ string) []string { return []string{"--module", "cognito__enum"} })
}
