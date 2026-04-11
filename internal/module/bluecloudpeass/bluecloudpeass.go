package bluecloudpeass

import (
	"context"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
	"github.com/you/bezosbuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "bluecloudpeass" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"blue-cloudpeass"} }

// Blue-CloudPEASS is distributed as a python script; the Docker image symlinks
// it onto PATH as `blue-cloudpeass`.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "bluecloudpeass", t, sink, "blue-cloudpeass", []string{"--provider", "aws"})
}
