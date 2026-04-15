package bluecloudpeass

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

func (Module) Name() string       { return "bluecloudpeass" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"blue-cloudpeass"} }

// Blue-AWSPEAS picks up credentials from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
// env vars injected by exttool. Output goes to stdout → stdout.log.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.Run(ctx, "bluecloudpeass", t, sink, "blue-cloudpeass",
		func(rawDir string) []string {
			return []string{"--out-json", filepath.Join(rawDir, "results.json")}
		})
}
