package bluecloudpeass

import (
	"context"
	"path/filepath"
	"time"

	"github.com/bc0la/BezosBuster/internal/creds"
	"github.com/bc0la/BezosBuster/internal/findings"
	"github.com/bc0la/BezosBuster/internal/module"
	"github.com/bc0la/BezosBuster/internal/module/exttool"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string       { return "bluecloudpeass" }
func (Module) Kind() module.Kind  { return module.KindExternal }
func (Module) Requires() []string { return []string{"blue-cloudpeass"} }

// Blue-AWSPEAS picks up credentials from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
// env vars injected by exttool. Output goes to stdout → stdout.log.
//
// Bounded to 30 minutes: AWSPEAS enumerates a lot and can stall on a slow or
// throttled account; the deadline group-kills it so it can't wedge collect.
func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	return exttool.RunWithTimeout(ctx, "bluecloudpeass", t, sink, "blue-cloudpeass", 30*time.Minute,
		func(rawDir string) []string {
			return []string{"--out-json", filepath.Join(rawDir, "results.json")}
		})
}
