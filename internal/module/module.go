package module

import (
	"context"
	"sync"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
)

type Kind string

const (
	KindNative   Kind = "native"
	KindExternal Kind = "external"
)

// Module is the unit of work the orchestrator runs per account.
type Module interface {
	Name() string
	Kind() Kind
	Requires() []string
	Run(ctx context.Context, target creds.AccountTarget, sink findings.Sink) error
}

var (
	regMu    sync.RWMutex
	registry = map[string]Module{}
)

// Register adds a module. Call from package init functions.
func Register(m Module) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, ok := registry[m.Name()]; ok {
		panic("module already registered: " + m.Name())
	}
	registry[m.Name()] = m
}

// All returns a snapshot of the registered modules.
func All() []Module {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Module, 0, len(registry))
	for _, m := range registry {
		out = append(out, m)
	}
	return out
}

// Get returns a module by name.
func Get(name string) (Module, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	m, ok := registry[name]
	return m, ok
}
