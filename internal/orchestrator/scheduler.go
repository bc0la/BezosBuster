package orchestrator

import (
	"context"
	"fmt"
	"sync"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/engagement"
	"github.com/you/bezosbuster/internal/module"
)

type Options struct {
	PerAccountConcurrency int
	GlobalConcurrency     int
	Modules               []string // if empty, run all registered
	// Done is a set of "account_id|module" pairs that should be skipped
	// entirely (no event, no DB update). Used by `resume`.
	Done map[string]bool
}

type Event struct {
	AccountID string
	Module    string
	Status    string // running | completed | failed | skipped
	Err       string
}

type Scheduler struct {
	eng     *engagement.Engagement
	opts    Options
	Events  chan Event
	watcher *creds.ExpiryWatcher
}

func New(eng *engagement.Engagement, opts Options, w *creds.ExpiryWatcher) *Scheduler {
	if opts.PerAccountConcurrency <= 0 {
		opts.PerAccountConcurrency = 4
	}
	if opts.GlobalConcurrency <= 0 {
		opts.GlobalConcurrency = 16
	}
	return &Scheduler{
		eng:     eng,
		opts:    opts,
		Events:  make(chan Event, 256),
		watcher: w,
	}
}

func (s *Scheduler) modulesToRun() []module.Module {
	if len(s.opts.Modules) == 0 {
		return module.All()
	}
	var out []module.Module
	for _, name := range s.opts.Modules {
		if m, ok := module.Get(name); ok {
			out = append(out, m)
		}
	}
	return out
}

// Run fans out the registered modules across all targets. Returns after
// every module on every account has completed (or failed/skipped).
func (s *Scheduler) Run(ctx context.Context, targets []creds.AccountTarget) error {
	defer close(s.Events)

	modules := s.modulesToRun()
	if len(modules) == 0 {
		return fmt.Errorf("no modules registered")
	}

	global := make(chan struct{}, s.opts.GlobalConcurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		t := t
		_ = s.eng.UpsertAccount(ctx, t.AccountID, t.Alias)
		_ = s.eng.MarkAccount(ctx, t.AccountID, "running", "")

		perAcct := make(chan struct{}, s.opts.PerAccountConcurrency)
		var acctWg sync.WaitGroup

		for _, m := range modules {
			m := m
			if s.opts.Done[t.AccountID+"|"+m.Name()] {
				continue
			}
			acctWg.Add(1)
			wg.Add(1)
			go func() {
				defer acctWg.Done()
				defer wg.Done()
				select {
				case perAcct <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-perAcct }()
				select {
				case global <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-global }()

				if s.watcher != nil && s.watcher.Tripped() {
					s.emit(ctx, t.AccountID, m.Name(), "skipped", "creds expired")
					return
				}

				s.emit(ctx, t.AccountID, m.Name(), "running", "")
				err := m.Run(ctx, t, s.eng)
				if err != nil {
					if creds.IsExpired(err) && s.watcher != nil {
						s.watcher.Trip()
					}
					s.emit(ctx, t.AccountID, m.Name(), "failed", err.Error())
					return
				}
				s.emit(ctx, t.AccountID, m.Name(), "completed", "")
			}()
		}

		go func() {
			acctWg.Wait()
			_ = s.eng.MarkAccount(ctx, t.AccountID, "completed", "")
		}()
	}

	wg.Wait()
	return nil
}

func (s *Scheduler) emit(ctx context.Context, accountID, name, status, errMsg string) {
	_ = s.eng.MarkModule(ctx, accountID, name, status, errMsg)
	select {
	case s.Events <- Event{AccountID: accountID, Module: name, Status: status, Err: errMsg}:
	default:
	}
}
