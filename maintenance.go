package goauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

// MaintenanceResult reports how many fully-expired rows one pass removed.
type MaintenanceResult struct {
	SessionsDeleted int `json:"sessionsDeleted"`
	TokensDeleted   int `json:"tokensDeleted"`
}

// maintenanceTarget is one table's cleanup capability plus where its count
// lands in MaintenanceResult.
type maintenanceTarget struct {
	name    string
	deleter port.ExpiredRowDeleter
	record  func(*MaintenanceResult, int)
}

// collectMaintenanceTargets wires the two SQL-backed cleanup targets.
// Storage is SQL-only, so both repositories always implement
// ExpiredRowDeleter — the parameters are typed as the capability, not
// any, so a repository that stopped implementing it fails the build.
func collectMaintenanceTargets(sessions, tokens port.ExpiredRowDeleter) []maintenanceTarget {
	return []maintenanceTarget{
		{
			name:    "sessions",
			deleter: sessions,
			record:  func(r *MaintenanceResult, n int) { r.SessionsDeleted = n },
		},
		{
			name:    "verification_tokens",
			deleter: tokens,
			record:  func(r *MaintenanceResult, n int) { r.TokensDeleted = n },
		},
	}
}

// maintenanceRunner owns the janitor goroutine and the manual pass entry
// point. It is built whenever there is at least one target; the goroutine
// only starts when the background janitor is enabled.
type maintenanceRunner struct {
	targets []maintenanceTarget
	cfg     MaintenanceConfig
	log     *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newMaintenanceRunner(cfg MaintenanceConfig, targets []maintenanceTarget) *maintenanceRunner {
	cfg = cfg.withDefaults()
	return &maintenanceRunner{targets: targets, cfg: cfg, log: cfg.Logger}
}

// start launches the janitor loop. It uses its own context — not a caller's —
// so a request-scoped context cannot stop background maintenance, and stop()
// cancels exactly this loop.
func (m *maintenanceRunner) start() {
	if len(m.targets) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(m.cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.runPass(ctx)
			}
		}
	}()
}

func (m *maintenanceRunner) stop() {
	if m.cancel == nil {
		return
	}
	m.cancel()
	m.wg.Wait()
	m.cancel = nil
}

// runPass does one bounded delete per target. Failures are logged and
// skipped: cleanup that cannot reach the database must never take down a
// running application, and the next pass retries.
func (m *maintenanceRunner) runPass(ctx context.Context) MaintenanceResult {
	var result MaintenanceResult
	if len(m.targets) == 0 {
		return result
	}
	cutoff := time.Now().UTC().Add(-m.cfg.Grace)
	for _, target := range m.targets {
		actx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
		n, err := target.deleter.DeleteExpiredBatch(actx, cutoff, m.cfg.BatchSize)
		cancel()
		if err != nil {
			m.log.Error("maintenance: expired-row cleanup failed", "table", target.name, "err", err)
			continue
		}
		if n > 0 {
			m.log.Info("maintenance: expired rows removed", "table", target.name, "rows", n)
		}
		target.record(&result, n)
	}
	return result
}

// RunMaintenance runs one maintenance pass immediately and reports what it
// removed. It works whether or not the background janitor is enabled, so a
// deployment that disables the janitor can drive cleanup from its own
// scheduler instead.
//
// It is safe to call concurrently with the background janitor: the
// underlying deletes are bounded and idempotent, so the worst case is two
// passes racing over the same expired rows.
func (a *Auth) RunMaintenance(ctx context.Context) (MaintenanceResult, error) {
	if a.maintenance == nil || len(a.maintenance.targets) == 0 {
		return MaintenanceResult{}, fmt.Errorf("goauth: no maintenance-capable repositories configured")
	}
	return a.maintenance.runPass(ctx), nil
}
