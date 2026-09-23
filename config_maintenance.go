package goauth

import (
	"errors"
	"log/slog"
	"time"
)

// Maintenance tuning defaults. The janitor is on by default because expired
// sessions and tokens are unusable by construction — leaving them behind only
// grows the tables that every session lookup reads. Cleanup is deliberately
// conservative: rows are only eligible once they are past expiry by Grace.
const (
	DefaultMaintenanceInterval  = time.Hour
	DefaultMaintenanceBatchSize = 1000
	DefaultMaintenanceGrace     = 24 * time.Hour
	DefaultMaintenanceTimeout   = 30 * time.Second
)

// MaintenanceConfig configures background cleanup of expired sessions and
// verification/reset tokens.
//
// The background janitor is enabled by default. It only ever deletes rows
// that are already dead — a session must be past its own expiry AND past (or
// missing) its refresh expiry, and a token must be past its expiry, each by
// at least Grace. No live credential is ever removed, so the default is safe
// to leave alone.
type MaintenanceConfig struct {
	// Disable turns off the background janitor. The manual entry point,
	// Auth.RunMaintenance, keeps working either way, so an operator can run
	// cleanup from their own scheduler instead.
	//
	// Spelled as "Disable" so the zero value keeps cleanup running; set it
	// when another process owns database maintenance.
	Disable bool

	// Interval is how often a pass runs. 0 means DefaultMaintenanceInterval.
	Interval time.Duration

	// BatchSize caps how many rows one pass deletes per table, which bounds
	// how long a single statement holds locks on a busy database. Passes
	// repeat at Interval, so a large backlog drains over several cycles
	// instead of one long transaction. 0 means DefaultMaintenanceBatchSize.
	BatchSize int

	// Grace is how far past expiry a row must be before it is eligible.
	// 0 means DefaultMaintenanceGrace (24h). Negative is rejected.
	Grace time.Duration

	// Timeout bounds one table's delete statement. 0 means
	// DefaultMaintenanceTimeout.
	Timeout time.Duration

	// Logger receives per-pass diagnostics. Nil means slog.Default().
	Logger *slog.Logger
}

// validateMaintenance rejects negative tuning values. Zero means "use the
// documented default" and stays valid.
func (c *Config) validateMaintenance() []error {
	var errs []error
	m := c.maintenance
	if m.Interval < 0 {
		errs = append(errs, errors.New("maintenance interval must not be negative"))
	}
	if m.BatchSize < 0 {
		errs = append(errs, errors.New("maintenance batch_size must not be negative"))
	}
	if m.Grace < 0 {
		errs = append(errs, errors.New("maintenance grace must not be negative"))
	}
	if m.Timeout < 0 {
		errs = append(errs, errors.New("maintenance timeout must not be negative"))
	}
	return errs
}

// withDefaults fills every zero field with its documented default. Called
// during wiring so the runner never has to re-check for zero.
func (c MaintenanceConfig) withDefaults() MaintenanceConfig {
	if c.Interval <= 0 {
		c.Interval = DefaultMaintenanceInterval
	}
	if c.BatchSize <= 0 {
		c.BatchSize = DefaultMaintenanceBatchSize
	}
	if c.Grace == 0 {
		c.Grace = DefaultMaintenanceGrace
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultMaintenanceTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// WithMaintenance tunes the background cleanup of expired sessions and
// tokens. Cleanup is on by default; MaintenanceConfig.Disable turns the
// background janitor off while keeping Auth.RunMaintenance available.
func WithMaintenance(cfg MaintenanceConfig) Option {
	return func(c *Config) {
		c.maintenance = cfg
	}
}
