package goauth

// WithMaintenance tunes the background cleanup of expired sessions and
// tokens. Cleanup is on by default; MaintenanceConfig.Disable turns the
// background janitor off while keeping Auth.RunMaintenance available.
func WithMaintenance(cfg MaintenanceConfig) Option {
	return func(c *Config) {
		c.maintenance = cfg
	}
}
