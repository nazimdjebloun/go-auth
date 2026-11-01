// Package ratelimitpolicy compiles rate selection and exemptions once at setup.
package ratelimitpolicy

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/internal/routepattern"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// Policy shares ServeMux semantics between rates and exemptions.
type Policy struct {
	rates  *routepattern.Matcher[ratelimit.Rate]
	exempt *routepattern.Matcher[bool]
}

// New validates and snapshots the configuration's route tables.
func New(cfg *ratelimit.Config) (*Policy, error) {
	rates, err := routepattern.New(cfg.Routes)
	if err != nil {
		return nil, err
	}
	values := make(map[string]bool, len(cfg.DisabledRoutes))
	for _, pattern := range cfg.DisabledRoutes {
		values[pattern] = true
	}
	exempt, err := routepattern.New(values)
	if err != nil {
		return nil, err
	}
	return &Policy{rates: rates, exempt: exempt}, nil
}

// Match returns the selected rate and its bounded counter identity. Exemptions
// take precedence and return a zero rate, which skips counters and headers.
func (p *Policy) Match(r *http.Request, fallback ratelimit.Rate, declared string) (ratelimit.Rate, string) {
	if _, pattern, ok := p.exempt.Match(r); ok {
		return ratelimit.Rate{}, pattern
	}
	if rate, pattern, ok := p.rates.Match(r); ok {
		return rate, pattern
	}
	if declared != "" {
		return fallback, declared
	}
	if r.Pattern != "" {
		return fallback, r.Pattern
	}
	return fallback, "*"
}
