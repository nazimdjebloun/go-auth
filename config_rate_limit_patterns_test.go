package goauth

import (
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestRateLimitPatternsFailConfiguration(t *testing.T) {
	for _, patterns := range [][]string{
		{"POST /widgets/*"}, {"POST /widgets/{id"},
		{"POST /widgets/{id}", "POST /widgets/{other}"},
	} {
		for _, exemption := range []bool{false, true} {
			rl := *ratelimit.DefaultRateLimitConfig()
			rl.Routes = map[string]ratelimit.Rate{}
			for _, pattern := range patterns {
				if exemption {
					rl.DisabledRoutes = append(rl.DisabledRoutes, pattern)
				} else {
					rl.Routes[pattern] = ratelimit.Rate{Requests: 1, Window: time.Minute}
				}
			}
			if _, err := NewConfig(append(validConfigOpts(), WithRateLimit(rl))...); err == nil {
				t.Errorf("accepted %v, exemption=%t", patterns, exemption)
			}
		}
	}
}
