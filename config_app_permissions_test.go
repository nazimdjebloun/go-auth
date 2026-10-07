package goauth

import "testing"

func TestAppPermissionConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   AppPermissionsConfig
		invalid bool
	}{
		{"disabled", AppPermissionsConfig{}, false},
		{"enabled", AppPermissionsConfig{Enable: true, EnableManagementHTTP: true}, false},
		{"management without feature", AppPermissionsConfig{EnableManagementHTTP: true}, true},
		{"admin signup default", AppPermissionsConfig{Enable: true, DefaultRoleSlug: "admin"}, true},
		{"noncanonical default", AppPermissionsConfig{Enable: true, DefaultRoleSlug: "Support"}, true},
		{"custom signup default", AppPermissionsConfig{Enable: true, DefaultRoleSlug: "support"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			WithAppPermissions(tc.input)(&cfg)
			cfg.applyAppPermissionDefaults()
			if got := len(cfg.validateAppPermissions()) > 0; got != tc.invalid {
				t.Fatalf("invalid=%v, want %v", got, tc.invalid)
			}
			if tc.input.DefaultRoleSlug == "" && cfg.appPermissions.DefaultRoleSlug != "user" {
				t.Fatal("missing baseline default")
			}
		})
	}
}
