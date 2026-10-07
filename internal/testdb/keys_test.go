package testdb

import (
	"reflect"
	"testing"
)

func TestCheckExpressionsCatalogRewrites(t *testing.T) {
	for _, test := range []struct {
		name, ddl, catalog string
	}{
		{
			name: "mysql_identifiers_and_charset",
			ddl:  `CHECK (system_key IS NULL OR system_key IN ('platform_admin', 'user'))`,
			catalog: "CHECK ((`system_key` is null) or (`system_key` in " +
				`(_utf8mb4\'platform_admin\',_utf8mb4\'user\')))`,
		},
		{
			name:    "mysql_booleans",
			ddl:     `CHECK (NOT is_system OR is_enabled)`,
			catalog: "CHECK (((0 = `is_system`) or (0 <> `is_enabled`)))",
		},
		{
			name: "mysql_namespace",
			ddl:  `CHECK (is_system = (SUBSTR(permission_key, 1, 11) = 'goauth.app.'))`,
			catalog: "CHECK ((`is_system` = (substr(`permission_key`,1,11) = " +
				`_utf8mb4\'goauth.app.\')))`,
		},
		{
			name:    "mysql_revision",
			ddl:     `CHECK (app_role_assignment_revision >= 0) CHECK (id = 1)`,
			catalog: "CHECK ((`id` = 1)) CHECK ((`app_role_assignment_revision` >= 0))",
		},
		{
			name: "postgres_casts_and_array",
			ddl:  `CHECK (revision > 0) CHECK (system_key IS NULL OR system_key IN ('platform_admin', 'user'))`,
			catalog: `CHECK ((revision > '0'::bigint)) CHECK (((system_key IS NULL) OR
				((system_key)::text = ANY (ARRAY['platform_admin'::character varying, 'user'::character varying]::text[]))))`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			want, got := checkExpressions(test.ddl), checkExpressions(test.catalog)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("catalog=%v, DDL=%v", got, want)
			}
		})
	}
}

func TestCheckExpressionsRetainsConstraintDifferences(t *testing.T) {
	for _, test := range []struct{ name, ddl, changed string }{
		{"boolean_polarity", `CHECK (NOT is_system OR is_enabled)`, "CHECK ((0 <> `is_system`) or (0 <> `is_enabled`))"},
		{"revision_operator", `CHECK (revision > 0)`, "CHECK (`revision` >= 0)"},
		{"ownership_namespace", `CHECK (is_system = (SUBSTR(permission_key, 1, 11) = 'goauth.app.'))`,
			"CHECK (`is_system` = (substr(`permission_key`,1,11) = _utf8mb4'goauth.org.'))"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if reflect.DeepEqual(checkExpressions(test.ddl), checkExpressions(test.changed)) {
				t.Fatalf("different constraints compared equal: %s / %s", test.ddl, test.changed)
			}
		})
	}
}
