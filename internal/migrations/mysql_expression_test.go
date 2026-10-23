package migrations

import "testing"

func TestMySQLCheckExpression(t *testing.T) {
	for _, test := range []struct {
		name, authored, live string
		equal                bool
	}{
		{
			name:     "namespace literal metadata",
			authored: "is_system = (substr(permission_key, 1, 11) = 'goauth.app.')",
			live:     "(`is_system` = (substr(`permission_key`,1,11) = _utf8mb4\\'goauth.app.\\'))", equal: true,
		},
		{
			name: "boolean truth predicates", authored: "NOT is_system OR is_enabled",
			live: "((0 = `is_system`) or (0 <> `is_enabled`))", equal: true,
		},
		{
			name: "right zero predicates", authored: "NOT is_system OR is_enabled",
			live: "((`is_system` = 0) or (`is_enabled` <> 0))", equal: true,
		},
		{
			name: "latin1 literal introducers", authored: "system_key IS NULL OR system_key IN ('platform_admin', 'user')",
			live: "(`system_key` is null) or (`system_key` in (_latin1\\'platform_admin\\',_latin1\\'user\\'))", equal: true,
		},
		{
			name: "literal case matters", authored: "permission_key = 'goauth.app.'",
			live: "`permission_key` = _utf8mb4\\'Goauth.app.\\'", equal: false,
		},
		{
			name: "escaped quote", authored: "name = 'O''Brien'",
			live: "`name` = _utf8mb4\\'O\\\\\\'Brien\\'", equal: true,
		},
		{
			name: "escaped backslash", authored: `name = 'a\\b'`,
			live: "`name` = _utf8mb4\\'a\\\\\\\\b\\'", equal: true,
		},
		{
			name: "scalar comparisons are preserved", authored: "is_system = (is_enabled <> 0)",
			live: "is_system = is_enabled", equal: false,
		},
		{
			name: "boolean precedence matters", authored: "a OR b AND c",
			live: "(a OR b) AND c", equal: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			want, err := parseExpression(test.authored, true)
			if err != nil {
				t.Fatal(err)
			}
			got, err := mysqlCheckExpression(test.live)
			if err != nil {
				t.Fatal(err)
			}
			if (got == want) != test.equal {
				t.Fatalf("unexpected CHECK equivalence: authored=%s live=%s", want, got)
			}
		})
	}
}

func TestMySQLCheckExpressionRejectsMalformedEscapes(t *testing.T) {
	for _, check := range []string{
		`name = \`, `name = \q`, `name = \'unfinished`, `name = \'a\\q\'`,
	} {
		t.Run(check, func(t *testing.T) {
			if _, err := mysqlCheckExpression(check); err == nil {
				t.Fatal("malformed CHECK metadata was accepted")
			}
		})
	}
}

func TestMySQLExpressionDefaultsPreserveLiteralValues(t *testing.T) {
	for _, test := range []struct {
		name, authored, live string
	}{
		{"empty text", "('')", "_utf8mb4\\'\\'"},
		{"mixed case", "('CaseSensitive')", "_utf8mb4\\'CaseSensitive\\'"},
		{"escaped quote", "('O''Brien')", "_utf8mb4\\'O\\\\\\'Brien\\'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			want, err := normalizeDefault("mysql", "text", test.authored, false)
			if err != nil {
				t.Fatal(err)
			}
			got, err := normalizeDefault("mysql", "text", test.live, true)
			if err != nil || got != want {
				t.Fatalf("expression default changed: got=%q want=%q err=%v", got, want, err)
			}
		})
	}
}
