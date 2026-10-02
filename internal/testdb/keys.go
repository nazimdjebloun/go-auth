package testdb

import (
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

var compositePrimary = regexp.MustCompile(`PRIMARY KEY \(([a-z_, ]+)\)`)
var inlineReference = regexp.MustCompile(`(?m)^\s+([a-z_]+) [^\n]*?REFERENCES ([a-z_]+)\(([a-z_]+)\)(?: ON DELETE (CASCADE|SET NULL))?`)
var tableReference = regexp.MustCompile(`FOREIGN KEY \(([a-z_]+)\) REFERENCES ([a-z_]+)\(([a-z_]+)\)(?: ON DELETE (CASCADE|SET NULL))?`)
var checks = regexp.MustCompile(`CHECK\s*\(`)
var checkCast = regexp.MustCompile(`::(?:character varying|bigint|integer|text)(?:\[\])?`)
var checkIn = regexp.MustCompile(`(?i)([a-z_]+) IN \(([^)]+)\)`)
var numericCheckCast = regexp.MustCompile(`'([0-9]+)'::(?:bigint|integer)`)

// AssertKeys checks primary/unique keys, every foreign-key relationship and
// deletion action, and the expressions of explicit CHECK constraints in each DDL.
func AssertKeys(t *testing.T, db *sql.DB) {
	t.Helper()
	ddl, err := schema.For(Driver(db))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tableDefinition.FindAllStringSubmatch(ddl, -1) {
		t.Run(table[1]+"_keys", func(t *testing.T) {
			wantKeys := make(map[string]bool)
			for _, line := range strings.Split(table[2], "\n") {
				col := columnDefinition.FindStringSubmatch(line)
				if col != nil {
					if strings.Contains(col[3], "PRIMARY KEY") {
						wantKeys["PRIMARY KEY:"+col[1]] = true
					}
					if strings.Contains(col[3], "UNIQUE") {
						wantKeys["UNIQUE:"+col[1]] = true
					}
				}
				if match := compositePrimary.FindStringSubmatch(line); match != nil {
					wantKeys["PRIMARY KEY:"+strings.ReplaceAll(match[1], " ", "")] = true
				}
				if strings.HasPrefix(strings.TrimSpace(line), "UNIQUE(") {
					columns := strings.TrimSuffix(strings.TrimPrefix(strings.TrimRight(strings.TrimSpace(line), ","), "UNIQUE("), ")")
					wantKeys["UNIQUE:"+strings.ReplaceAll(columns, " ", "")] = true
				}
			}
			gotKeys := catalogKeys(t, db, table[1])
			if !reflect.DeepEqual(gotKeys, wantKeys) {
				t.Errorf("keys=%v want %v", gotKeys, wantKeys)
			}
			wantFK := make(map[string]string)
			for _, pattern := range []*regexp.Regexp{inlineReference, tableReference} {
				for _, fk := range pattern.FindAllStringSubmatch(table[2], -1) {
					action := fk[4]
					if action == "" {
						action = "RESTRICT"
					}
					wantFK[fk[1]] = fk[2] + "." + fk[3] + ":" + action
				}
			}
			gotFK := catalogForeignKeys(t, db, table[1])
			if !reflect.DeepEqual(gotFK, wantFK) {
				t.Errorf("foreign keys=%v want %v", gotFK, wantFK)
			}
			wantChecks := checkExpressions(table[2])
			if got := catalogChecks(t, db, table[1]); !reflect.DeepEqual(got, wantChecks) {
				t.Errorf("CHECK expressions=%v want %v", got, wantChecks)
			}
		})
	}
}

func catalogKeys(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	result := make(map[string]bool)
	if Driver(db) == "sqlite" {
		rows, err := db.QueryContext(t.Context(), `SELECT name FROM pragma_table_info(?) WHERE pk>0 ORDER BY pk`, table)
		if err != nil {
			t.Fatal(err)
		}
		primary := scanStrings(t, rows)
		if len(primary) > 0 {
			result["PRIMARY KEY:"+strings.Join(primary, ",")] = true
		}
		rows, err = db.QueryContext(t.Context(), `SELECT name FROM pragma_index_list(?) WHERE "unique" AND origin!='pk'`, table)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range scanStrings(t, rows) {
			rows, err = db.QueryContext(t.Context(), `SELECT name FROM pragma_index_info(?) ORDER BY seqno`, name)
			if err != nil {
				t.Fatal(err)
			}
			result["UNIQUE:"+strings.Join(scanStrings(t, rows), ",")] = true
		}
		return result
	}
	scope := "tc.table_schema='public'"
	if Driver(db) == "mysql" {
		scope = "tc.table_schema=DATABASE()"
	}
	query := `SELECT tc.constraint_name,tc.constraint_type,k.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage k ON k.constraint_schema=tc.constraint_schema AND k.constraint_name=tc.constraint_name AND k.table_name=tc.table_name WHERE ` + scope + ` AND tc.table_name=? AND tc.constraint_type IN ('PRIMARY KEY','UNIQUE') ORDER BY tc.constraint_name,k.ordinal_position`
	rows, err := db.QueryContext(t.Context(), SQL(db, query), table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	groups := make(map[string][]string)
	kinds := make(map[string]string)
	for rows.Next() {
		var name, kind, column string
		if err := rows.Scan(&name, &kind, &column); err != nil {
			t.Fatal(err)
		}
		groups[name] = append(groups[name], column)
		kinds[name] = kind
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for name, columns := range groups {
		result[kinds[name]+":"+strings.Join(columns, ",")] = true
	}
	return result
}

func catalogForeignKeys(t *testing.T, db *sql.DB, table string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	var query string
	switch Driver(db) {
	case "sqlite":
		query = `SELECT "from","table","to",on_delete FROM pragma_foreign_key_list(?)`
	case "mysql":
		query = `SELECT k.column_name,k.referenced_table_name,k.referenced_column_name,r.delete_rule FROM information_schema.key_column_usage k JOIN information_schema.referential_constraints r ON r.constraint_schema=k.constraint_schema AND r.constraint_name=k.constraint_name AND r.table_name=k.table_name WHERE k.table_schema=DATABASE() AND k.table_name=? AND k.referenced_table_name IS NOT NULL`
	default:
		query = `SELECT k.column_name,c.table_name,c.column_name,r.delete_rule FROM information_schema.referential_constraints r JOIN information_schema.key_column_usage k ON k.constraint_schema=r.constraint_schema AND k.constraint_name=r.constraint_name JOIN information_schema.constraint_column_usage c ON c.constraint_schema=r.unique_constraint_schema AND c.constraint_name=r.unique_constraint_name WHERE k.table_schema='public' AND k.table_name=?`
	}
	rows, err := db.QueryContext(t.Context(), SQL(db, query), table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var column, parent, target, action string
		if err := rows.Scan(&column, &parent, &target, &action); err != nil {
			t.Fatal(err)
		}
		if action == "NO ACTION" {
			action = "RESTRICT"
		}
		result[column] = parent + "." + target + ":" + action
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func checkExpressions(ddl string) []string {
	var result []string
	for _, match := range checks.FindAllStringIndex(ddl, -1) {
		start := match[1]
		depth := 1
		quoted := false
		for i := start; i < len(ddl); i++ {
			if ddl[i] == '\'' {
				if quoted && i+1 < len(ddl) && ddl[i+1] == '\'' {
					i++
					continue
				}
				quoted = !quoted
			}
			if quoted {
				continue
			}
			if ddl[i] == '(' {
				depth++
			}
			if ddl[i] == ')' {
				depth--
				if depth == 0 {
					expr := numericCheckCast.ReplaceAllString(ddl[start:i], "$1")
					expr = checkCast.ReplaceAllString(expr, "")
					expr = checkIn.ReplaceAllString(expr, "$1=ANY(ARRAY[$2])")
					expr = strings.NewReplacer("(", "", ")", "", " ", "", "\n", "", "\t", "").Replace(expr)
					result = append(result, strings.ToLower(expr))
					break
				}
			}
		}
	}
	sort.Strings(result)
	return result
}

func catalogChecks(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	var query string
	switch Driver(db) {
	case "sqlite":
		var ddl string
		if err := db.QueryRowContext(t.Context(), `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		return checkExpressions(ddl)
	case "mysql":
		query = `SELECT CONCAT('CHECK (',c.check_clause,')') FROM information_schema.table_constraints t JOIN information_schema.check_constraints c ON c.constraint_schema=t.constraint_schema AND c.constraint_name=t.constraint_name WHERE t.table_schema=DATABASE() AND t.table_name=? AND t.constraint_type='CHECK'`
	default:
		query = `SELECT pg_get_constraintdef(co.oid) FROM pg_constraint co JOIN pg_class c ON c.oid=co.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=? AND co.contype='c'`
	}
	rows, err := db.QueryContext(t.Context(), SQL(db, query), table)
	if err != nil {
		t.Fatal(err)
	}
	return checkExpressions(strings.Join(scanStrings(t, rows), "\n"))
}

func scanStrings(t *testing.T, rows *sql.Rows) []string {
	t.Helper()
	var result []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		result = append(result, s)
	}
	err := rows.Err()
	closeErr := rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return result
}

// AssertForeignKeyIntegrity asks SQLite to validate every persisted reference.
// The server engines enforce the same references during each write.
func AssertForeignKeyIntegrity(t *testing.T, db *sql.DB) {
	t.Helper()
	if Driver(db) != "sqlite" {
		return
	}
	rows, err := db.QueryContext(t.Context(), "PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		t.Error("SQLite foreign-key integrity violation")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// TableNames returns sorted canonical names for tests that exercise every table.
func TableNames(driver string) []string {
	ddl, err := schema.For(driver)
	if err != nil {
		panic(fmt.Sprint(err))
	}
	var names []string
	for _, m := range tableDefinition.FindAllStringSubmatch(ddl, -1) {
		names = append(names, m[1])
	}
	sort.Strings(names)
	return names
}
