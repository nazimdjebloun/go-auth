package testdb

import (
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

var tableDefinition = regexp.MustCompile(`(?ms)^CREATE TABLE IF NOT EXISTS ([a-z_]+) \(\n(.*?)^\)`)
var columnDefinition = regexp.MustCompile(`^\s+([a-z_]+) ([A-Z]+(?:\([0-9]+\))?)(.*)`)
var indexDefinition = regexp.MustCompile(`(?m)^CREATE INDEX(?: IF NOT EXISTS)? ([a-z_]+) ON ([a-z_]+)(?: USING ([A-Za-z]+))?\s*\(([^;]+?)\)(?: WHERE ([^;]+))?;`)
var defaultDefinition = regexp.MustCompile(`(?i)DEFAULT\s+(\('(?:''|[^'])*'\)|'(?:''|[^'])*'|[a-z_]+(?:\([0-9]*\))?|[0-9]+)`)
var columnCollation = regexp.MustCompile(`COLLATE ([a-z0-9_]+)`)
var defaultCast = regexp.MustCompile(`::(?:character varying|bigint|integer|text|jsonb)(?:\([0-9]+\))?`)

// AssertSchema checks every canonical table, column, and named index against
// the live catalog, independently of the SQL splitter used for application.
func AssertSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	ddl, err := schema.For(Driver(db))
	if err != nil {
		t.Fatal(err)
	}
	tables := tableDefinition.FindAllStringSubmatch(ddl, -1)
	if len(tables) != 15 {
		t.Fatalf("canonical table inventory = %d, want 15", len(tables))
	}
	for _, table := range tables {
		t.Run(table[1], func(t *testing.T) {
			actual := catalogColumns(t, db, table[1])
			want := 0
			for _, line := range strings.Split(table[2], "\n") {
				col := columnDefinition.FindStringSubmatch(line)
				if col == nil {
					continue
				}
				want++
				got, ok := actual[col[1]]
				if !ok {
					t.Errorf("missing column %s", col[1])
					continue
				}
				decl := col[2] + col[3]
				expectedType := strings.ToLower(col[2])
				if Driver(db) == "postgres" {
					switch expectedType {
					case "timestamptz":
						expectedType = "timestamp with time zone"
					case "int":
						expectedType = "integer"
					default:
					}
					if strings.HasPrefix(expectedType, "varchar") {
						expectedType = strings.Replace(expectedType, "varchar", "character varying", 1)
					}
				}
				if Driver(db) == "mysql" {
					if expectedType == "boolean" {
						expectedType = "tinyint(1)"
					}
					if expectedType == "integer" {
						expectedType = "int"
					}
					if strings.Contains(decl, "UNSIGNED") {
						expectedType += " unsigned"
					}
				}
				if strings.ToLower(got.kind) != expectedType {
					t.Errorf("%s type = %q, want %q", col[1], got.kind, expectedType)
				}
				// SQLite reports an implicit PRIMARY KEY differently from NOT NULL.
				if Driver(db) != "sqlite" || !strings.Contains(decl, "PRIMARY KEY") {
					wantNullable := !strings.Contains(decl, "NOT NULL") && !strings.Contains(decl, "PRIMARY KEY")
					if got.nullable != wantNullable {
						t.Errorf("%s nullable=%v want %v", col[1], got.nullable, wantNullable)
					}
				}
				def := defaultDefinition.FindStringSubmatch(decl)
				if (def != nil) != got.defaultValue.Valid {
					t.Errorf("%s default presence=%v want %v", col[1], got.defaultValue.Valid, def != nil)
				} else if def != nil && normalizeDefault(def[1], expectedType) != normalizeDefault(got.defaultValue.String, expectedType) {
					t.Errorf("%s default=%q want %q", col[1], got.defaultValue.String, def[1])
				}
				if coll := columnCollation.FindStringSubmatch(decl); coll != nil && got.collation != coll[1] {
					t.Errorf("%s collation=%q want %q", col[1], got.collation, coll[1])
				}
			}
			if len(actual) != want {
				t.Errorf("column count=%d want %d", len(actual), want)
			}
		})
	}
	indexes := indexDefinition.FindAllStringSubmatch(ddl, -1)
	if len(indexes) < 30 {
		t.Fatalf("incomplete named-index inventory: %d", len(indexes))
	}
	for _, idx := range indexes {
		t.Run(idx[1], func(t *testing.T) {
			want := make([]string, 0)
			cols := catalogColumns(t, db, idx[2])
			for _, part := range strings.Split(idx[4], ",") {
				part = strings.TrimSpace(part)
				if Driver(db) == "mysql" {
					// MySQL omits SUB_PART when a VARCHAR prefix spans its full width.
					for name, col := range cols {
						if col.kind == "varchar"+strings.TrimPrefix(part, name) && strings.HasPrefix(part, name+"(") {
							part = name
						}
					}
				}
				want = append(want, strings.ToLower(part))
			}
			got, unique, predicate, method := catalogIndex(t, db, idx[2], idx[1])
			if !reflect.DeepEqual(got, want) {
				t.Errorf("index columns=%v want %v", got, want)
			}
			if unique {
				t.Error("ordinary canonical index unexpectedly unique")
			}
			wantMethod := strings.ToLower(idx[3])
			if wantMethod == "" {
				wantMethod = "btree"
			}
			if method != wantMethod {
				t.Errorf("index access method=%q want %q", method, wantMethod)
			}
			if (predicate != "") != (idx[5] != "") {
				t.Errorf("partial predicate=%q want %q", predicate, idx[5])
			}
			if idx[5] != "" {
				normalize := func(s string) string {
					s = strings.ReplaceAll(s, "::text", "")
					s = strings.NewReplacer("(", "", ")", "", " ", "", "\n", "").Replace(s)
					return strings.ToLower(s)
				}
				if normalize(predicate) != normalize(idx[5]) {
					t.Errorf("predicate=%q want %q", predicate, idx[5])
				}
			}
		})
	}
}

type columnInfo struct {
	kind         string
	nullable     bool
	defaultValue sql.NullString
	collation    string
}

func normalizeDefault(value, kind string) string {
	value = defaultCast.ReplaceAllString(strings.TrimSpace(value), "")
	if strings.HasPrefix(value, "_utf8mb4") {
		value = strings.ReplaceAll(strings.TrimPrefix(value, "_utf8mb4"), "\\'", "'")
	}
	for strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	value = strings.Trim(value, "'")
	if kind == "tinyint(1)" {
		if strings.EqualFold(value, "true") {
			return "1"
		}
		if strings.EqualFold(value, "false") {
			return "0"
		}
	}
	if strings.HasPrefix(strings.ToLower(value), "current_timestamp") || strings.EqualFold(value, "now()") || strings.EqualFold(value, "gen_random_uuid()") {
		return strings.TrimSuffix(strings.ToLower(value), "()")
	}
	return value
}

func catalogColumns(t *testing.T, db *sql.DB, table string) map[string]columnInfo {
	t.Helper()
	var query string
	switch Driver(db) {
	case "postgres":
		query = `SELECT a.attname, format_type(a.atttypid,a.atttypmod), NOT a.attnotnull, pg_get_expr(d.adbin,d.adrelid),COALESCE(coll.collname,'') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum LEFT JOIN pg_collation coll ON coll.oid=a.attcollation WHERE n.nspname='public' AND c.relname=? AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`
	case "mysql":
		query = `SELECT column_name,column_type,is_nullable='YES',column_default,COALESCE(collation_name,'') FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? ORDER BY ordinal_position`
	default:
		query = `SELECT name,type,"notnull"=0,dflt_value,'' FROM pragma_table_info(?) ORDER BY cid`
	}
	rows, err := db.QueryContext(t.Context(), SQL(db, query), table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}()
	result := make(map[string]columnInfo)
	for rows.Next() {
		var name string
		var c columnInfo
		if err := rows.Scan(&name, &c.kind, &c.nullable, &c.defaultValue, &c.collation); err != nil {
			t.Fatal(err)
		}
		result[name] = c
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func catalogIndex(t *testing.T, db *sql.DB, table, name string) ([]string, bool, string, string) {
	t.Helper()
	var columnsQuery, propertiesQuery string
	var args []any
	switch Driver(db) {
	case "postgres":
		columnsQuery = `SELECT pg_get_indexdef(c.oid,k.ord::int,TRUE) || CASE WHEN NOT op.opcdefault THEN ' ' || op.opcname ELSE '' END || CASE WHEN (i.indoption[(k.ord-1)::int] & 1)=1 THEN ' DESC' ELSE '' END FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_opclass op ON op.oid=i.indclass[(k.ord-1)::int] WHERE n.nspname='public' AND c.relname=? ORDER BY k.ord`
		propertiesQuery = `SELECT i.indisunique,COALESCE(pg_get_expr(i.indpred,i.indrelid),''),am.amname FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_am am ON am.oid=c.relam WHERE n.nspname='public' AND c.relname=?`
		args = []any{name}
	case "mysql":
		columnsQuery = `SELECT CONCAT(IF(sub_part IS NULL,column_name,CONCAT(column_name,'(',sub_part,')')),IF(collation='D',' DESC','')) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=? ORDER BY seq_in_index`
		propertiesQuery = `SELECT non_unique=0,'',LOWER(index_type) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=? LIMIT 1`
		args = []any{table, name}
	default:
		columnsQuery = `SELECT name || CASE WHEN coll!='BINARY' THEN ' COLLATE ' || coll ELSE '' END || CASE WHEN "desc" THEN ' DESC' ELSE '' END FROM pragma_index_xinfo(?) WHERE "key" ORDER BY seqno`
		propertiesQuery = `SELECT "unique", CASE WHEN partial THEN (SELECT substr(sql,instr(sql,' WHERE ')+7) FROM sqlite_master WHERE name=?) ELSE '' END,'btree' FROM pragma_index_list(?) WHERE name=?`
		args = []any{name}
	}
	rows, err := db.QueryContext(t.Context(), SQL(db, columnsQuery), args...)
	if err != nil {
		t.Fatal(err)
	}
	var columns []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		columns = append(columns, strings.ToLower(col))
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	var unique bool
	var predicate string
	var method string
	if Driver(db) == "sqlite" {
		args = []any{name, table, name}
	}
	if err := db.QueryRowContext(t.Context(), SQL(db, propertiesQuery), args...).Scan(&unique, &predicate, &method); err != nil {
		t.Fatal(fmt.Errorf("index %s: %w", name, err))
	}
	return columns, unique, predicate, method
}
