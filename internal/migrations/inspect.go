package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

func objectExists(ctx context.Context, q queryer, dialect, name string) (bool, error) {
	var count int
	var query string
	switch dialect {
	case "postgres":
		query = "SELECT COUNT(*) FROM pg_class WHERE oid=to_regclass($1)"
	case "mysql":
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?"
	case "sqlite":
		query = "SELECT COUNT(*) FROM main.sqlite_schema WHERE name=?"
	}
	err := q.QueryRowContext(ctx, query, name).Scan(&count)
	return count != 0, err
}

func requireUnused(ctx context.Context, q queryer, dialect, script string) error {
	def, err := parseDefinition(dialect, script)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(def.tables)+len(def.indexes))
	for name := range def.tables {
		names = append(names, name)
	}
	if dialect != "mysql" {
		for name := range def.indexes {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		exists, err := objectExists(ctx, q, dialect, name)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: reserved object %q already exists", ErrUntracked, name)
		}
	}
	return nil
}

func drift(object, detail string) error {
	return fmt.Errorf("%w: %s: %s", ErrDrift, object, detail)
}

func verify(ctx context.Context, q queryer, dialect, script string) error {
	def, err := parseDefinition(dialect, script)
	if err != nil {
		return fmt.Errorf("goauth: invalid published schema snapshot: %w", err)
	}
	if dialect == "sqlite" {
		return verifySQLite(ctx, q, def)
	}
	names := make([]string, 0, len(def.tables))
	for name := range def.tables {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		table := def.tables[name]
		if err := verifyColumns(ctx, q, dialect, table); err != nil {
			return err
		}
		var constraints []string
		if dialect == "postgres" {
			constraints, err = postgresConstraints(ctx, q, name)
		} else {
			constraints, err = mysqlConstraints(ctx, q, name)
		}
		if err != nil {
			return err
		}
		slices.Sort(constraints)
		if !slices.Equal(constraints, table.constraints) {
			return drift(name, "primary, unique, CHECK or foreign-key constraints differ")
		}
		if err := verifyIndexes(ctx, q, dialect, table, def); err != nil {
			return err
		}
		if err := verifyForeignKeyData(ctx, q, dialect, table); err != nil {
			return err
		}
	}
	return nil
}

func normalizedDDL(ddl string) (string, error) {
	tokens, err := tokenize(ddl)
	if err != nil {
		return "", err
	}
	result := make([]string, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		if i+2 < len(tokens) && tokens[i] == "if" && tokens[i+1] == "not" && tokens[i+2] == "exists" {
			i += 2
			continue
		}
		if tokens[i] != ";" {
			result = append(result, tokens[i])
		}
	}
	return strings.Join(result, " "), nil
}

func verifySQLite(ctx context.Context, q queryer, def definition) error {
	rows, err := q.QueryContext(ctx, "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY name")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	found := map[string]bool{}
	for rows.Next() {
		var kind, name, table string
		var ddl sql.NullString
		if err := rows.Scan(&kind, &name, &table, &ddl); err != nil {
			return err
		}
		var expected string
		if spec, ok := def.tables[name]; ok {
			if kind != "table" {
				return drift(name, "reserved name is not a table")
			}
			expected = spec.sql
		} else if idx, ok := def.indexes[name]; ok {
			if kind != "index" || table != idx.table {
				return drift(name, "reserved name is not the expected index")
			}
			actual, err := normalizedDDL(ddl.String)
			if err != nil {
				return err
			}
			// Keep complete index SQL, including predicates and collations.
			var b strings.Builder
			b.WriteString("CREATE ")
			if idx.unique {
				b.WriteString("UNIQUE ")
			}
			fmt.Fprintf(&b, "INDEX %s ON %s (%s)", name, table, strings.Join(idx.columns, ","))
			// The AST predicate is deliberately not converted back to SQL.
			if idx.predicate != "" {
				prefix, predicate, ok := strings.Cut(actual, " where ")
				if !ok {
					return drift(name, "partial-index predicate is missing")
				}
				parsed, err := expression(predicate)
				if err != nil || parsed != idx.predicate {
					return drift(name, "partial-index predicate differs")
				}
				actual = prefix
			}
			want, err := normalizedDDL(b.String())
			if err != nil {
				return err
			}
			if actual != want {
				return drift(name, "index columns, uniqueness, ordering or collation differ")
			}
			found[name] = true
			continue
		} else if _, owned := def.tables[table]; owned {
			// SQLite autoindexes implement the PRIMARY/UNIQUE clauses already
			// checked in the complete CREATE TABLE definition.
			if kind == "index" && !ddl.Valid && strings.HasPrefix(name, "sqlite_autoindex_") {
				continue
			}
			return drift(table, "unexpected index or trigger "+name)
		} else {
			continue
		}
		actual, err := normalizedDDL(ddl.String)
		if err != nil {
			return err
		}
		want, err := normalizedDDL(expected)
		if err != nil {
			return err
		}
		if actual != want {
			return drift(name, "table definition differs from the supported snapshot")
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for name := range def.tables {
		if !found[name] {
			return drift(name, "missing table")
		}
	}
	for name := range def.indexes {
		if !found[name] {
			return drift(name, "missing index")
		}
	}
	return nil
}

func verifyColumns(ctx context.Context, q queryer, dialect string, table *tableSpec) error {
	var query string
	if dialect == "postgres" {
		var kind, persistence string
		var policies, inherited bool
		err := q.QueryRowContext(ctx, `SELECT c.relkind::text,c.relpersistence::text,c.relrowsecurity,
			EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid)
			FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname=current_schema() AND c.relname=$1`, table.name).Scan(&kind, &persistence, &policies, &inherited)
		if errors.Is(err, sql.ErrNoRows) {
			return drift(table.name, "missing table in current_schema()")
		}
		if err != nil {
			return err
		}
		if kind != "r" || persistence != "p" || policies || inherited {
			return drift(table.name, "unexpected table kind, persistence, inheritance or row security")
		}
		query = `SELECT a.attname,format_type(a.atttypid,a.atttypmod),NOT a.attnotnull,
			pg_get_expr(d.adbin,d.adrelid),COALESCE(coll.collname,''),
			a.attgenerated::text || a.attidentity::text,''
			FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
			JOIN pg_namespace n ON n.oid=c.relnamespace
			LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
			LEFT JOIN pg_collation coll ON coll.oid=a.attcollation
			WHERE n.nspname=current_schema() AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`
	} else {
		var kind, engine, collation string
		err := q.QueryRowContext(ctx, `SELECT table_type,COALESCE(engine,''),table_collation FROM information_schema.tables
			WHERE table_schema=DATABASE() AND table_name=?`, table.name).Scan(&kind, &engine, &collation)
		if errors.Is(err, sql.ErrNoRows) {
			return drift(table.name, "missing table")
		}
		if err != nil {
			return err
		}
		if kind != "BASE TABLE" || engine != "InnoDB" || collation != "utf8mb4_unicode_ci" {
			return drift(table.name, "table engine or default collation differs")
		}
		query = `SELECT column_name,column_type,is_nullable='YES',column_default,
			COALESCE(collation_name,''),extra,COALESCE(generation_expression,'')
			FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? ORDER BY ordinal_position`
	}
	rows, err := q.QueryContext(ctx, query, table.name)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	index := 0
	for rows.Next() {
		var name, kind, collation, extra, generated string
		var nullable bool
		var actualDefault sql.NullString
		if err := rows.Scan(&name, &kind, &nullable, &actualDefault, &collation, &extra, &generated); err != nil {
			return err
		}
		if index >= len(table.columns) {
			return drift(table.name, "unexpected column "+name)
		}
		want := table.columns[index]
		index++
		extra = strings.TrimSpace(strings.ReplaceAll(strings.ToLower(extra), "default_generated", ""))
		wantExtra := strings.TrimSuffix(want.extra, "()")
		extra = strings.TrimSuffix(extra, "()")
		if name != want.name || strings.ToLower(kind) != want.kind || nullable != want.nullable {
			return drift(table.name+"."+want.name, "column name, type, ordering or nullability differs")
		}
		if collation != want.collation || extra != wantExtra || generated != "" {
			return drift(table.name+"."+name, "collation, generation or update behavior differs")
		}
		if actualDefault.Valid != (want.defaultSQL != nil) {
			return drift(table.name+"."+name, "default presence differs")
		}
		if want.defaultSQL != nil {
			actual, err := normalizeDefault(dialect, kind, actualDefault.String, true)
			if err != nil {
				return drift(table.name+"."+name, "unsupported live default")
			}
			expected, err := normalizeDefault(dialect, kind, *want.defaultSQL, false)
			if err != nil || actual != expected {
				return drift(table.name+"."+name, "default differs")
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if index != len(table.columns) {
		return drift(table.name, "missing columns")
	}
	return nil
}

func normalizeDefault(dialect, kind, value string, live bool) (string, error) {
	if dialect == "mysql" && live && (strings.HasPrefix(kind, "varchar") || kind == "text") {
		// DEFAULT_GENERATED TEXT defaults retain an expression in MySQL.
		if !strings.HasPrefix(value, "(") && !strings.HasPrefix(value, "'") && !strings.HasPrefix(value, "_utf8mb4") {
			return "'" + strings.ReplaceAll(value, "'", "''") + "'", nil
		}
	}
	value, err := expression(value)
	if err != nil {
		return "", err
	}
	if kind == "tinyint(1)" {
		if value == "true" {
			return "1", nil
		}
		if value == "false" {
			return "0", nil
		}
	}
	if value == "current_timestamp" || value == "current_timestamp()" {
		value = "now()"
	}
	return value, nil
}

func postgresConstraints(ctx context.Context, q queryer, table string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT c.contype::text,c.condeferrable,c.condeferred,c.convalidated,
		COALESCE((to_jsonb(c)->>'conenforced')::boolean,TRUE),
		COALESCE((SELECT string_agg(a.attname,',' ORDER BY k.ord) FROM unnest(c.conkey) WITH ORDINALITY k(num,ord)
		JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num),''),
		COALESCE(f.relname,''),COALESCE(fn.nspname=current_schema(),TRUE),
		COALESCE((SELECT string_agg(a.attname,',' ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(num,ord)
		JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.num),''),
		c.confdeltype::text,c.confupdtype::text,c.confmatchtype::text,COALESCE(pg_get_expr(c.conbin,c.conrelid,TRUE),''),
		COALESCE((SELECT indnullsnotdistinct FROM pg_index WHERE indexrelid=c.conindid),FALSE)
		FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
		LEFT JOIN pg_class f ON f.oid=c.confrelid LEFT JOIN pg_namespace fn ON fn.oid=f.relnamespace
		WHERE n.nspname=current_schema() AND t.relname=$1 AND c.contype!='n'`, table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := []string{}
	actions := map[string]string{"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT"}
	for rows.Next() {
		var kind, columns, target, keys, deleteAction, updateAction, match, check string
		var deferrable, deferred, valid, enforced, sameSchema, nullsNotDistinct bool
		if err := rows.Scan(&kind, &deferrable, &deferred, &valid, &enforced, &columns, &target,
			&sameSchema, &keys, &deleteAction, &updateAction, &match, &check, &nullsNotDistinct); err != nil {
			return nil, err
		}
		if deferrable || deferred || !valid || !enforced || !sameSchema || nullsNotDistinct {
			return nil, drift(table, "constraint validation, deferral, uniqueness or target schema differs")
		}
		switch kind {
		case "p":
			result = append(result, "primary("+columns+")")
		case "u":
			result = append(result, "unique("+columns+")")
		case "f":
			if match != "s" {
				return nil, drift(table, "foreign-key match mode differs")
			}
			result = append(result, foreignSignature(foreignKey{
				columns: strings.Split(columns, ","), target: target, keys: strings.Split(keys, ","),
				delete: actions[deleteAction], update: actions[updateAction],
			}))
		case "c":
			expr, err := expression(check)
			if err != nil {
				return nil, drift(table, "unsupported live CHECK expression")
			}
			result = append(result, "check("+expr+")")
		default:
			return nil, drift(table, "unexpected constraint kind")
		}
	}
	return result, rows.Err()
}

func mysqlConstraints(ctx context.Context, q queryer, table string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT t.constraint_type,t.enforced,
		COALESCE((SELECT GROUP_CONCAT(k.column_name ORDER BY k.ordinal_position SEPARATOR ',')
		FROM information_schema.key_column_usage k WHERE k.constraint_schema=t.constraint_schema
		AND k.table_name=t.table_name AND k.constraint_name=t.constraint_name),''),
		COALESCE(c.check_clause,''),COALESCE(r.referenced_table_name,''),
		COALESCE(r.unique_constraint_schema=DATABASE(),TRUE),
		COALESCE((SELECT GROUP_CONCAT(k.referenced_column_name ORDER BY k.ordinal_position SEPARATOR ',')
		FROM information_schema.key_column_usage k WHERE k.constraint_schema=t.constraint_schema
		AND k.table_name=t.table_name AND k.constraint_name=t.constraint_name),''),
		COALESCE(r.delete_rule,''),COALESCE(r.update_rule,'')
		FROM information_schema.table_constraints t
		LEFT JOIN information_schema.check_constraints c ON c.constraint_schema=t.constraint_schema AND c.constraint_name=t.constraint_name
		LEFT JOIN information_schema.referential_constraints r ON r.constraint_schema=t.constraint_schema
		AND r.table_name=t.table_name AND r.constraint_name=t.constraint_name
		WHERE t.table_schema=DATABASE() AND t.table_name=?`, table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := []string{}
	for rows.Next() {
		var kind, enforced, columns, check, target, keys, deleteAction, updateAction string
		var sameSchema bool
		if err := rows.Scan(&kind, &enforced, &columns, &check, &target, &sameSchema, &keys, &deleteAction, &updateAction); err != nil {
			return nil, err
		}
		if enforced != "YES" || !sameSchema {
			return nil, drift(table, "unenforced constraint or external auth FK target")
		}
		switch kind {
		case "PRIMARY KEY":
			result = append(result, "primary("+columns+")")
		case "UNIQUE":
			result = append(result, "unique("+columns+")")
		case "FOREIGN KEY":
			if deleteAction == "NO ACTION" {
				deleteAction = "RESTRICT"
			}
			if updateAction == "NO ACTION" {
				updateAction = "RESTRICT"
			}
			result = append(result, foreignSignature(foreignKey{
				columns: strings.Split(columns, ","), target: target, keys: strings.Split(keys, ","),
				delete: deleteAction, update: updateAction,
			}))
		case "CHECK":
			expr, err := expression(check)
			if err != nil {
				return nil, drift(table, "unsupported live CHECK expression")
			}
			result = append(result, "check("+expr+")")
		default:
			return nil, drift(table, "unexpected constraint kind")
		}
	}
	return result, rows.Err()
}

func verifyIndexes(ctx context.Context, q queryer, dialect string, table *tableSpec, def definition) error {
	var query string
	if dialect == "postgres" {
		query = `SELECT x.relname,am.amname,i.indisunique,i.indisvalid AND i.indisready AND i.indnatts=i.indnkeyatts,
			COALESCE(pg_get_expr(i.indpred,i.indrelid,TRUE),''),
			array_to_json(ARRAY(SELECT pg_get_indexdef(x.oid,k.ord::int,TRUE)
			|| CASE WHEN NOT op.opcdefault THEN ' '||op.opcname ELSE '' END
			|| CASE WHEN (i.indoption[(k.ord-1)::int]&1)=1 THEN ' DESC' ELSE '' END
			|| CASE WHEN (i.indoption[(k.ord-1)::int]&3)=2 THEN ' NULLS FIRST'
			WHEN (i.indoption[(k.ord-1)::int]&3)=1 THEN ' NULLS LAST' ELSE '' END
			FROM unnest(i.indkey) WITH ORDINALITY k(num,ord)
			JOIN pg_opclass op ON op.oid=i.indclass[(k.ord-1)::int] ORDER BY k.ord))::text
			FROM pg_index i JOIN pg_class x ON x.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid
			JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_am am ON am.oid=x.relam
			WHERE n.nspname=current_schema() AND t.relname=$1
			AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conindid=i.indexrelid AND conrelid=i.indrelid)`
	} else {
		query = `SELECT index_name,LOWER(index_type),non_unique=0,MIN(is_visible='YES'),'',
			CONCAT('[',GROUP_CONCAT(JSON_QUOTE(CONCAT(COALESCE(column_name,''),
			IF(sub_part IS NULL,'',CONCAT('(',sub_part,')')),IF(collation='D',' DESC','')))
			ORDER BY seq_in_index SEPARATOR ','),']')
			FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=?
			GROUP BY index_name,index_type,non_unique`
	}
	rows, err := q.QueryContext(ctx, query, table.name)
	if err != nil {
		return err
	}
	found := map[string]bool{}
	for rows.Next() {
		var name, method, predicate, columnJSON string
		var unique, valid bool
		if err := rows.Scan(&name, &method, &unique, &valid, &predicate, &columnJSON); err != nil {
			_ = rows.Close()
			return err
		}
		columns := []string{}
		if err := json.Unmarshal([]byte(columnJSON), &columns); err != nil {
			_ = rows.Close()
			return err
		}
		for i := range columns {
			columns[i] = normalizeIndexColumn(dialect, columns[i], table)
		}
		idx, expected := def.indexes[name]
		if !expected || idx.table != table.name {
			if dialect == "mysql" && mysqlImplicitIndex(name, unique, columns, table) && valid && method == "btree" {
				continue
			}
			_ = rows.Close()
			return drift(table.name, "unexpected index "+name)
		}
		parsedPredicate := ""
		if predicate != "" {
			parsedPredicate, err = expression(predicate)
			if err != nil {
				_ = rows.Close()
				return drift(name, "unsupported live index predicate")
			}
		}
		if unique != idx.unique || !valid || method != idx.method || !slices.Equal(columns, idx.columns) || parsedPredicate != idx.predicate {
			_ = rows.Close()
			return drift(name, "index definition or validity differs")
		}
		found[name] = true
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	for name, idx := range def.indexes {
		if idx.table == table.name && !found[name] {
			return drift(name, "missing index")
		}
	}
	var triggers int
	if dialect == "postgres" {
		query = `SELECT COUNT(*) FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid
			JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=current_schema() AND t.relname=$1
			AND (NOT g.tgisinternal OR g.tgenabled!='O')`
	} else {
		query = "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema=DATABASE() AND event_object_table=?"
	}
	if err := q.QueryRowContext(ctx, query, table.name).Scan(&triggers); err != nil {
		return err
	}
	if triggers != 0 {
		return drift(table.name, "unexpected trigger or changed FK trigger enforcement")
	}
	return nil
}

func mysqlImplicitIndex(name string, unique bool, columns []string, table *tableSpec) bool {
	if unique {
		kind := "unique"
		if name == "PRIMARY" {
			kind = "primary"
		}
		return slices.Contains(table.constraints, kind+"("+strings.Join(columns, ",")+")")
	}
	for _, fk := range table.foreignKeys {
		expectedName := fk.name
		if expectedName == "" {
			expectedName = fk.columns[0]
		}
		if name != expectedName || !slices.Equal(columns, fk.columns) {
			continue
		}
		// InnoDB may keep its automatically created FK supporting index even
		// after a later named index covers it. Only the exact generated key is allowed.
		return true
	}
	return false
}

// Re-enabling FK enforcement does not validate rows written while it was
// bypassed. Adoption and postconditions must reject existing orphaned auth data.
func verifyForeignKeyData(ctx context.Context, q queryer, dialect string, table *tableSpec) error {
	quote := "`"
	if dialect == "postgres" {
		quote = `"`
	}
	identifier := func(name string) string { return quote + name + quote }
	for _, fk := range table.foreignKeys {
		joins := make([]string, len(fk.columns))
		present := make([]string, len(fk.columns))
		for i, column := range fk.columns {
			joins[i] = "c." + identifier(column) + " = p." + identifier(fk.keys[i])
			present[i] = "c." + identifier(column) + " IS NOT NULL"
		}
		// Identifiers come exclusively from the validated embedded snapshot.
		query := "SELECT EXISTS(SELECT 1 FROM " + identifier(table.name) + " c LEFT JOIN " + identifier(fk.target) +
			" p ON " + strings.Join(joins, " AND ") + " WHERE " + strings.Join(present, " AND ") +
			" AND p." + identifier(fk.keys[0]) + " IS NULL)"
		var orphan bool
		if err := q.QueryRowContext(ctx, query).Scan(&orphan); err != nil {
			return err
		}
		if orphan {
			return drift(table.name, "orphaned foreign-key data targeting "+fk.target)
		}
	}
	return nil
}
