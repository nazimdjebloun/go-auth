package migrations

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// These parsers describe our checked-in snapshots, not arbitrary consumer SQL.
// Snapshot formatting and the accepted expression subset are authoring contracts.
var (
	tableDefinition      = regexp.MustCompile(`(?ms)^CREATE TABLE(?: IF NOT EXISTS)? ([a-z_]+) \(\n(.*?)^\)([^;]*);`)
	columnDefinition     = regexp.MustCompile(`^\s+([a-z_]+) ([A-Z]+(?:\([0-9]+\))?)([^\n]*)`)
	primaryKeyDefinition = regexp.MustCompile(`PRIMARY KEY\s*\(([^)]+)\)`)
	uniqueDefinition     = regexp.MustCompile(`UNIQUE\s*\(([^)]+)\)`)
	indexDefinition      = regexp.MustCompile(`(?m)^CREATE (UNIQUE )?INDEX(?: IF NOT EXISTS)? ([a-z_]+) ON ([a-z_]+)(?: USING ([A-Za-z]+))?\s*\(([^;]+?)\)(?: WHERE ([^;]+))?;`)
	tableStart           = regexp.MustCompile(`(?im)^CREATE TABLE\b`)
	indexStart           = regexp.MustCompile(`(?im)^CREATE (?:UNIQUE )?INDEX\b`)
	defaultDefinition    = regexp.MustCompile(`(?i)DEFAULT\s+(\('(?:''|[^'])*'\)|'(?:''|[^'])*'|[a-z_]+(?:\([0-9]*\))?|[0-9]+)`)
	collationDefinition  = regexp.MustCompile(`(?i)COLLATE ([a-z0-9_]+)`)
	foreignDefinition    = regexp.MustCompile(`(?i)(?:CONSTRAINT\s+([a-z_]+)\s+)?FOREIGN KEY\s*\(([^)]+)\)\s+REFERENCES\s+([a-z_]+)\s*\(([^)]+)\)([^,\n]*)`)
	referenceDefinition  = regexp.MustCompile(`(?i)REFERENCES\s+([a-z_]+)\s*\(([^)]+)\)([^,\n]*)`)
	onDeleteDefinition   = regexp.MustCompile(`(?i)ON DELETE\s+(CASCADE|RESTRICT|SET NULL|NO ACTION)`)
	onUpdateDefinition   = regexp.MustCompile(`(?i)ON UPDATE\s+(CASCADE|RESTRICT|SET NULL|NO ACTION)`)
)

type definition struct {
	tables  map[string]*tableSpec
	indexes map[string]indexSpec
}

type tableSpec struct {
	name        string
	sql         string
	columns     []columnSpec
	constraints []string
	foreignKeys []foreignKey
}

type columnSpec struct {
	name       string
	kind       string
	nullable   bool
	defaultSQL *string
	collation  string
	extra      string
}

type indexSpec struct {
	name      string
	table     string
	method    string
	columns   []string
	predicate string
	unique    bool
}

type foreignKey struct {
	name    string
	columns []string
	target  string
	keys    []string
	delete  string
	update  string
}

func parseDefinition(dialect, script string) (definition, error) {
	script = strings.ReplaceAll(script, "\r\n", "\n")
	result := definition{tables: map[string]*tableSpec{}, indexes: map[string]indexSpec{}}
	for _, match := range tableDefinition.FindAllStringSubmatch(script, -1) {
		table := &tableSpec{name: match[1], sql: match[0], columns: []columnSpec{}, constraints: []string{}}
		for _, line := range strings.Split(match[2], "\n") {
			col := columnDefinition.FindStringSubmatch(line)
			if col == nil {
				continue
			}
			c := columnSpec{name: col[1], kind: strings.ToLower(col[2]), nullable: true}
			c.nullable = !strings.Contains(col[3], "NOT NULL")
			primary := strings.Contains(col[3], "PRIMARY KEY")
			if primary && dialect != "sqlite" {
				c.nullable = false
			}
			if primary {
				table.constraints = append(table.constraints, "primary("+c.name+")")
			}
			if strings.Contains(col[3], "UNIQUE") {
				table.constraints = append(table.constraints, "unique("+c.name+")")
			}
			if def := defaultDefinition.FindStringSubmatch(col[3]); def != nil {
				c.defaultSQL = &def[1]
			}
			if coll := collationDefinition.FindStringSubmatch(col[3]); coll != nil {
				c.collation = strings.ToLower(coll[1])
			}
			switch dialect {
			case "postgres":
				if c.kind == "timestamptz" {
					c.kind = "timestamp with time zone"
				}
				if c.kind == "int" {
					c.kind = "integer"
				}
				c.kind = strings.Replace(c.kind, "varchar", "character varying", 1)
				if c.collation == "" && (c.kind == "text" || strings.HasPrefix(c.kind, "character varying")) {
					c.collation = "default"
				}
			case "mysql":
				if c.kind == "boolean" {
					c.kind = "tinyint(1)"
				}
				if c.kind == "integer" {
					c.kind = "int"
				}
				if strings.Contains(col[3], "UNSIGNED") {
					c.kind += " unsigned"
				}
				if c.collation == "" && (c.kind == "text" || strings.HasPrefix(c.kind, "varchar")) {
					c.collation = "utf8mb4_unicode_ci"
				}
				if _, extra, ok := strings.Cut(col[3], "ON UPDATE "); ok {
					c.extra = "on update " + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(extra), ","))
				}
			}
			if ref := referenceDefinition.FindStringSubmatch(col[3]); ref != nil {
				table.foreignKeys = append(table.foreignKeys, makeForeign(dialect, "", c.name, ref[1], ref[2], ref[3]))
			}
			table.columns = append(table.columns, c)
		}
		for _, pk := range primaryKeyDefinition.FindAllStringSubmatch(match[2], -1) {
			table.constraints = append(table.constraints, "primary("+names(pk[1])+")")
		}
		for _, uq := range uniqueDefinition.FindAllStringSubmatch(match[2], -1) {
			table.constraints = append(table.constraints, "unique("+names(uq[1])+")")
		}
		for _, fk := range foreignDefinition.FindAllStringSubmatch(match[2], -1) {
			table.foreignKeys = append(table.foreignKeys, makeForeign(dialect, fk[1], fk[2], fk[3], fk[4], fk[5]))
		}
		for _, fk := range table.foreignKeys {
			table.constraints = append(table.constraints, foreignSignature(fk))
		}
		checks, err := checkExpressions(match[2])
		if err != nil {
			return result, err
		}
		for _, check := range checks {
			expression, err := parseExpression(check, dialect == "mysql")
			if err != nil {
				return result, fmt.Errorf("%s CHECK: %w", table.name, err)
			}
			table.constraints = append(table.constraints, "check("+expression+")")
		}
		slices.Sort(table.constraints)
		if _, duplicate := result.tables[table.name]; duplicate || len(table.columns) == 0 {
			return result, fmt.Errorf("duplicate or empty table definition %s", table.name)
		}
		result.tables[table.name] = table
	}
	if len(result.tables) == 0 {
		return result, fmt.Errorf("snapshot has no recognized table definitions")
	}
	for _, match := range indexDefinition.FindAllStringSubmatch(script, -1) {
		idx := indexSpec{name: match[2], table: match[3], method: strings.ToLower(match[4]), unique: match[1] != ""}
		if _, duplicate := result.indexes[idx.name]; duplicate || result.tables[idx.table] == nil {
			return result, fmt.Errorf("duplicate or external index definition %s", idx.name)
		}
		if idx.method == "" {
			idx.method = "btree"
		}
		idx.columns = make([]string, 0)
		for _, col := range strings.Split(match[5], ",") {
			idx.columns = append(idx.columns, normalizeIndexColumn(dialect, col, result.tables[idx.table]))
		}
		if match[6] != "" {
			predicate, err := expression(match[6])
			if err != nil {
				return result, fmt.Errorf("index %s predicate: %w", idx.name, err)
			}
			idx.predicate = predicate
		}
		result.indexes[idx.name] = idx
	}
	if len(tableStart.FindAllStringIndex(script, -1)) != len(result.tables) ||
		len(indexStart.FindAllStringIndex(script, -1)) != len(result.indexes) {
		return result, fmt.Errorf("snapshot contains unsupported table or index formatting")
	}
	for _, table := range result.tables {
		for _, fk := range table.foreignKeys {
			if len(fk.columns) == 0 || len(fk.columns) != len(fk.keys) || result.tables[fk.target] == nil {
				return result, fmt.Errorf("unsupported foreign-key definition in %s", table.name)
			}
		}
	}
	return result, nil
}

func names(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(value), " ", ""), "`", ""))
}

func makeForeign(dialect, name, cols, target, keys, tail string) foreignKey {
	fk := foreignKey{
		name: name, columns: strings.Split(names(cols), ","), target: target,
		keys: strings.Split(names(keys), ","), delete: "NO ACTION", update: "NO ACTION",
	}
	if dialect == "mysql" {
		fk.delete, fk.update = "RESTRICT", "RESTRICT"
	}
	if match := onDeleteDefinition.FindStringSubmatch(tail); match != nil {
		fk.delete = strings.ToUpper(match[1])
	}
	if match := onUpdateDefinition.FindStringSubmatch(tail); match != nil {
		fk.update = strings.ToUpper(match[1])
	}
	return fk
}

func foreignSignature(fk foreignKey) string {
	return "foreign(" + strings.Join(fk.columns, ",") + ")->" + fk.target + "(" +
		strings.Join(fk.keys, ",") + ")/" + fk.delete + "/" + fk.update
}

func normalizeIndexColumn(dialect, value string, table *tableSpec) string {
	value = strings.ToLower(strings.Join(strings.Fields(strings.ReplaceAll(value, "`", "")), " "))
	value = strings.TrimSuffix(value, " asc")
	if dialect == "mysql" && table != nil {
		for _, col := range table.columns {
			// MySQL omits a prefix length spanning the complete VARCHAR.
			if col.kind == "varchar"+strings.TrimPrefix(value, col.name) && strings.HasPrefix(value, col.name+"(") {
				return col.name
			}
		}
	}
	return value
}

func checkExpressions(body string) ([]string, error) {
	tokens, err := tokenize(body)
	if err != nil {
		return nil, err
	}
	checks := []string{}
	for i := 0; i < len(tokens)-1; i++ {
		if tokens[i] != "check" || tokens[i+1] != "(" {
			continue
		}
		start, depth := i+2, 1
		i += 2
		for ; i < len(tokens); i++ {
			if tokens[i] == "(" {
				depth++
			}
			if tokens[i] == ")" {
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if depth != 0 {
			return nil, fmt.Errorf("unclosed CHECK expression")
		}
		checks = append(checks, strings.Join(tokens[start:i], " "))
	}
	return checks, nil
}
