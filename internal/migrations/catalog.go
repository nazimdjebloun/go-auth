// Package migrations owns the immutable auth catalog and standalone executor.
// It deliberately does not use the application's migration history.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

//go:embed postgres/* mysql/* sqlite/*
var files embed.FS

var migrationName = regexp.MustCompile(`^([0-9]{6})_v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?_[0-9]{3}\.sql$`)
var snapshotName = regexp.MustCompile(`^schema_[0-9]{6}\.sql$`)

// Catalog describes one dialect's published linear migration history.
type Catalog struct {
	Format            int    `json:"format"`
	Release           string `json:"release"`
	Dialect           string `json:"dialect"`
	TargetRevision    int64  `json:"targetRevision"`
	BootstrapRevision int64  `json:"bootstrapRevision"`
	Migrations        []Step `json:"migrations"`
}

// Step describes a reviewed, immutable migration. SQL is exported separately.
type Step struct {
	ID             int64    `json:"id"`
	File           string   `json:"file"`
	Checksum       string   `json:"checksum"`
	Kind           string   `json:"kind"`
	Transactional  bool     `json:"transactional"`
	Schema         string   `json:"schema"`
	SchemaChecksum string   `json:"schemaChecksum"`
	Checks         []string `json:"checks"`
	SQLiteRebuild  bool     `json:"sqliteRebuild,omitempty"`
	SQL            string   `json:"-"`
	schemaSQL      string
	statements     []string
}

// Dialect resolves exactly the aliases accepted by the schema API.
func Dialect(driver string) (string, error) {
	switch driver {
	case "postgres", "pg":
		return "postgres", nil
	case "sqlite", "sqlite3":
		return "sqlite", nil
	case "mysql":
		return "mysql", nil
	default:
		return "", fmt.Errorf("%w %q", schema.ErrUnsupportedDriver, driver)
	}
}

// Load returns a fresh copy, validating names, ordering and published checksums.
func Load(driver string) (Catalog, error) {
	dialect, err := Dialect(driver)
	if err != nil {
		return Catalog{}, err
	}
	b, err := files.ReadFile(dialect + "/catalog.json")
	if err != nil {
		return Catalog{}, err
	}
	var catalog Catalog
	if err := json.Unmarshal(b, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("goauth: decode migration catalog: %w", err)
	}
	if catalog.Format != 1 || catalog.Dialect != dialect || len(catalog.Migrations) == 0 {
		return Catalog{}, fmt.Errorf("goauth: invalid %s migration catalog", dialect)
	}
	var previous int64
	for i := range catalog.Migrations {
		step := &catalog.Migrations[i]
		match := migrationName.FindStringSubmatch(step.File)
		if match == nil {
			return Catalog{}, fmt.Errorf("goauth: invalid migration filename %q", step.File)
		}
		id, _ := strconv.ParseInt(match[1], 10, 64)
		if id != step.ID || id <= previous {
			return Catalog{}, fmt.Errorf("goauth: invalid migration ordering at %q", step.File)
		}
		previous = id
		if (i == 0 && step.Kind != "baseline") || (i != 0 && step.Kind != "upgrade") {
			return Catalog{}, fmt.Errorf("goauth: invalid migration kind at %q", step.File)
		}
		if dialect == "mysql" && step.Transactional {
			return Catalog{}, fmt.Errorf("goauth: MySQL DDL migration %d cannot be transactional", id)
		}
		if dialect == "sqlite" && !step.Transactional {
			return Catalog{}, fmt.Errorf("goauth: SQLite migration %d must be transactional", id)
		}
		if !snapshotName.MatchString(step.Schema) {
			return Catalog{}, fmt.Errorf("goauth: invalid schema snapshot for migration %d", id)
		}
		b, err := files.ReadFile(dialect + "/" + step.File)
		if err != nil {
			return Catalog{}, err
		}
		digest := sha256.Sum256(b)
		if hex.EncodeToString(digest[:]) != step.Checksum {
			return Catalog{}, fmt.Errorf("goauth: published checksum mismatch for %s/%s", dialect, step.File)
		}
		step.SQL = string(b)
		step.statements, err = statements(step.SQL)
		if err != nil {
			return Catalog{}, fmt.Errorf("goauth: parse migration %d: %w", id, err)
		}
		b, err = files.ReadFile(dialect + "/" + step.Schema)
		if err != nil {
			return Catalog{}, err
		}
		step.schemaSQL = string(b)
		digest = sha256.Sum256(b)
		if hex.EncodeToString(digest[:]) != step.SchemaChecksum {
			return Catalog{}, fmt.Errorf("goauth: schema snapshot checksum mismatch for migration %d", id)
		}
		if _, err := parseDefinition(dialect, step.schemaSQL); err != nil {
			return Catalog{}, fmt.Errorf("goauth: invalid verification snapshot for migration %d: %w", id, err)
		}
		for _, check := range step.Checks {
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(check)), "SELECT ") {
				return Catalog{}, fmt.Errorf("goauth: migration %d requires SELECT verification queries", id)
			}
		}
	}
	if catalog.BootstrapRevision != catalog.Migrations[0].ID || catalog.TargetRevision != previous {
		return Catalog{}, fmt.Errorf("goauth: invalid baseline or target revision for %s", dialect)
	}
	desired, err := schema.For(dialect)
	if err != nil {
		return Catalog{}, err
	}
	if strings.ReplaceAll(desired, "\r\n", "\n") != catalog.Migrations[len(catalog.Migrations)-1].schemaSQL {
		return Catalog{}, fmt.Errorf("goauth: canonical schema differs from the catalog's target snapshot")
	}
	return catalog, nil
}

// Statement boundaries are authored explicitly. This permits dollar-quoted
// functions and compound trigger bodies without pretending to parse arbitrary
// SQL. The marker is reserved and must never occur inside a statement body.
func statements(script string) ([]string, error) {
	const marker = "-- goauth:statement"
	parts := strings.Split(script, marker+"\n")
	if len(parts) < 2 || len(schema.SplitSQL(parts[0])) != 0 {
		return nil, fmt.Errorf("missing explicit statement boundaries")
	}
	result := make([]string, 0, len(parts)-1)
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty migration statement")
		}
		result = append(result, part)
	}
	return result, nil
}
