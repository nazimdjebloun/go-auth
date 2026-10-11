package migrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

// Export writes review artifacts. Existing published SQL is
// immutable; a different dialect needs a different output directory.
func Export(driver, directory string) error {
	catalog, err := Load(driver)
	if err != nil {
		return err
	}
	if directory == "" {
		return fmt.Errorf("goauth: export directory is required")
	}
	desired, err := schema.For(driver)
	if err != nil {
		return err
	}
	desired = strings.ReplaceAll(desired, "\r\n", "\n")
	// The public export has one complete desired schema. Historical structural
	// verification fixtures stay embedded in the runner, rather than becoming
	// extra schema files or implied filesystem deployment state.
	for i := range catalog.Migrations {
		catalog.Migrations[i].Schema = ""
	}
	manifest, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	manifest = append(manifest, '\n')
	manifestPath := filepath.Join(directory, "migrations", "catalog.json")
	if existing, err := os.ReadFile(manifestPath); err == nil {
		old, err := decodeCatalog(existing)
		if err != nil {
			return fmt.Errorf("goauth: invalid existing export manifest: %w", err)
		}
		if old.Dialect != catalog.Dialect || old.TargetRevision > catalog.TargetRevision {
			return fmt.Errorf("goauth: export directory contains a different dialect or newer catalog")
		}
		if old.Format != catalog.Format || old.BootstrapRevision != catalog.BootstrapRevision ||
			len(old.Migrations) == 0 || len(old.Migrations) > len(catalog.Migrations) ||
			old.TargetRevision != old.Migrations[len(old.Migrations)-1].ID {
			return fmt.Errorf("goauth: existing export manifest is not a supported catalog prefix")
		}
		for i, previous := range old.Migrations {
			step := catalog.Migrations[i]
			previousMetadata, _ := json.Marshal(previous)
			metadata, _ := json.Marshal(step)
			if !bytes.Equal(previousMetadata, metadata) {
				return fmt.Errorf("goauth: existing export metadata differs at migration %d", previous.ID)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	writes := map[string][]byte{
		filepath.Join(directory, "auth.schema.sql"): []byte(fmt.Sprintf(
			"-- go-auth %s; dialect %s; desired schema revision %d.\n-- Applied state is recorded in the database.\n%s",
			catalog.Release, catalog.Dialect, catalog.TargetRevision, desired,
		)),
		filepath.Join(directory, "reference.md"): []byte(reference(catalog, desired)),
		manifestPath:                             manifest,
	}
	for _, step := range catalog.Migrations {
		path := filepath.Join(directory, "migrations", step.File)
		if existing, err := os.ReadFile(path); err == nil && string(existing) != step.SQL {
			return fmt.Errorf("goauth: refusing to replace modified published artifact %q", path)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
		writes[path] = []byte(step.SQL)
	}
	for path, contents := range writes {
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return err
		}
		if err := os.WriteFile(path, contents, 0600); err != nil {
			return fmt.Errorf("goauth: export %q: %w", path, err)
		}
	}
	return nil
}

// Stable targets are a maintainer declaration, not inferred from SQL types.
var stableTargets = map[string]bool{"users.id": true, "organizations.id": true}

func reference(catalog Catalog, desired string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# go-auth schema reference — %s (%s), revision %d\n\n",
		catalog.Release, catalog.Dialect, catalog.TargetRevision)
	b.WriteString("Auth table names are fixed. Run auth migrations separately through `goauth migrate`.\n")
	b.WriteString("Create auth targets before application foreign keys. Keep ORM migration ownership separate.\n")
	b.WriteString("Use application extension tables; do not add columns, constraints, indexes or triggers to auth tables.\n\n")
	b.WriteString("Changes to declared stable FK targets require a major version bump.\n\n")
	b.WriteString("| Table | Primary key | Type | Stable FK target |\n|---|---|---|---|\n")
	tables := tableDefinition.FindAllStringSubmatch(desired, -1)
	for _, table := range tables {
		keys := []string{}
		types := map[string]string{}
		for _, line := range strings.Split(table[2], "\n") {
			if col := columnDefinition.FindStringSubmatch(line); col != nil {
				types[col[1]] = col[2]
				if strings.Contains(col[3], "PRIMARY KEY") {
					keys = append(keys, col[1])
				}
			}
			if match := primaryKeyDefinition.FindStringSubmatch(line); match != nil {
				keys = strings.Split(strings.ReplaceAll(match[1], " ", ""), ",")
			}
		}
		keyTypes := make([]string, 0, len(keys))
		stable := "no"
		for _, key := range keys {
			keyTypes = append(keyTypes, types[key])
			if stableTargets[table[1]+"."+key] {
				stable = "yes"
			}
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n",
			table[1], strings.Join(keys, ", "), strings.Join(keyTypes, ", "), stable)
	}
	if catalog.Dialect == "mysql" {
		b.WriteString("\nStable ID columns use `utf8mb4_unicode_ci`; child FK columns must use matching types and collations.\n")
	}
	b.WriteString("\nThe journal table `goauth_migrations` is also reserved and library-owned.\n")
	return b.String()
}
