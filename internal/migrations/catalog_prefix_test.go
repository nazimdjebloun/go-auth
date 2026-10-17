package migrations

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

// Only the manifest changes when selecting a historical target. All SQL and
// snapshots still come from the source with their original published checksums.
type catalogManifestFS struct {
	fs.FS
	path     string
	contents []byte
}

func (source catalogManifestFS) Open(name string) (fs.File, error) {
	if name == source.path {
		return fstest.MapFS{name: &fstest.MapFile{Data: source.contents}}.Open(name)
	}
	return source.FS.Open(name)
}

func catalogPrefix(t *testing.T, source fs.FS, catalog Catalog, count int) Catalog {
	t.Helper()
	if count < 1 || count > len(catalog.Migrations) {
		t.Fatalf("invalid catalog prefix length %d", count)
	}
	catalog.Migrations = catalog.Migrations[:count:count]
	catalog.TargetRevision = catalog.Migrations[count-1].ID
	manifest, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := ReadCatalog(catalogManifestFS{
		FS: source, path: catalog.Dialect + "/catalog.json", contents: manifest,
	}, catalog.Dialect)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func bootstrapCatalog(t *testing.T, dialect string) Catalog {
	t.Helper()
	catalog, err := ReadCatalog(files, dialect)
	if err != nil {
		t.Fatal(err)
	}
	return catalogPrefix(t, files, catalog, 1)
}

func applyBootstrap(t *testing.T, db *sql.DB, dialect string) {
	t.Helper()
	if _, err := runCatalog(t.Context(), db, Options{Driver: dialect}, bootstrapCatalog(t, dialect), "apply", 0); err != nil {
		t.Fatal(err)
	}
}

func requireCompletedCatalog(t *testing.T, catalog Catalog, status Status) {
	t.Helper()
	if status.Revision != catalog.TargetRevision || status.TargetRevision != catalog.TargetRevision ||
		status.Dirty || len(status.Pending) != 0 || len(status.History) != len(catalog.Migrations) {
		t.Fatalf("catalog did not complete: %+v", status)
	}
	for i, record := range status.History {
		if record.ID != catalog.Migrations[i].ID || record.State != "complete" || record.CompletedAt == nil || record.Mode != "executed" {
			t.Fatalf("migration has no completed execution record: %+v", record)
		}
	}
}

func TestSelectedBackendPublishedCatalogUpgradePrefixes(t *testing.T) {
	catalog, err := Load(testdb.Selected())
	if err != nil {
		t.Fatal(err)
	}
	for i, step := range catalog.Migrations {
		t.Run(fmt.Sprintf("from_%06d", step.ID), func(t *testing.T) {
			db := testdb.OpenSelected(t)
			options := Options{Driver: catalog.Dialect}
			prefix := catalogPrefix(t, files, catalog, i+1)
			installed, err := runCatalog(t.Context(), db, options, prefix, "apply", 0)
			if err != nil {
				t.Fatal("install published prefix", err)
			}
			requireCompletedCatalog(t, prefix, installed)
			upgraded, err := Apply(t.Context(), db, options)
			if err != nil {
				t.Fatal("upgrade published prefix to target", err)
			}
			requireCompletedCatalog(t, catalog, upgraded)
			if !reflect.DeepEqual(installed.History, upgraded.History[:len(installed.History)]) {
				t.Fatal("upgrade changed previously completed journal records")
			}
			if err := Verify(t.Context(), db, options); err != nil {
				t.Fatal("verify published target", err)
			}
			repeated, err := Apply(t.Context(), db, options)
			if err != nil {
				t.Fatal("repeat published target apply", err)
			}
			requireCompletedCatalog(t, catalog, repeated)
			if !reflect.DeepEqual(upgraded.History, repeated.History) {
				t.Fatal("repeat apply changed completed journal records")
			}
		})
	}
}

func TestCatalogPrefixIsolatesBootstrap(t *testing.T) {
	catalog := upgradeCatalog(t, "sqlite")
	source := frozenFixture(t, catalog)
	prefix := catalogPrefix(t, source, catalog, 1)
	if len(prefix.Migrations) != 1 || prefix.TargetRevision != catalog.BootstrapRevision || len(catalog.Migrations) != 3 ||
		!reflect.DeepEqual(prefix.Migrations[0], catalog.Migrations[0]) {
		t.Fatal("bootstrap extraction retained later synthetic steps or changed the baseline")
	}
	manifest, err := json.Marshal(prefix)
	if err != nil {
		t.Fatal(err)
	}
	source["sqlite/"+prefix.Migrations[0].File].Data = []byte(prefix.Migrations[0].SQL + "-- tampered\n")
	if _, err := ReadCatalog(catalogManifestFS{FS: source, path: "sqlite/catalog.json", contents: manifest}, "sqlite"); err == nil {
		t.Fatal("prefix manifest concealed a modified source artifact")
	}
}
