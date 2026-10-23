package migrationtool

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/nazimdjebloun/go-auth/internal/migrations"
)

const statementFormat = "{{ range .Changes }}-- goauth:statement\n{{ .Cmd }};\n\n{{ end }}"

var sqliteAutoindexLabel = regexp.MustCompile(`(?m)^(\s*)index "sqlite_autoindex_[a-z_]+_[0-9]+" \{`)

// CreateDraft compares released history with canonical SQL in a disposable
// Atlas database. It writes review files only, leaving source catalogs untouched.
func (t Tool) CreateDraft(ctx context.Context, options DraftOptions) (string, error) {
	t, err := t.prepare()
	if err != nil {
		return "", err
	}
	catalog, manifest, err := t.catalog(ctx, options.Driver)
	if err != nil {
		return "", err
	}
	file, err := nextFile(catalog, options.Release, options.Sequence)
	if err != nil {
		return "", err
	}
	desired, err := t.desired(catalog.Dialect)
	if err != nil {
		return "", err
	}
	work, err := os.MkdirTemp("", "goauth-migration-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(work) }()
	var sql []byte
	if options.Manual {
		sql = []byte("-- goauth:statement\n-- Write the reviewed transformation here.\n")
	} else {
		pin, err := t.pinnedAtlas(ctx)
		if err != nil {
			return "", err
		}
		generated, err := t.diff(ctx, pin, work, catalog, desired)
		if err != nil {
			return "", err
		}
		if len(generated) == 0 {
			return "", fmt.Errorf("migrationtool: schema unchanged; use --manual for required data work or release to retain the schema revision")
		}
		if len(generated) != 1 {
			return "", fmt.Errorf("migrationtool: expected one Atlas draft, got %d", len(generated))
		}
		sql, err = os.ReadFile(generated[0])
		if err != nil {
			return "", err
		}
	}
	draft := Draft{
		Format: 1, Dialect: catalog.Dialect, Release: options.Release,
		ID: catalog.TargetRevision + 1, Sequence: options.Sequence, File: file,
		BaseRevision: catalog.TargetRevision, BaseCatalogChecksum: checksum(manifest),
		DesiredChecksum: checksum(desired), Transactional: catalog.Dialect != "mysql", Checks: []string{},
	}
	metadata, err := jsonBytes(draft)
	if err != nil {
		return "", err
	}
	directory := options.Directory
	if directory == "" {
		directory = filepath.Join(".migration-drafts", catalog.Dialect)
	}
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(t.Root, directory)
	}
	if _, err := os.Stat(directory); err == nil || !os.IsNotExist(err) {
		return "", fmt.Errorf("migrationtool: choose a new draft directory: %s", directory)
	}
	if err := os.MkdirAll(filepath.Dir(directory), 0750); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(filepath.Dir(directory), ".draft-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	for name, contents := range map[string][]byte{
		"draft.json": metadata, "migration.sql": sql, "schema.sql": desired,
	} {
		if err := writeNew(filepath.Join(staging, name), contents); err != nil {
			return "", err
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := os.Rename(staging, directory); err != nil {
		return "", err
	}
	return directory, nil
}

func nextFile(catalog migrations.Catalog, release string, sequence int) (string, error) {
	if !releaseName.MatchString(release) || sequence < 1 || sequence > 999 || catalog.TargetRevision >= 999999 {
		return "", fmt.Errorf("migrationtool: require a vMAJOR.MINOR.PATCH release, step 1..999 and an available six-digit ID")
	}
	previousSequence := 0
	for _, step := range catalog.Migrations {
		// Split at underscores; prerelease hyphens and dots remain metadata.
		parts := strings.Split(strings.TrimSuffix(step.File, ".sql"), "_")
		if len(parts) != 3 {
			return "", fmt.Errorf("migrationtool: invalid published filename")
		}
		suffix, err := strconv.Atoi(parts[2])
		if err != nil {
			return "", err
		}
		if parts[1] == release {
			previousSequence = max(previousSequence, suffix)
		}
	}
	if sequence != previousSequence+1 {
		return "", fmt.Errorf("migrationtool: release %s requires step %03d", release, previousSequence+1)
	}
	return fmt.Sprintf("%06d_%s_%03d.sql", catalog.TargetRevision+1, release, sequence), nil
}

func fileURL(path string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
}

func (t Tool) diff(ctx context.Context, pin toolchain, work string, catalog migrations.Catalog, desired []byte) ([]string, error) {
	history := filepath.Join(work, "history")
	if err := os.MkdirAll(history, 0750); err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(catalog.Migrations))
	for _, step := range catalog.Migrations {
		contents := step.SQL
		if !step.Transactional || step.SQLiteRebuild {
			contents = "-- atlas:txmode none\n" + contents
		}
		if step.SQLiteRebuild {
			contents = "-- atlas:txmode none\nPRAGMA foreign_keys=OFF;\n" + step.SQL + "\nPRAGMA foreign_keys=ON;\n"
		}
		if err := writeNew(filepath.Join(history, step.File), []byte(contents)); err != nil {
			return nil, err
		}
		known[step.File] = true
	}
	schemaPath := filepath.Join(work, "schema.sql")
	if err := writeNew(schemaPath, desired); err != nil {
		return nil, err
	}
	if _, err := t.atlas(ctx, work, "migrate", "hash", "--dir", fileURL(history)); err != nil {
		return nil, err
	}
	devURL, ok := pin.DevDatabases[catalog.Dialect]
	if !ok {
		return nil, fmt.Errorf("migrationtool: no pinned dev database for %s", catalog.Dialect)
	}
	if catalog.Dialect == "sqlite" {
		// Atlas v1.3.0 renames UNIQUE autoindexes on only one side of its
		// diff. Keep their full definitions but omit SQLite-generated names
		// from the temporary desired HCL so Atlas matches them by their parts.
		hcl, err := t.atlas(ctx, work, "schema", "inspect", "--url", fileURL(schemaPath), "--dev-url", devURL)
		if err != nil {
			return nil, err
		}
		schemaPath = filepath.Join(work, "schema.hcl")
		if err := writeNew(schemaPath, sqliteAutoindexLabel.ReplaceAll(hcl, []byte("${1}index {"))); err != nil {
			return nil, err
		}
	}
	if _, err := t.atlas(ctx, work, "migrate", "diff", "review", "--dir", fileURL(history),
		"--to", fileURL(schemaPath), "--dev-url", devURL, "--format", statementFormat); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(history)
	if err != nil {
		return nil, err
	}
	var generated []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") && !known[entry.Name()] {
			generated = append(generated, filepath.Join(history, entry.Name()))
		}
	}
	return generated, nil
}
