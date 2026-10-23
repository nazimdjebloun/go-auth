package migrationtool

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nazimdjebloun/go-auth/internal/migrations"
)

// Seal appends reviewed SQL, its full target fixture and checksums. Before any
// source mutation Atlas must replay the candidate to the canonical schema.
// This proves the empty-schema result; populated upgrade tests remain required.
func (t Tool) Seal(ctx context.Context, directory string, reviewed bool) error {
	if !reviewed {
		return fmt.Errorf("migrationtool: review migration.sql, schema.sql and draft.json, then supply --reviewed")
	}
	t, err := t.prepare()
	if err != nil {
		return err
	}
	unlock, err := t.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(t.Root, directory)
	}
	var draft Draft
	if err := readJSON(filepath.Join(directory, "draft.json"), &draft); err != nil {
		return err
	}
	catalog, manifest, err := t.catalog(ctx, draft.Dialect)
	if err != nil {
		return err
	}
	file, err := nextFile(catalog, draft.Release, draft.Sequence)
	if err != nil {
		return err
	}
	if draft.Format != 1 || draft.ID != catalog.TargetRevision+1 || draft.File != file ||
		draft.BaseRevision != catalog.TargetRevision || draft.BaseCatalogChecksum != checksum(manifest) {
		return fmt.Errorf("migrationtool: draft history changed; create and review a new draft")
	}
	desired, err := t.desired(catalog.Dialect)
	if err != nil {
		return err
	}
	// #nosec G304 -- The maintainer explicitly selects this local review directory.
	snapshot, err := os.ReadFile(filepath.Join(directory, "schema.sql"))
	if err != nil {
		return err
	}
	if checksum(desired) != draft.DesiredChecksum || checksum(snapshot) != draft.DesiredChecksum {
		return fmt.Errorf("migrationtool: desired schema changed since drafting; create and review a new draft")
	}
	// #nosec G304 -- Read reviewed SQL from the maintainer-selected draft, never from a request.
	sql, err := os.ReadFile(filepath.Join(directory, "migration.sql"))
	if err != nil {
		return err
	}
	if strings.Contains(string(sql), "\r") {
		return fmt.Errorf("migrationtool: migration SQL must use LF line endings")
	}
	step := migrations.Step{
		ID: draft.ID, File: file, Checksum: checksum(sql), Kind: "upgrade",
		Transactional: draft.Transactional, SQLiteRebuild: draft.SQLiteRebuild,
		Schema: fmt.Sprintf("schema_%06d.sql", draft.ID), SchemaChecksum: checksum(snapshot), Checks: draft.Checks,
		Preconditions: draft.Preconditions, Retry: draft.Retry,
	}
	catalog.Migrations = append(catalog.Migrations, step)
	catalog.TargetRevision, catalog.Release = step.ID, draft.Release
	work, err := os.MkdirTemp("", "goauth-seal-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	candidate, err := t.candidate(work, catalog, sql, snapshot)
	if err != nil {
		return err
	}
	if err := migrations.ValidateTarget(candidate, string(desired)); err != nil {
		return err
	}
	pin, err := t.pinnedAtlas(ctx)
	if err != nil {
		return err
	}
	remaining, err := t.diff(ctx, pin, filepath.Join(work, "replay"), candidate, desired)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return fmt.Errorf("migrationtool: reviewed history does not produce the canonical schema; source files were left unchanged")
	}
	// Atlas replay may take minutes. Preserve edits made while it was running
	// instead of publishing stale reviewed inputs over the current checkout.
	_, currentManifest, err := t.catalog(ctx, catalog.Dialect)
	if err != nil {
		return err
	}
	currentDesired, err := t.desired(catalog.Dialect)
	if err != nil {
		return err
	}
	// #nosec G304 -- Re-read the same explicitly selected draft to detect edits during replay.
	currentSQL, err := os.ReadFile(filepath.Join(directory, "migration.sql"))
	if err != nil {
		return err
	}
	// #nosec G304 -- Re-read the same explicitly selected snapshot to detect edits during replay.
	currentSnapshot, err := os.ReadFile(filepath.Join(directory, "schema.sql"))
	if err != nil {
		return err
	}
	var currentDraft Draft
	if err := readJSON(filepath.Join(directory, "draft.json"), &currentDraft); err != nil {
		return err
	}
	reviewedMetadata, err := jsonBytes(draft)
	if err != nil {
		return err
	}
	currentMetadata, err := jsonBytes(currentDraft)
	if err != nil {
		return err
	}
	if !bytes.Equal(manifest, currentManifest) || !bytes.Equal(desired, currentDesired) ||
		!bytes.Equal(sql, currentSQL) || !bytes.Equal(snapshot, currentSnapshot) || !bytes.Equal(reviewedMetadata, currentMetadata) {
		return fmt.Errorf("migrationtool: source or review inputs changed during replay; inspect and review them again before sealing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	contents, err := jsonBytes(catalog)
	if err != nil {
		return err
	}
	source := filepath.Join(t.Root, "internal/migrations", catalog.Dialect)
	var created []string
	success := false
	defer func() {
		if !success {
			for _, path := range created {
				_ = os.Remove(path)
			}
		}
	}()
	for _, artifact := range []struct {
		name     string
		contents []byte
	}{{step.File, sql}, {step.Schema, snapshot}} {
		path := filepath.Join(source, artifact.name)
		if err := writeNew(path, artifact.contents); err != nil {
			return err
		}
		created = append(created, path)
	}
	if err := replaceFile(filepath.Join(source, "catalog.json"), contents); err != nil {
		return err
	}
	success = true
	return nil
}

func (t Tool) candidate(work string, catalog migrations.Catalog, sql, snapshot []byte) (migrations.Catalog, error) {
	root := filepath.Join(work, "catalog")
	directory := filepath.Join(root, catalog.Dialect)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return catalog, err
	}
	for i, step := range catalog.Migrations {
		for _, artifact := range []struct {
			name     string
			contents []byte
		}{
			{step.File, sql}, {step.Schema, snapshot},
		} {
			contents := artifact.contents
			if i != len(catalog.Migrations)-1 {
				var err error
				contents, err = os.ReadFile(filepath.Join(t.Root, "internal/migrations", catalog.Dialect, artifact.name))
				if err != nil {
					return catalog, err
				}
			}
			if err := writeNew(filepath.Join(directory, artifact.name), contents); err != nil {
				return catalog, err
			}
		}
	}
	contents, err := jsonBytes(catalog)
	if err != nil {
		return catalog, err
	}
	if err := writeNew(filepath.Join(directory, "catalog.json"), contents); err != nil {
		return catalog, err
	}
	return migrations.ReadCatalog(os.DirFS(root), catalog.Dialect)
}

// Check validates all desired schemas and the immutable catalog prefix without
// Atlas or database access. Unexpected SQL files identify interrupted publication.
func (t Tool) Check(ctx context.Context) error {
	t, err := t.prepare()
	if err != nil {
		return err
	}
	var release string
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		catalog, _, err := t.catalog(ctx, dialect)
		if err != nil {
			return err
		}
		desired, err := t.desired(dialect)
		if err != nil {
			return err
		}
		if err := migrations.ValidateTarget(catalog, string(desired)); err != nil {
			return fmt.Errorf("migrationtool: %s target: %w", dialect, err)
		}
		if release != "" && catalog.Release != release {
			return fmt.Errorf("migrationtool: dialect catalogs declare different library releases; use release after sealing all dialects")
		}
		release = catalog.Release
		known := map[string]bool{"catalog.json": true}
		for _, step := range catalog.Migrations {
			known[step.File], known[step.Schema] = true, true
		}
		entries, err := os.ReadDir(filepath.Join(t.Root, "internal/migrations", dialect))
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !known[entry.Name()] && !strings.HasPrefix(entry.Name(), ".") {
				return fmt.Errorf("migrationtool: undeclared artifact %s/%s", dialect, entry.Name())
			}
		}
	}
	return nil
}

// SetRelease updates release metadata for all dialects while preserving every
// migration identity. Releases without schema changes need no empty SQL file.
func (t Tool) SetRelease(ctx context.Context, release string) error {
	if !releaseName.MatchString(release) {
		return fmt.Errorf("migrationtool: require a vMAJOR.MINOR.PATCH release")
	}
	t, err := t.prepare()
	if err != nil {
		return err
	}
	unlock, err := t.lock()
	if err != nil {
		return err
	}
	defer unlock()
	writes := make(map[string][]byte, 3)
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		catalog, _, err := t.catalog(ctx, dialect)
		if err != nil {
			return err
		}
		desired, err := t.desired(dialect)
		if err != nil {
			return err
		}
		if err := migrations.ValidateTarget(catalog, string(desired)); err != nil {
			return err
		}
		catalog.Release = release
		contents, err := jsonBytes(catalog)
		if err != nil {
			return err
		}
		writes[dialect] = contents
	}
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := replaceFile(filepath.Join(t.Root, "internal/migrations", dialect, "catalog.json"), writes[dialect]); err != nil {
			return err
		}
	}
	return nil
}

func replaceFile(path string, contents []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".catalog-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
