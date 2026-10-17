// Package migrationtool prepares reviewed auth migrations for library maintainers.
// It never connects to a consuming application's database.
package migrationtool

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nazimdjebloun/go-auth/internal/migrations"
)

//go:embed toolchain.json
var toolchainJSON []byte

var releaseName = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[a-zA-Z0-9.-]+)?$`)
var atlasVersion = regexp.MustCompile(`(?m)^atlas(?: community)? version (v[0-9]+\.[0-9]+\.[0-9]+)(?:[-+\s]|$)`)

type toolchain struct {
	AtlasVersion string            `json:"atlasVersion"`
	DevDatabases map[string]string `json:"devDatabases"`
}

type commandRunner func(context.Context, string, string, ...string) ([]byte, error)

// Tool operates on a maintainer checkout. BaseRef must contain the immutable
// catalog to preserve; HEAD is appropriate while preparing the first release.
type Tool struct {
	Root      string
	AtlasPath string
	BaseRef   string
	// Diagnostics receives raw Atlas output only on failure. Nil keeps it
	// private; use a trusted maintainer terminal because output may contain SQL.
	Diagnostics io.Writer
	run         commandRunner
}

// DraftOptions identifies the next ordered release step. Manual prepares a
// skeleton for transformations that a structural diff cannot infer.
type DraftOptions struct {
	Driver    string
	Release   string
	Sequence  int
	Directory string
	Manual    bool
}

// Draft records the exact inputs reviewed before sealing a new catalog entry.
// Maintainers edit execution mode and data checks along with migration.sql.
type Draft struct {
	Format              int                     `json:"format"`
	Dialect             string                  `json:"dialect"`
	Release             string                  `json:"release"`
	ID                  int64                   `json:"id"`
	Sequence            int                     `json:"sequence"`
	File                string                  `json:"file"`
	BaseRevision        int64                   `json:"baseRevision"`
	BaseCatalogChecksum string                  `json:"baseCatalogChecksum"`
	DesiredChecksum     string                  `json:"desiredChecksum"`
	Transactional       bool                    `json:"transactional"`
	SQLiteRebuild       bool                    `json:"sqliteRebuild,omitempty"`
	Checks              []string                `json:"checks"`
	Preconditions       []string                `json:"preconditions,omitempty"`
	Retry               *migrations.RetryPolicy `json:"retry,omitempty"`
}

func (t Tool) prepare() (Tool, error) {
	if t.Root == "" {
		t.Root = "."
	}
	root, err := filepath.Abs(t.Root)
	if err != nil {
		return t, err
	}
	t.Root = root
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || !strings.HasPrefix(string(module), "module github.com/nazimdjebloun/go-auth\n") &&
		!strings.HasPrefix(string(module), "module github.com/nazimdjebloun/go-auth\r\n") {
		return t, fmt.Errorf("migrationtool: --root must be a go-auth maintainer checkout")
	}
	if t.AtlasPath == "" {
		t.AtlasPath = "atlas"
	}
	if t.BaseRef == "" {
		t.BaseRef = "HEAD"
	}
	if strings.HasPrefix(t.BaseRef, "-") {
		return t, fmt.Errorf("migrationtool: --base-ref must be a Git ref")
	}
	if t.run == nil {
		t.run = runCommand
	}
	return t, nil
}

func runCommand(ctx context.Context, executable, directory string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	// Preserve partial diagnostics and both process/context causes. Callers
	// decide whether raw output is safe to display; errors never include it.
	return output, errors.Join(err, ctx.Err())
}

func (t Tool) catalog(ctx context.Context, driver string) (migrations.Catalog, []byte, error) {
	catalog, err := migrations.ReadCatalog(os.DirFS(filepath.Join(t.Root, "internal/migrations")), driver)
	if err != nil {
		return catalog, nil, err
	}
	manifest, err := os.ReadFile(filepath.Join(t.Root, "internal/migrations", catalog.Dialect, "catalog.json"))
	if err == nil {
		err = t.checkPrefix(ctx, catalog)
	}
	return catalog, manifest, err
}

func (t Tool) checkPrefix(ctx context.Context, catalog migrations.Catalog) error {
	// Command arguments are passed directly, never assembled into shell text.
	ref, err := t.run(ctx, "git", t.Root, "rev-parse", "--verify", t.BaseRef+"^{commit}")
	if err != nil {
		return fmt.Errorf("migrationtool: resolve immutable --base-ref: %w", err)
	}
	commit := strings.TrimSpace(string(ref))
	if matched, _ := regexp.MatchString(`^[a-f0-9]{40,64}$`, commit); !matched {
		return fmt.Errorf("migrationtool: invalid base commit identity")
	}
	gitFile := func(name string) ([]byte, error) {
		return t.run(ctx, "git", t.Root, "show", commit+":internal/migrations/"+catalog.Dialect+"/"+name)
	}
	contents, err := gitFile("catalog.json")
	if err != nil {
		return fmt.Errorf("migrationtool: --base-ref must contain a %s migration catalog: %w", catalog.Dialect, err)
	}
	var base migrations.Catalog
	if err := json.Unmarshal(contents, &base); err != nil {
		return fmt.Errorf("migrationtool: invalid base catalog: %w", err)
	}
	if tag := strings.TrimPrefix(t.BaseRef, "refs/tags/"); releaseName.MatchString(tag) && base.Release != tag {
		return fmt.Errorf("migrationtool: %s base catalog release does not match tag %s", catalog.Dialect, tag)
	}
	if base.Format != catalog.Format || base.Dialect != catalog.Dialect || base.BootstrapRevision != catalog.BootstrapRevision ||
		len(base.Migrations) == 0 || len(base.Migrations) > len(catalog.Migrations) ||
		base.TargetRevision != base.Migrations[len(base.Migrations)-1].ID {
		return fmt.Errorf("migrationtool: source catalog does not preserve the immutable base")
	}
	for i, previous := range base.Migrations {
		step := catalog.Migrations[i]
		oldMetadata, _ := json.Marshal(previous)
		newMetadata, _ := json.Marshal(step)
		if !bytes.Equal(oldMetadata, newMetadata) {
			return fmt.Errorf("migrationtool: immutable metadata changed at %s/%06d", catalog.Dialect, previous.ID)
		}
		for _, artifact := range []struct{ name, digest string }{
			{previous.File, previous.Checksum}, {previous.Schema, previous.SchemaChecksum},
		} {
			contents, err := gitFile(artifact.name)
			if err != nil || checksum(contents) != artifact.digest {
				return fmt.Errorf("migrationtool: immutable base artifact invalid at %s/%s", catalog.Dialect, artifact.name)
			}
		}
	}
	return nil
}

func (t Tool) desired(dialect string) ([]byte, error) {
	contents, err := os.ReadFile(filepath.Join(t.Root, "internal/schema", dialect+".sql"))
	return bytes.ReplaceAll(contents, []byte("\r\n"), []byte("\n")), err
}

func (t Tool) atlas(ctx context.Context, directory string, args ...string) ([]byte, error) {
	output, err := t.run(ctx, t.AtlasPath, directory, args...)
	if err != nil {
		operation := "command"
		if len(args) > 0 && args[0] == "version" {
			operation = "version"
		} else if len(args) > 1 && args[0] == "migrate" && (args[1] == "hash" || args[1] == "diff") {
			operation = "migrate " + args[1]
		}
		var writeErr error
		if t.Diagnostics != nil && len(output) != 0 {
			var written int
			written, writeErr = t.Diagnostics.Write(output)
			if written != len(output) && writeErr == nil {
				writeErr = io.ErrShortWrite
			}
		}
		return nil, &atlasError{
			operation: operation, cause: errors.Join(err, writeErr, ctx.Err()),
			diagnosticsFailed: writeErr != nil, outputHidden: t.Diagnostics == nil && len(output) != 0,
		}
	}
	return output, nil
}

// Keep automatic error rendering independent of output, argv and arbitrary
// runner/writer messages. Unwrap retains the full causes for deliberate inspection.
type atlasError struct {
	operation         string
	cause             error
	diagnosticsFailed bool
	outputHidden      bool
}

func (e *atlasError) Error() string {
	message := "migrationtool: Atlas " + e.operation + " failed"
	var exit *exec.ExitError
	var unavailable *exec.Error
	switch {
	case errors.Is(e.cause, context.Canceled):
		message += ": canceled"
	case errors.Is(e.cause, context.DeadlineExceeded):
		message += ": deadline exceeded"
	case errors.As(e.cause, &exit):
		message += fmt.Sprintf(": exit status %d", exit.ExitCode())
	case errors.As(e.cause, &unavailable), errors.Is(e.cause, os.ErrNotExist), errors.Is(e.cause, os.ErrPermission):
		message += ": executable unavailable"
	}
	if e.diagnosticsFailed {
		message += "; diagnostic output could not be written"
	}
	if e.outputHidden {
		message += "; use --diagnostics in a trusted maintainer terminal for raw output"
	}
	return message
}

func (e *atlasError) Unwrap() error { return e.cause }

func (t Tool) pinnedAtlas(ctx context.Context) (toolchain, error) {
	var pin toolchain
	if err := json.Unmarshal(toolchainJSON, &pin); err != nil {
		return pin, err
	}
	output, err := t.atlas(ctx, t.Root, "version")
	if err != nil {
		return pin, err
	}
	match := atlasVersion.FindSubmatch(output)
	if match == nil || string(match[1]) != pin.AtlasVersion {
		return pin, fmt.Errorf("migrationtool: install pinned Atlas %s", pin.AtlasVersion)
	}
	return pin, nil
}

func (t Tool) lock() (func(), error) {
	path := filepath.Join(t.Root, ".migration-author.lock")
	if err := writeNew(path, fmt.Appendf(nil, "pid=%d\n", os.Getpid())); err != nil {
		return nil, fmt.Errorf("migrationtool: authoring lock unavailable; inspect %s: %w", path, err)
	}
	return func() { _ = os.Remove(path) }, nil
}

func checksum(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func readJSON(path string, target any) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("migrationtool: decode %s: %w", filepath.Base(path), err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("migrationtool: trailing content in %s", filepath.Base(path))
	}
	return nil
}

func jsonBytes(value any) ([]byte, error) {
	contents, err := json.MarshalIndent(value, "", "  ")
	return append(contents, '\n'), err
}

func writeNew(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(contents)
	result := errors.Join(writeErr, file.Close())
	if result != nil {
		_ = os.Remove(path) // This call created the file exclusively.
	}
	return result
}
