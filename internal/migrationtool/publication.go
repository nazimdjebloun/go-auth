package migrationtool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nazimdjebloun/go-auth/internal/migrations"
)

// CheckOptions adds release safeguards to the ordinary offline catalog check.
// Replay uses only pinned disposable development databases, never an app DSN.
type CheckOptions struct {
	Published bool
	Release   string
	Replay    bool
}

func (t Tool) CheckPublication(ctx context.Context, options CheckOptions) error {
	if options.Release != "" && !releaseName.MatchString(options.Release) {
		return fmt.Errorf("migrationtool: --release must be vMAJOR.MINOR.PATCH")
	}
	t, err := t.prepare()
	if err != nil {
		return err
	}
	if err := t.Check(ctx); err != nil {
		return err
	}
	var catalogs []migrations.Catalog
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		catalog, err := migrations.ReadCatalog(os.DirFS(filepath.Join(t.Root, "internal/migrations")), dialect)
		if err != nil {
			return err
		}
		if options.Release != "" && catalog.Release != options.Release {
			return fmt.Errorf("migrationtool: %s catalog declares %s; release requires %s", dialect, catalog.Release, options.Release)
		}
		catalogs = append(catalogs, catalog)
	}
	if options.Published {
		if err := t.checkPublished(ctx, catalogs); err != nil {
			return err
		}
	}
	if options.Replay {
		if err := t.replay(ctx, catalogs); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (t Tool) checkPublished(ctx context.Context, catalogs []migrations.Catalog) error {
	output, err := t.run(ctx, "git", t.Root, "tag", "--list", "v*")
	if err != nil {
		return fmt.Errorf("migrationtool: list published release tags: %w", err)
	}
	for _, tag := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if !releaseName.MatchString(tag) {
			continue
		}
		ref := "refs/tags/" + tag
		paths, err := t.run(ctx, "git", t.Root, "ls-tree", "-r", "--name-only", ref+"^{commit}", "--",
			"internal/migrations/postgres/catalog.json", "internal/migrations/mysql/catalog.json", "internal/migrations/sqlite/catalog.json")
		if err != nil {
			return fmt.Errorf("migrationtool: inspect release %s: %w", tag, err)
		}
		count := len(strings.Fields(string(paths)))
		if count == 0 {
			continue // Legacy releases predate the migration catalog.
		}
		if count != len(catalogs) {
			return fmt.Errorf("migrationtool: release %s contains only part of the dialect catalog", tag)
		}
		base := t
		base.BaseRef = ref
		for _, catalog := range catalogs {
			if err := base.checkPrefix(ctx, catalog); err != nil {
				return fmt.Errorf("migrationtool: published release %s: %w", tag, err)
			}
		}
	}
	return nil
}

func (t Tool) replay(ctx context.Context, catalogs []migrations.Catalog) error {
	pin, err := t.pinnedAtlas(ctx)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "goauth-publication-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	for _, catalog := range catalogs {
		desired, err := t.desired(catalog.Dialect)
		if err != nil {
			return err
		}
		remaining, err := t.diff(ctx, pin, filepath.Join(work, catalog.Dialect), catalog, desired)
		if err != nil {
			return fmt.Errorf("migrationtool: %s replay: %w", catalog.Dialect, err)
		}
		if len(remaining) != 0 {
			return fmt.Errorf("migrationtool: %s history replay requires a structural diff to reach the canonical schema", catalog.Dialect)
		}
	}
	return ctx.Err()
}
