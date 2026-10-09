package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// AppPermissionsRepository shares the existing DB's transaction context.
type AppPermissionsRepository struct{ db *DB }

// NewAppPermissionsRepository uses the caller's database and transaction manager.
func NewAppPermissionsRepository(db *DB) *AppPermissionsRepository {
	return &AppPermissionsRepository{db: db}
}

var (
	_ port.AppPermissionReader   = (*AppPermissionsRepository)(nil)
	_ port.AppPermissionWriter   = (*AppPermissionsRepository)(nil)
	_ port.AppRoleStore          = (*AppPermissionsRepository)(nil)
	_ port.AppAuthorizationState = (*AppPermissionsRepository)(nil)
)

const appPermissionColumns = "id, permission_key, name, description, is_enabled, is_system, revision, created_at, updated_at"

func scanAppPermission(s scanner) (*domain.AppPermission, error) {
	var p domain.AppPermission
	err := s.Scan(&p.ID, &p.Key, &p.Name, &p.Description, &p.IsEnabled, &p.IsSystem, &p.Revision, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

// PermissionByKey returns nil for an uninstalled definition.
func (r *AppPermissionsRepository) PermissionByKey(ctx context.Context, key string) (*domain.AppPermission, error) {
	return scanAppPermission(r.db.QueryRowContext(ctx, r.currentQuery(ctx, "SELECT "+appPermissionColumns+" FROM app_permissions WHERE permission_key=$1"), key))
}

// PermissionByID resolves an installed definition for guarded CRUD.
func (r *AppPermissionsRepository) PermissionByID(ctx context.Context, id string) (*domain.AppPermission, error) {
	return scanAppPermission(r.db.QueryRowContext(ctx, r.currentQuery(ctx, "SELECT "+appPermissionColumns+" FROM app_permissions WHERE id=$1"), id))
}

// ListAppPermissions lists installed records, never uninstalled catalog entries.
func (r *AppPermissionsRepository) ListAppPermissions(
	ctx context.Context,
	limit, offset int,
) (result []domain.AppPermission, err error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+appPermissionColumns+" FROM app_permissions ORDER BY permission_key LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	result = []domain.AppPermission{}
	for rows.Next() {
		p, err := scanAppPermission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *p)
	}
	return result, rows.Err()
}

// InsertAppPermission preserves server-owned metadata and ownership.
func (r *AppPermissionsRepository) InsertAppPermission(ctx context.Context, p *domain.AppPermission) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO app_permissions (`+appPermissionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, p.ID, p.Key, p.Name, p.Description, p.IsEnabled, p.IsSystem, p.Revision, p.CreatedAt, p.UpdatedAt)
	return wrapCreateErr(r.db.Driver(), err)
}

// UpdateAppPermission cannot change library definitions, keys or ownership.
func (r *AppPermissionsRepository) UpdateAppPermission(ctx context.Context, p *domain.AppPermission, expected uint64) (bool, error) {
	return affected(r.db.ExecContext(ctx, `UPDATE app_permissions SET name=$1,description=$2,is_enabled=$3,revision=revision+1,updated_at=$4 WHERE id=$5 AND revision=$6 AND is_system=false`, p.Name, p.Description, p.IsEnabled, p.UpdatedAt, p.ID, expected))
}

// DeleteAppPermission relies on RESTRICT so services must handle references first.
func (r *AppPermissionsRepository) DeleteAppPermission(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM app_permissions WHERE id=$1`, id)
	return err
}

// PermissionGrantRoles supplies affected role IDs for cleanup and revision bumps.
func (r *AppPermissionsRepository) PermissionGrantRoles(ctx context.Context, id string) ([]string, error) {
	return r.strings(ctx, `SELECT role_id FROM app_role_permissions WHERE permission_id=$1 ORDER BY role_id`, id)
}

// RemovePermissionGrants must participate in the definition deletion transaction.
func (r *AppPermissionsRepository) RemovePermissionGrants(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM app_role_permissions WHERE permission_id=$1`, id)
	return err
}

// RolePermissionKeys excludes disabled definitions from effective access.
func (r *AppPermissionsRepository) RolePermissionKeys(ctx context.Context, id string) ([]string, error) {
	return r.strings(ctx, `SELECT p.permission_key FROM app_permissions p JOIN app_role_permissions g ON g.permission_id=p.id WHERE g.role_id=$1 AND p.is_enabled=true ORDER BY p.permission_key`, id)
}

func (r *AppPermissionsRepository) strings(ctx context.Context, query string, args ...any) (result []string, err error) {
	rows, err := r.db.QueryContext(ctx, r.currentQuery(ctx, query), args...)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	result = []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *AppPermissionsRepository) currentQuery(ctx context.Context, query string) string {
	if _, ok := txFromContext(ctx); ok && (r.db.Driver() == "mysql" || r.db.Driver() == "postgres") {
		return query + " FOR UPDATE"
	}
	return query
}

// RoleGrantKeys includes disabled definitions for management/delegation checks.
func (r *AppPermissionsRepository) RoleGrantKeys(ctx context.Context, id string) ([]string, error) {
	return r.strings(ctx, `SELECT p.permission_key FROM app_permissions p JOIN app_role_permissions g ON g.permission_id=p.id WHERE g.role_id=$1 ORDER BY p.permission_key`, id)
}

// EnabledBusinessPermissionKeys supplies the database portion of full admin access.
func (r *AppPermissionsRepository) EnabledBusinessPermissionKeys(ctx context.Context) ([]string, error) {
	return r.strings(ctx, `SELECT permission_key FROM app_permissions WHERE is_system=false AND is_enabled=true ORDER BY permission_key`)
}

// AppStateRevision is zero until trusted initialization completes.
func (r *AppPermissionsRepository) AppStateRevision(ctx context.Context) (uint64, error) {
	var revision uint64
	err := r.db.QueryRowContext(ctx, `SELECT revision FROM app_authorization_state WHERE id=1`).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return revision, err
}

// LockAppState takes a current locking read before management decisions.
func (r *AppPermissionsRepository) LockAppState(ctx context.Context) error {
	if _, ok := txFromContext(ctx); !ok {
		return errors.New("app authorization lock requires transaction")
	}
	query := `SELECT revision FROM app_authorization_state WHERE id=1 FOR UPDATE`
	if r.db.UsesPositionalParams() && r.db.Driver() != "mysql" {
		if _, err := r.db.ExecContext(ctx, `UPDATE app_authorization_state SET id=id WHERE id=1`); err != nil {
			return err
		}
		query = `SELECT revision FROM app_authorization_state WHERE id=1`
	}
	var revision uint64
	if err := r.db.QueryRowContext(ctx, query).Scan(&revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrAppPermissionsNotInitialized
		}
		return fmt.Errorf("locking app authorization: %w", err)
	}
	return nil
}

// InitializeAppState is atomic with protected role and first-admin creation.
func (r *AppPermissionsRepository) InitializeAppState(ctx context.Context, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO app_authorization_state(id,revision,created_at) VALUES (1,1,$1)`, now)
	return wrapCreateErr(r.db.Driver(), err)
}

// BumpAppState marks a committed change without modifying account assignments.
func (r *AppPermissionsRepository) BumpAppState(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `UPDATE app_authorization_state SET revision=revision+1 WHERE id=1`)
	return err
}
