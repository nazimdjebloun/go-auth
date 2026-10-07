package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

const appRoleColumns = "id,slug,name,description,is_enabled,system_key,revision,created_at,updated_at"

func scanAppRole(s scanner) (*domain.AppRole, error) {
	var role domain.AppRole
	err := s.Scan(&role.ID, &role.Slug, &role.Name, &role.Description, &role.IsEnabled, &role.SystemKey, &role.Revision, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	role.PermissionKeys = []string{}
	return &role, err
}

// RoleByID reads the persistent identity, not grants or a legacy role string.
func (r *AppPermissionsRepository) RoleByID(ctx context.Context, id string) (*domain.AppRole, error) {
	return scanAppRole(r.db.QueryRowContext(ctx, "SELECT "+appRoleColumns+" FROM app_roles WHERE id=$1", id))
}

// RoleBySlug resolves protected/default roles through unique immutable slugs.
func (r *AppPermissionsRepository) RoleBySlug(ctx context.Context, slug string) (*domain.AppRole, error) {
	return scanAppRole(r.db.QueryRowContext(ctx, "SELECT "+appRoleColumns+" FROM app_roles WHERE slug=$1", slug))
}

// ListAppRoles returns a page in deterministic slug order.
func (r *AppPermissionsRepository) ListAppRoles(ctx context.Context, limit, offset int) ([]domain.AppRole, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+appRoleColumns+" FROM app_roles ORDER BY slug LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := []domain.AppRole{}
	for rows.Next() {
		role, err := scanAppRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, *role)
	}
	return roles, rows.Err()
}

// InsertAppRole never invents hierarchy or automatic grants.
func (r *AppPermissionsRepository) InsertAppRole(ctx context.Context, role *domain.AppRole) error {
	_, err := r.db.ExecContext(ctx, "INSERT INTO app_roles ("+appRoleColumns+") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", role.ID, role.Slug, role.Name, role.Description, role.IsEnabled, role.SystemKey, role.Revision, role.CreatedAt, role.UpdatedAt)
	return wrapCreateErr(r.db.Driver(), err)
}

// UpdateAppRole guards revisions and refuses protected identities at SQL level.
func (r *AppPermissionsRepository) UpdateAppRole(ctx context.Context, role *domain.AppRole, expected uint64) (bool, error) {
	return affected(r.db.ExecContext(ctx, `UPDATE app_roles SET name=$1,description=$2,is_enabled=$3,revision=revision+1,updated_at=$4 WHERE id=$5 AND revision=$6 AND system_key IS NULL`, role.Name, role.Description, role.IsEnabled, role.UpdatedAt, role.ID, expected))
}

// DeleteAppRole only deletes custom roles; assigned-role FKs remain restrictive.
func (r *AppPermissionsRepository) DeleteAppRole(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM app_roles WHERE id=$1 AND system_key IS NULL`, id)
	return err
}

// RoleUserCount supports explicit in-use errors before restrictive deletion.
func (r *AppPermissionsRepository) RoleUserCount(ctx context.Context, id string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE app_role_id=$1`, id).Scan(&n)
	return n, err
}

// ReplaceRoleGrants joins the service transaction and records the grant actor.
func (r *AppPermissionsRepository) ReplaceRoleGrants(ctx context.Context, id string, permissions []string, actor string, now time.Time) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM app_role_permissions WHERE role_id=$1`, id); err != nil {
		return err
	}
	for _, permission := range permissions {
		if _, err := r.db.ExecContext(ctx, `INSERT INTO app_role_permissions(role_id,permission_id,granted_by,created_at) VALUES ($1,$2,$3,$4)`, id, permission, actor, now); err != nil {
			return err
		}
	}
	return nil
}

// BumpRoleRevision invalidates pending grant/assignment writes after bulk deletion.
func (r *AppPermissionsRepository) BumpRoleRevision(ctx context.Context, id string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE app_roles SET revision=revision+1,updated_at=$1 WHERE id=$2 AND system_key IS NULL`, now, id)
	return err
}

// SetUserAppRole replaces exactly one role, checking the assignment revision.
func (r *AppPermissionsRepository) SetUserAppRole(ctx context.Context, userID, roleID string, expected uint64, now time.Time) (bool, error) {
	return affected(r.db.ExecContext(ctx, `UPDATE users SET app_role_id=$1,app_role_assignment_revision=app_role_assignment_revision+1,updated_at=$2 WHERE id=$3 AND app_role_assignment_revision=$4`, roleID, now, userID, expected))
}
