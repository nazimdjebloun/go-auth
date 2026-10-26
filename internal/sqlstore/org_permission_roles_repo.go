package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

const orgRoleColumns = "id,org_id,slug,name,description,is_enabled,system_key,revision,created_at,updated_at"

func scanOrgRole(s scanner) (*domain.OrgPermissionRole, error) {
	var role domain.OrgPermissionRole
	err := s.Scan(&role.ID, &role.OrgID, &role.Slug, &role.Name, &role.Description, &role.IsEnabled, &role.SystemKey, &role.Revision, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	role.PermissionKeys = []string{}
	return &role, err
}

// RoleByID reads the persistent org identity rather than the fixed account role.
func (r *OrgPermissionsRepository) RoleByID(ctx context.Context, orgID, id string) (*domain.OrgPermissionRole, error) {
	return scanOrgRole(r.db.QueryRowContext(ctx, r.currentQuery(ctx, "SELECT "+orgRoleColumns+" FROM org_roles WHERE org_id=$1 AND id=$2"), orgID, id))
}

// RoleBySlug resolves protected/default roles through unique immutable slugs.
func (r *OrgPermissionsRepository) RoleBySlug(ctx context.Context, orgID, slug string) (*domain.OrgPermissionRole, error) {
	return scanOrgRole(r.db.QueryRowContext(ctx, r.currentQuery(ctx, "SELECT "+orgRoleColumns+" FROM org_roles WHERE org_id=$1 AND slug=$2"), orgID, slug))
}

// ListOrgRoles returns a page in deterministic slug order.
func (r *OrgPermissionsRepository) ListOrgRoles(
	ctx context.Context,
	orgID string, limit, offset int,
) (roles []domain.OrgPermissionRole, err error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+orgRoleColumns+" FROM org_roles WHERE org_id=$1 ORDER BY slug LIMIT $2 OFFSET $3", orgID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	roles = []domain.OrgPermissionRole{}
	for rows.Next() {
		role, err := scanOrgRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, *role)
	}
	return roles, rows.Err()
}

// InsertOrgRole never invents hierarchy or automatic grants.
func (r *OrgPermissionsRepository) InsertOrgRole(ctx context.Context, role *domain.OrgPermissionRole) error {
	_, err := r.db.ExecContext(ctx, "INSERT INTO org_roles ("+orgRoleColumns+") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", role.ID, role.OrgID, role.Slug, role.Name, role.Description, role.IsEnabled, role.SystemKey, role.Revision, role.CreatedAt, role.UpdatedAt)
	return wrapCreateErr(r.db.Driver(), err)
}

// UpdateOrgRole guards revisions and refuses protected identities at SQL level.
func (r *OrgPermissionsRepository) UpdateOrgRole(ctx context.Context, role *domain.OrgPermissionRole, expected uint64) (bool, error) {
	return affected(r.db.ExecContext(ctx, `UPDATE org_roles SET name=$1,description=$2,is_enabled=$3,revision=revision+1,updated_at=$4 WHERE org_id=$5 AND id=$6 AND revision=$7 AND system_key IS NULL`, role.Name, role.Description, role.IsEnabled, role.UpdatedAt, role.OrgID, role.ID, expected))
}

// DeleteOrgRole only deletes custom roles; assigned-role FKs remain restrictive.
func (r *OrgPermissionsRepository) DeleteOrgRole(ctx context.Context, orgID, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM org_roles WHERE org_id=$1 AND id=$2 AND system_key IS NULL`, orgID, id)
	return err
}

// RoleUserCount includes pending invitations, which must not silently lose their role.
func (r *OrgPermissionsRepository) RoleUserCount(ctx context.Context, orgID, id string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM org_member_roles WHERE org_id=$1 AND role_id=$2) + (SELECT COUNT(*) FROM org_invite_roles WHERE org_id=$3 AND role_id=$4)`, orgID, id, orgID, id).Scan(&count)
	return count, err
}

// ReplaceRoleGrants joins the service transaction and records the grant actor.
func (r *OrgPermissionsRepository) ReplaceRoleGrants(ctx context.Context, orgID, id string, permissions []string, actor string, now time.Time) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM org_role_permissions WHERE org_id=$1 AND role_id=$2`, orgID, id); err != nil {
		return err
	}
	for _, permission := range permissions {
		if _, err := r.db.ExecContext(ctx, `INSERT INTO org_role_permissions(org_id,role_id,permission_id,granted_by,created_at) VALUES ($1,$2,$3,$4,$5)`, orgID, id, permission, actor, now); err != nil {
			return err
		}
	}
	return nil
}

// BumpRoleRevision invalidates pending grant/assignment writes after bulk deletion.
func (r *OrgPermissionsRepository) BumpRoleRevision(ctx context.Context, orgID, id string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE org_roles SET revision=revision+1,updated_at=$1 WHERE org_id=$2 AND id=$3 AND system_key IS NULL`, now, orgID, id)
	return err
}

// MemberRole returns an explicit assignment; absence means the legacy built-in role.
func (r *OrgPermissionsRepository) MemberRole(ctx context.Context, orgID, userID string) (*domain.OrgPermissionRole, uint64, error) {
	var id string
	var revision uint64
	err := r.db.QueryRowContext(ctx, r.currentQuery(ctx, `SELECT role_id,revision FROM org_member_roles WHERE org_id=$1 AND user_id=$2`), orgID, userID).Scan(&id, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	role, err := r.RoleByID(ctx, orgID, id)
	return role, revision, err
}

// SetMemberRole guards replacement with the observed membership assignment revision.
func (r *OrgPermissionsRepository) SetMemberRole(ctx context.Context, orgID, userID, roleID string, expected uint64) (bool, error) {
	if expected == 0 {
		_, err := r.db.ExecContext(ctx, `INSERT INTO org_member_roles(org_id,user_id,role_id,revision) VALUES ($1,$2,$3,1)`, orgID, userID, roleID)
		if err != nil {
			return false, wrapCreateErr(r.db.Driver(), err)
		}
		return true, nil
	}
	return affected(r.db.ExecContext(ctx, `UPDATE org_member_roles SET role_id=$1,revision=revision+1 WHERE org_id=$2 AND user_id=$3 AND revision=$4`, roleID, orgID, userID, expected))
}

// SetInviteRole freezes the selected role revision in the invitation transaction.
func (r *OrgPermissionsRepository) SetInviteRole(ctx context.Context, orgID, inviteID, roleID string, revision uint64) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO org_invite_roles(org_id,invite_id,role_id,role_revision) VALUES ($1,$2,$3,$4)`, orgID, inviteID, roleID, revision)
	return err
}

// InviteRole loads the live role and the revision originally proposed by the invite.
func (r *OrgPermissionsRepository) InviteRole(ctx context.Context, orgID, inviteID string) (*domain.OrgPermissionRole, uint64, error) {
	var id string
	var revision uint64
	err := r.db.QueryRowContext(ctx, r.currentQuery(ctx, `SELECT role_id,role_revision FROM org_invite_roles WHERE org_id=$1 AND invite_id=$2`), orgID, inviteID).Scan(&id, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	role, err := r.RoleByID(ctx, orgID, id)
	return role, revision, err
}
