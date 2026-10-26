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

// OrgPermissionsRepository shares the existing DB's transaction context.
type OrgPermissionsRepository struct{ db *DB }

// NewOrgPermissionsRepository uses the caller's database and transaction manager.
func NewOrgPermissionsRepository(db *DB) *OrgPermissionsRepository {
	return &OrgPermissionsRepository{db: db}
}

var (
	_ port.OrgPermissionReader    = (*OrgPermissionsRepository)(nil)
	_ port.OrgPermissionWriter    = (*OrgPermissionsRepository)(nil)
	_ port.OrgPermissionRoleStore = (*OrgPermissionsRepository)(nil)
	_ port.OrgAuthorizationState  = (*OrgPermissionsRepository)(nil)
)

const orgPermissionColumns = "id, org_id, permission_key, name, description, is_enabled, is_system, revision, created_at, updated_at"

func scanOrgPermission(s scanner) (*domain.OrgPermission, error) {
	var p domain.OrgPermission
	err := s.Scan(&p.ID, &p.OrgID, &p.Key, &p.Name, &p.Description, &p.IsEnabled, &p.IsSystem, &p.Revision, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

// PermissionByKey returns nil for an uninstalled definition.
func (r *OrgPermissionsRepository) PermissionByKey(ctx context.Context, orgID, key string) (*domain.OrgPermission, error) {
	return scanOrgPermission(r.db.QueryRowContext(ctx, r.currentQuery(ctx, "SELECT "+orgPermissionColumns+" FROM org_permissions WHERE org_id=$1 AND permission_key=$2"), orgID, key))
}

// PermissionByID resolves an installed definition for guarded CRUD.
func (r *OrgPermissionsRepository) PermissionByID(ctx context.Context, orgID, id string) (*domain.OrgPermission, error) {
	return scanOrgPermission(r.db.QueryRowContext(ctx, r.currentQuery(ctx, "SELECT "+orgPermissionColumns+" FROM org_permissions WHERE org_id=$1 AND id=$2"), orgID, id))
}

// ListOrgPermissions lists installed records, never uninstalled catalog entries.
func (r *OrgPermissionsRepository) ListOrgPermissions(
	ctx context.Context,
	orgID string, limit, offset int,
) (result []domain.OrgPermission, err error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+orgPermissionColumns+" FROM org_permissions WHERE org_id=$1 ORDER BY permission_key LIMIT $2 OFFSET $3", orgID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	result = []domain.OrgPermission{}
	for rows.Next() {
		p, err := scanOrgPermission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *p)
	}
	return result, rows.Err()
}

// InsertOrgPermission preserves server-owned metadata and ownership.
func (r *OrgPermissionsRepository) InsertOrgPermission(ctx context.Context, p *domain.OrgPermission) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO org_permissions (`+orgPermissionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.ID, p.OrgID, p.Key, p.Name, p.Description, p.IsEnabled, p.IsSystem, p.Revision, p.CreatedAt, p.UpdatedAt)
	return wrapCreateErr(r.db.Driver(), err)
}

// UpdateOrgPermission cannot change library definitions, keys or ownership.
func (r *OrgPermissionsRepository) UpdateOrgPermission(ctx context.Context, p *domain.OrgPermission, expected uint64) (bool, error) {
	return affected(r.db.ExecContext(ctx, `UPDATE org_permissions SET name=$1,description=$2,is_enabled=$3,revision=revision+1,updated_at=$4 WHERE org_id=$5 AND id=$6 AND revision=$7 AND is_system=false`, p.Name, p.Description, p.IsEnabled, p.UpdatedAt, p.OrgID, p.ID, expected))
}

// DeleteOrgPermission joins the guarded service transaction; services reject referenced business definitions.
func (r *OrgPermissionsRepository) DeleteOrgPermission(ctx context.Context, orgID, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM org_permissions WHERE org_id=$1 AND id=$2`, orgID, id)
	return err
}

// PermissionGrantRoles supplies affected role IDs for cleanup and revision bumps.
func (r *OrgPermissionsRepository) PermissionGrantRoles(ctx context.Context, orgID, id string) ([]string, error) {
	return r.strings(ctx, `SELECT role_id FROM org_role_permissions WHERE org_id=$1 AND permission_id=$2 ORDER BY role_id`, orgID, id)
}

// RemovePermissionGrants must participate in the definition deletion transaction.
func (r *OrgPermissionsRepository) RemovePermissionGrants(ctx context.Context, orgID, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM org_role_permissions WHERE org_id=$1 AND permission_id=$2`, orgID, id)
	return err
}

// RolePermissionKeys excludes disabled definitions from effective access.
func (r *OrgPermissionsRepository) RolePermissionKeys(ctx context.Context, orgID, id string) ([]string, error) {
	return r.strings(ctx, `SELECT p.permission_key FROM org_permissions p JOIN org_role_permissions g ON g.permission_id=p.id AND g.org_id=p.org_id WHERE g.org_id=$1 AND g.role_id=$2 AND p.is_enabled=true ORDER BY p.permission_key`, orgID, id)
}

func (r *OrgPermissionsRepository) strings(ctx context.Context, query string, args ...any) (result []string, err error) {
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

func (r *OrgPermissionsRepository) currentQuery(ctx context.Context, query string) string {
	if _, ok := txFromContext(ctx); ok && (r.db.Driver() == "mysql" || r.db.Driver() == "postgres") {
		return query + " FOR UPDATE"
	}
	return query
}

// RoleGrantKeys includes disabled definitions for management/delegation checks.
func (r *OrgPermissionsRepository) RoleGrantKeys(ctx context.Context, orgID, id string) ([]string, error) {
	return r.strings(ctx, `SELECT p.permission_key FROM org_permissions p JOIN org_role_permissions g ON g.permission_id=p.id AND g.org_id=p.org_id WHERE g.org_id=$1 AND g.role_id=$2 ORDER BY p.permission_key`, orgID, id)
}

// EnabledBusinessPermissionKeys supplies the database portion of full owner access.
func (r *OrgPermissionsRepository) EnabledBusinessPermissionKeys(ctx context.Context, orgID string) ([]string, error) {
	return r.strings(ctx, `SELECT permission_key FROM org_permissions WHERE org_id=$1 AND is_system=false AND is_enabled=true ORDER BY permission_key`, orgID)
}

// LockOrg serializes authorization and membership mutations on the same organization.
func (r *OrgPermissionsRepository) LockOrg(ctx context.Context, orgID string) error {
	if _, ok := txFromContext(ctx); !ok {
		return errors.New("org authorization lock requires transaction")
	}
	query := `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`
	if r.db.Driver() == "sqlite" || r.db.Driver() == "sqlite3" {
		if _, err := r.db.ExecContext(ctx, `UPDATE organizations SET id=id WHERE id=$1`, orgID); err != nil {
			return err
		}
		query = `SELECT id FROM organizations WHERE id=$1`
	}
	var id string
	if err := r.db.QueryRowContext(ctx, query, orgID).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrOrgNotFound
		}
		return fmt.Errorf("locking organization: %w", err)
	}
	return nil
}

// OrgStateRevision is zero until an owner initializes this organization.
func (r *OrgPermissionsRepository) OrgStateRevision(ctx context.Context, orgID string) (uint64, error) {
	var revision uint64
	err := r.db.QueryRowContext(ctx, r.currentQuery(ctx, `SELECT revision FROM org_authorization_state WHERE org_id=$1`), orgID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return revision, err
}

// InitializeOrgState commits with protected-role creation, never at startup.
func (r *OrgPermissionsRepository) InitializeOrgState(ctx context.Context, orgID string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO org_authorization_state(org_id,revision,created_at) VALUES ($1,1,$2)`, orgID, now)
	return wrapCreateErr(r.db.Driver(), err)
}

// BumpOrgState advances the organization's management revision in its transaction.
func (r *OrgPermissionsRepository) BumpOrgState(ctx context.Context, orgID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE org_authorization_state SET revision=revision+1 WHERE org_id=$1`, orgID)
	return err
}
