package sqlstore

const (
	orgCols = "id, name, slug, created_by, owner_count, member_count, metadata, created_at, updated_at"

	orgCreateQuery = `INSERT INTO organizations (` + orgCols + `) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	orgByIDQuery = `SELECT ` + orgCols + ` FROM organizations WHERE id = $1`

	orgBySlugQuery = `SELECT ` + orgCols + ` FROM organizations WHERE slug = $1`

	orgUpdateQuery = `UPDATE organizations SET name = $1, slug = $2, metadata = $3, updated_at = $4 WHERE id = $5`

	orgDeleteQuery = `DELETE FROM organizations WHERE id = $1`

	orgAddMemberQuery = `INSERT INTO organization_members (org_id, user_id, role, joined_at) VALUES ($1, $2, $3, $4)`

	orgRemoveMemberQuery = `DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2`

	orgUpdateMemberRoleQuery = `UPDATE organization_members SET role = $1 WHERE org_id = $2 AND user_id = $3`

	orgGetMembershipQuery = `SELECT org_id, user_id, role, joined_at FROM organization_members WHERE org_id = $1 AND user_id = $2`

	orgListMembersCountQuery = `SELECT COUNT(*) FROM organization_members WHERE org_id = $1`

	orgListMembersQuery = `SELECT om.org_id, om.user_id, om.role, om.joined_at,
		u.id, u.email, u.name, u.role, u.is_verified, u.is_banned, u.created_at, u.updated_at
		FROM organization_members om
		JOIN users u ON u.id = om.user_id
		WHERE om.org_id = $1
		ORDER BY om.joined_at ASC
		LIMIT $2 OFFSET $3`

	orgListUserOrgsQuery = `SELECT o.id, o.name, o.slug, o.created_by, o.owner_count, o.member_count,
		o.metadata, o.created_at, o.updated_at
		FROM organizations o
		JOIN organization_members om ON om.org_id = o.id
		WHERE om.user_id = $1
		ORDER BY o.name ASC`

	orgIncrementOwnerCountQuery = `UPDATE users SET org_owner_count = org_owner_count + 1 WHERE id = $1 AND org_owner_count < $2`

	orgDecrementUserOwnerCountQuery = `UPDATE users SET org_owner_count = org_owner_count - 1 WHERE id = $1 AND org_owner_count > 0`

	orgIncrementOrgMemberCountQuery = `UPDATE organizations SET member_count = member_count + 1 WHERE id = $1 AND member_count < $2`

	orgDecrementOrgMemberCountQuery = `UPDATE organizations SET member_count = member_count - 1 WHERE id = $1 AND member_count > 0`

	orgTryDecrementOwnerCountQuery = `UPDATE organizations SET owner_count = owner_count - 1 WHERE id = $1 AND owner_count > 1`

	orgIncrementOrgOwnerCountQuery = `UPDATE organizations SET owner_count = owner_count + 1 WHERE id = $1`

	orgDecrementOwnerCountForOrgOwnersQuery = `UPDATE users SET org_owner_count = org_owner_count - 1
		WHERE id IN (SELECT user_id FROM organization_members WHERE org_id = $1 AND role = 'owner')`

	orgInviteCols = "id, org_id, email, role, code_hash, invited_by, expires_at, created_at"

	orgInviteCreateQuery = `INSERT INTO organization_invites (` + orgInviteCols + `) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	orgInviteByIDQuery = `SELECT ` + orgInviteCols + ` FROM organization_invites WHERE id = $1`

	orgInviteByCodeHashQuery = `SELECT ` + orgInviteCols + ` FROM organization_invites WHERE code_hash = $1`

	orgInviteListByOrgIDQuery = `SELECT ` + orgInviteCols + ` FROM organization_invites WHERE org_id = $1 ORDER BY created_at DESC`

	orgInviteUpdateQuery = `UPDATE organization_invites SET code_hash = $1, expires_at = $2 WHERE id = $3`

	orgInviteDeleteQuery = `DELETE FROM organization_invites WHERE id = $1`

	orgInviteClaimQuery = `DELETE FROM organization_invites WHERE id = $1 AND expires_at > $2`
)
