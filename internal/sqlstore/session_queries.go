package sqlstore

const (
	sessionCols = `id, user_id, token_hash, refresh_token_hash, prev_refresh_token_hash, ip_address, user_agent, is_revoked, expires_at, refresh_expires_at, refresh_rotated_at, created_at, revoked_at, last_active_at, active_org_id, active_org_role`

	sessionCreateQuery = `INSERT INTO sessions (` + sessionCols + `) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	sessionByTokenHashQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE token_hash = $1`

	sessionByRefreshHashQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE refresh_token_hash = $1`

	sessionByPreviousRefreshHashQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE prev_refresh_token_hash = $1`

	sessionListByUserQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > $2 ORDER BY created_at DESC`

	sessionCountByUserQuery = `SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > $2`

	sessionListByUserPaginatedQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`

	sessionDeleteByTokenHashQuery = `DELETE FROM sessions WHERE token_hash = $1`

	sessionDeleteByIDQuery = `DELETE FROM sessions WHERE id = $1`

	sessionRevokeByIDForUserQuery = `DELETE FROM sessions WHERE id = $1 AND user_id = $2`

	sessionDeleteByUserQuery = `DELETE FROM sessions WHERE user_id = $1`

	sessionDeleteByUserExceptQuery = `DELETE FROM sessions WHERE user_id = $1 AND id != $2`

	sessionDeleteExpiredQuery = `DELETE FROM sessions WHERE refresh_expires_at < $1`

	sessionUpdateLastActiveQuery = `UPDATE sessions SET last_active_at = $1 WHERE token_hash = $2`

	sessionRotateRefreshQuery = `UPDATE sessions
		SET token_hash              = $1,
		    refresh_token_hash      = $2,
		    prev_refresh_token_hash = refresh_token_hash,
		    refresh_rotated_at      = $3,
		    expires_at              = $4
		WHERE refresh_token_hash = $5
		  AND is_revoked = false
		  AND refresh_expires_at > $6
		  AND created_at > $7
		RETURNING ` + sessionCols

	sessionRotateRefreshNoReturningQuery = `UPDATE sessions
		SET token_hash              = $1,
		    refresh_token_hash      = $2,
		    prev_refresh_token_hash = refresh_token_hash,
		    refresh_rotated_at      = $3,
		    expires_at              = $4
		WHERE refresh_token_hash = $5
		  AND is_revoked = false
		  AND refresh_expires_at > $6
		  AND created_at > $7`

	sessionUpdateActiveOrgRoleQuery = `UPDATE sessions SET active_org_role = $1 WHERE user_id = $2 AND active_org_id = $3 AND is_revoked = false`

	sessionClearActiveOrgForUserQuery = `UPDATE sessions SET active_org_id = NULL, active_org_role = NULL WHERE user_id = $1 AND active_org_id = $2 AND is_revoked = false`
	sessionClearActiveOrgQuery        = `UPDATE sessions SET active_org_id = NULL, active_org_role = NULL WHERE id = $1 AND is_revoked = false`

	sessionClearActiveOrgForAllMembersQuery = `UPDATE sessions SET active_org_id = NULL, active_org_role = NULL WHERE active_org_id = $1 AND is_revoked = false`

	sessionSetActiveOrgQuery = `UPDATE sessions SET active_org_id = $1, active_org_role = $2 WHERE id = $3 AND is_revoked = false`
)
