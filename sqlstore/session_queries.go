package sqlstore

const (
	sessionCols = `id, user_id, token_hash, refresh_token_hash, prev_refresh_token_hash, ip_address, user_agent, is_revoked, expires_at, refresh_expires_at, refresh_rotated_at, created_at, revoked_at, last_active_at`

	sessionCreateQuery = `INSERT INTO sessions (` + sessionCols + `) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	sessionByTokenHashQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE token_hash = $1`

	sessionByRefreshHashQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE refresh_token_hash = $1`

	sessionByPreviousRefreshHashQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE prev_refresh_token_hash = $1`

	sessionListByUserQuery = `SELECT ` + sessionCols + ` FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > $2 ORDER BY created_at DESC`

	sessionDeleteByTokenHashQuery = `DELETE FROM sessions WHERE token_hash = $1`

	sessionDeleteByIDQuery = `DELETE FROM sessions WHERE id = $1`

	sessionDeleteByUserQuery = `DELETE FROM sessions WHERE user_id = $1`

	sessionDeleteByUserExceptQuery = `DELETE FROM sessions WHERE user_id = $1 AND id != $2`

	sessionDeleteExpiredQuery = `DELETE FROM sessions WHERE expires_at < $1`

	sessionUpdateLastActiveQuery = `UPDATE sessions SET last_active_at = $1 WHERE token_hash = $2`

	sessionUpdateRefreshQuery = `UPDATE sessions SET token_hash = $1, refresh_token_hash = $2, prev_refresh_token_hash = $3, expires_at = $4, refresh_expires_at = $5, refresh_rotated_at = $6, last_active_at = $7 WHERE id = $8 AND refresh_token_hash = $9`
)
