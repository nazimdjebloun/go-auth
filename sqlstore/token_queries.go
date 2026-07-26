package sqlstore

const (
	tokenCreateQuery = `INSERT INTO verification_tokens (id, user_id, email, token_hash, type, expires_at, used_at, code_verifier) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	tokenByHashQuery = `SELECT id, user_id, email, token_hash, type, expires_at, used_at, code_verifier FROM verification_tokens WHERE token_hash = $1`

	tokenHasValidByUserAndTypeQuery = `SELECT EXISTS(SELECT 1 FROM verification_tokens WHERE user_id=$1 AND type=$2 AND used_at IS NULL AND expires_at > $3)`

	tokenMarkUsedQuery = `UPDATE verification_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL`

	tokenDeleteExpiredQuery = `DELETE FROM verification_tokens WHERE expires_at < $1`

	tokenDeleteUnusedByUserAndTypeQuery = `DELETE FROM verification_tokens WHERE user_id=$1 AND type=$2 AND used_at IS NULL`
)
