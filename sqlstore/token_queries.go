package sqlstore

const (
	// tokenSelectColumns is the single source of truth for the verification
	// token column list and its order — scanToken depends on both.
	tokenSelectColumns = "id, user_id, email, token_hash, type, expires_at, used_at, created_at, code_verifier, attempts, resend_count"

	tokenCreateQuery = `INSERT INTO verification_tokens (id, user_id, email, token_hash, type, expires_at, used_at, code_verifier, attempts, resend_count, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	tokenByHashQuery = `SELECT ` + tokenSelectColumns + ` FROM verification_tokens WHERE token_hash = $1`

	tokenByIDQuery = `SELECT ` + tokenSelectColumns + ` FROM verification_tokens WHERE id = $1`

	tokenHasValidByUserAndTypeQuery = `SELECT EXISTS(SELECT 1 FROM verification_tokens WHERE user_id=$1 AND type=$2 AND used_at IS NULL AND expires_at > $3)`

	tokenGetLastByUserAndTypeQuery = `SELECT ` + tokenSelectColumns + ` FROM verification_tokens WHERE user_id=$1 AND type=$2 ORDER BY created_at DESC LIMIT 1`

	tokenMarkUsedQuery = `UPDATE verification_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL`

	tokenDeleteExpiredQuery = `DELETE FROM verification_tokens WHERE expires_at < $1`

	tokenDeleteUnusedByUserAndTypeQuery = `DELETE FROM verification_tokens WHERE user_id=$1 AND type=$2 AND used_at IS NULL`

	// The three queries below apply their cap in the WHERE clause and are
	// gated on RowsAffected. See port.TokenRepository for why they are not
	// read-then-write, and why they report a bool rather than a count.
	tokenIncrementAttemptsQuery = `UPDATE verification_tokens SET attempts = attempts + 1 WHERE id = $1 AND attempts < $2`

	tokenMarkUsedIfUnderCapQuery = `UPDATE verification_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL AND attempts < $3`

	tokenUpdateForResendQuery = `UPDATE verification_tokens SET token_hash = $1, expires_at = $2, resend_count = resend_count + 1
		WHERE id = $3 AND used_at IS NULL AND resend_count < $4 AND attempts < $5`
)
