package sqlstore

const (
	userCreateQuery = `
		INSERT INTO users (id, email, password_hash, name, role, is_verified, verified_at, is_banned, two_factor_enabled, org_owner_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	userByIDQuery = `
		SELECT ` + userSelectColumns + ` FROM users WHERE id = $1`

	userByEmailQuery = `
		SELECT ` + userSelectColumns + ` FROM users WHERE email = $1`

	userUpdateQuery = `
		UPDATE users SET email=$1, password_hash=$2, name=$3, role=$4,
			is_verified=$5, verified_at=$6, is_banned=$7, updated_at=$8
		WHERE id=$9`

	userSetTwoFactorQuery = `
		UPDATE users SET two_factor_enabled=$1, updated_at=$2 WHERE id=$3`

	userBanQuery = `
		UPDATE users SET is_banned=$1, banned_at=$2, updated_at=$3 WHERE id=$4`

	userSetPasswordQuery = `
		UPDATE users SET password_hash=$1, is_verified=true, verified_at=$2, updated_at=$3
		WHERE id=$4`

	userDeleteQuery = `DELETE FROM users WHERE id = $1`

	userUpdateLastLoginQuery = `UPDATE users SET last_login_at=$1, updated_at=$2 WHERE id=$3`

	// userSelectColumns is the single source of truth for the user column list
	// and its order — scanRow depends on both. The by-id and by-email queries
	// build on it so a new column can never land in one and be forgotten in the
	// other.
	userSelectColumns = "id, email, password_hash, name, role, is_verified, verified_at, is_banned, banned_at, two_factor_enabled, org_owner_count, last_login_at, created_at, updated_at"
)
