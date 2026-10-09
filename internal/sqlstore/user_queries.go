package sqlstore

var (
	userCreateQuery = `
		INSERT INTO users (id, email, password_hash, password_pepper_version, name, role, is_verified, verified_at, is_banned, two_factor_enabled, org_owner_count, created_at, updated_at, app_role_id, app_role_assignment_revision)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

	// App permissions leave the unused users.role column at its schema default.
	userCreateAppQuery = `
		INSERT INTO users (id, email, password_hash, password_pepper_version, name, is_verified, verified_at, is_banned, two_factor_enabled, org_owner_count, created_at, updated_at, app_role_id, app_role_assignment_revision)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	userByIDQuery = `
		SELECT ` + userSelectColumns + ` FROM users WHERE id = $1`

	userByEmailQuery = `
		SELECT ` + userSelectColumns + ` FROM users WHERE email = $1`

	userUpdateQuery = `
		UPDATE users SET email=$1, name=$2,
			is_verified=$3, verified_at=$4, updated_at=$5
		WHERE id=$6`

	userSetTwoFactorQuery = `
		UPDATE users SET two_factor_enabled=$1, updated_at=$2 WHERE id=$3`

	userBanQuery = `
		UPDATE users SET is_banned=$1, banned_at=$2, updated_at=$3 WHERE id=$4`

	userSetPasswordQuery = sqlText(`
		UPDATE users SET password_hash=$1, password_pepper_version=$2, is_verified=true, verified_at=$3, updated_at=$4
		WHERE id=$5 AND password_hash IS NULL`)

	userUpdatePasswordHashQuery = sqlText(`
		UPDATE users SET password_hash=$1, password_pepper_version=$2, updated_at=$3
		WHERE id=$4 AND password_hash=$5
			AND COALESCE(password_pepper_version, 0) = $6
			AND COALESCE(password_pepper_version, 0) <= $7`)

	userPasswordPepperVersionsQuery = sqlText(`
		SELECT DISTINCT password_pepper_version FROM users
		WHERE password_pepper_version IS NOT NULL
		ORDER BY password_pepper_version`)

	userDeleteQuery = `DELETE FROM users WHERE id = $1`

	userSetRoleQuery = `UPDATE users SET role = $1, updated_at = $2 WHERE id = $3`

	userUpdateLastLoginQuery = `UPDATE users SET last_login_at=$1, updated_at=$2 WHERE id=$3`

	// userSelectColumns is the single source of truth for the user column list
	// and its order — scanRow depends on both. The by-id and by-email queries
	// build on it so a new column can never land in one and be forgotten in the
	// other.
	userSelectColumns = "id, email, password_hash, password_pepper_version, name, role, is_verified, verified_at, is_banned, banned_at, two_factor_enabled, org_owner_count, last_login_at, created_at, updated_at, app_role_id, app_role_assignment_revision"
)
