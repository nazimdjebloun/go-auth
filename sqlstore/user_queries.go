package sqlstore

const (
	userCreateQuery = `
		INSERT INTO users (id, email, password_hash, name, role, is_verified, verified_at, is_banned, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	userByIDQuery = `
		SELECT id, email, password_hash, name, role, is_verified, verified_at, is_banned, banned_at, created_at, updated_at
		FROM users WHERE id = $1`

	userByEmailQuery = `
		SELECT id, email, password_hash, name, role, is_verified, verified_at, is_banned, banned_at, created_at, updated_at
		FROM users WHERE email = $1`

	userUpdateQuery = `
		UPDATE users SET email=$1, password_hash=$2, name=$3, role=$4,
			is_verified=$5, verified_at=$6, is_banned=$7, updated_at=$8
		WHERE id=$9`

	userBanQuery = `
		UPDATE users SET is_banned=$1, banned_at=$2, updated_at=$3 WHERE id=$4`

	userSetPasswordQuery = `
		UPDATE users SET password_hash=$1, is_verified=true, verified_at=$2, updated_at=$2
		WHERE id=$3`

	userDeleteQuery = `DELETE FROM users WHERE id = $1`

	userSelectColumns = "id, email, password_hash, name, role, is_verified, verified_at, is_banned, banned_at, created_at, updated_at"
)
