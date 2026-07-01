package sqlstore

const (
	inviteSelectColumns = "id, email, code, created_by, status, expires_at, accepted_at, created_at"

	inviteCreateQuery = `INSERT INTO invites (id, email, code, created_by, status, expires_at, accepted_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	inviteByIDQuery = `SELECT ` + inviteSelectColumns + ` FROM invites WHERE id = $1`

	inviteByCodeQuery = `SELECT ` + inviteSelectColumns + ` FROM invites WHERE code = $1`

	inviteByEmailQuery = `SELECT ` + inviteSelectColumns + ` FROM invites WHERE email = $1 ORDER BY created_at DESC LIMIT 1`

	inviteUpdateQuery = `UPDATE invites SET email=$1, code=$2, created_by=$3, status=$4, expires_at=$5, accepted_at=$6 WHERE id=$7`

	inviteDeleteQuery = `DELETE FROM invites WHERE id = $1`
)
