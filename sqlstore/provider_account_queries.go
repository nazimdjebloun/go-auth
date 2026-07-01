package sqlstore

const (
	providerAccountSelectColumns = "id, user_id, provider, provider_user_id, provider_email, provider_name, avatar_url, access_token, refresh_token, token_expires_at, created_at, updated_at"

	providerAccountCreateQuery = `INSERT INTO provider_accounts (` + providerAccountSelectColumns + `) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	providerAccountByProviderQuery = `SELECT ` + providerAccountSelectColumns + ` FROM provider_accounts WHERE provider = $1 AND provider_user_id = $2`

	providerAccountDeleteQuery = `DELETE FROM provider_accounts WHERE user_id = $1 AND provider = $2`

	providerAccountListByUserQuery = `SELECT ` + providerAccountSelectColumns + ` FROM provider_accounts WHERE user_id = $1 ORDER BY created_at`
)
