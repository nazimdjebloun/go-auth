package migrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"golang.org/x/crypto/bcrypt"
)

const (
	upgradeUser    = "11111111-1111-1111-1111-111111111111"
	upgradeOAuth   = "22222222-2222-2222-2222-222222222222"
	upgradeSession = "33333333-3333-3333-3333-333333333333"
	upgradeRole    = "66666666-6666-6666-6666-666666666666"
)

func fixtureChecksum(contents string) string {
	digest := sha256.Sum256([]byte(contents))
	return hex.EncodeToString(digest[:])
}

// These fixture-only changes exercise two skipped releases and a required
// backfill. They are not published auth schema changes or release promises.
func upgradeCatalog(t *testing.T, dialect string) Catalog {
	t.Helper()
	catalog, err := Load(dialect)
	if err != nil {
		t.Fatal(err)
	}
	baseline := catalog.Migrations[0].schemaSQL
	definition, err := parseDefinition(dialect, baseline)
	if err != nil {
		t.Fatal(err)
	}
	users := definition.tables["users"].sql
	constraint := strings.Index(users, "\n    FOREIGN KEY")
	if constraint < 0 {
		t.Fatal("frozen users fixture is missing its role foreign key")
	}
	expanded := users[:constraint] + "\n    migration_note VARCHAR(255)," + users[constraint:]
	schema2 := strings.Replace(baseline, users, expanded, 1)
	schema3 := strings.Replace(schema2, "    migration_note VARCHAR(255),\n", "    migration_note VARCHAR(255) NOT NULL,\n", 1)
	commands2 := []string{
		"ALTER TABLE users ADD COLUMN migration_note VARCHAR(255);",
		"UPDATE users SET migration_note=email;",
	}
	var commands3 []string
	switch dialect {
	case "postgres":
		commands3 = []string{"ALTER TABLE users ALTER COLUMN migration_note SET NOT NULL;"}
	case "mysql":
		commands3 = []string{"ALTER TABLE users MODIFY COLUMN migration_note VARCHAR(255) NOT NULL;"}
	case "sqlite":
		target, err := parseDefinition(dialect, schema3)
		if err != nil {
			t.Fatal(err)
		}
		create := strings.Replace(target.tables["users"].sql, "CREATE TABLE IF NOT EXISTS users (", "CREATE TABLE users_rebuild (", 1)
		columns := make([]string, 0, len(target.tables["users"].columns))
		for _, column := range target.tables["users"].columns {
			columns = append(columns, column.name)
		}
		list := strings.Join(columns, ",")
		commands3 = []string{create, "INSERT INTO users_rebuild (" + list + ") SELECT " + list + " FROM users;",
			"DROP TABLE users;", "ALTER TABLE users_rebuild RENAME TO users;"}
		for _, index := range indexDefinition.FindAllStringSubmatch(schema3, -1) {
			if index[3] == "users" {
				commands3 = append(commands3, index[0])
			}
		}
	}
	for i, commands := range [][]string{commands2, commands3} {
		id := int64(i + 2)
		snapshot := []string{schema2, schema3}[i]
		catalog.Migrations = append(catalog.Migrations, Step{
			ID: id, File: fmt.Sprintf("%06d_v0.%d.0_001.sql", id, i+5), Kind: "upgrade",
			Transactional: dialect != "mysql", SQLiteRebuild: dialect == "sqlite" && id == 3,
			Schema: fmt.Sprintf("schema_%06d.sql", id), schemaSQL: snapshot,
			SQL:    "-- goauth:statement\n" + strings.Join(commands, "\n-- goauth:statement\n") + "\n",
			Checks: []string{"SELECT COUNT(*)=0 FROM users WHERE migration_note IS NULL OR migration_note<>email"},
		})
	}
	catalog.TargetRevision, catalog.Release = 3, "v0.6.0"
	return validateFixture(t, catalog)
}

func validateFixture(t *testing.T, catalog Catalog) Catalog {
	t.Helper()
	source := fstest.MapFS{}
	for i := range catalog.Migrations {
		step := &catalog.Migrations[i]
		step.Checksum, step.SchemaChecksum = fixtureChecksum(step.SQL), fixtureChecksum(step.schemaSQL)
		source[catalog.Dialect+"/"+step.File] = &fstest.MapFile{Data: []byte(step.SQL)}
		source[catalog.Dialect+"/"+step.Schema] = &fstest.MapFile{Data: []byte(step.schemaSQL)}
	}
	manifest, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	source[catalog.Dialect+"/catalog.json"] = &fstest.MapFile{Data: manifest}
	validated, err := ReadCatalog(source, catalog.Dialect)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func upgradeExec(t *testing.T, db *sql.DB, dialect, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), bind(dialect, query), args...); err != nil {
		t.Fatal(err)
	}
}

func seedUpgradeData(t *testing.T, db *sql.DB, dialect string) (string, string) {
	t.Helper()
	mac := hmac.New(sha256.New, []byte("fixture-pepper-version-2"))
	_, _ = mac.Write([]byte("correct-password"))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	hash, err := hasher.New(bcrypt.MinCost).Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	upgradeExec(t, db, dialect, `INSERT INTO app_roles(id,slug,name,description,created_at,updated_at)
		VALUES (?,'member','Member','',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, upgradeRole)
	upgradeExec(t, db, dialect, `INSERT INTO users(id,email,name,password_hash,password_pepper_version,app_role_id,app_role_assignment_revision,created_at,updated_at)
		VALUES (?,'password@example.com','Password',?,2,?,5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, upgradeUser, hash, upgradeRole)
	upgradeExec(t, db, dialect, `INSERT INTO users(id,email,name,created_at,updated_at)
		VALUES (?,'oauth@example.com','OAuth',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, upgradeOAuth)
	upgradeExec(t, db, dialect, `INSERT INTO sessions(id,user_id,token_hash,refresh_token_hash,prev_refresh_token_hash,is_revoked,revoked_at,expires_at,refresh_expires_at,created_at,last_active_at)
		VALUES (?,?,?,?,?,TRUE,'2021-01-01 00:00:00','2030-01-01 00:00:00','2030-02-01 00:00:00',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		upgradeSession, upgradeUser, fixtureChecksum("session-token"), fixtureChecksum("refresh-token"), fixtureChecksum("previous-refresh-token"))
	upgradeExec(t, db, dialect, `INSERT INTO verification_tokens(id,user_id,email,token_hash,type,expires_at,used_at,created_at)
		VALUES ('44444444-4444-4444-4444-444444444444',?,'password@example.com',?,'reset_password','2030-01-01 00:00:00','2021-01-01 00:00:00',CURRENT_TIMESTAMP)`, upgradeUser, fixtureChecksum("consumed-token"))
	upgradeExec(t, db, dialect, `INSERT INTO provider_accounts(id,user_id,provider,provider_user_id,provider_email,provider_name,avatar_url,access_token,created_at,updated_at)
		VALUES ('55555555-5555-5555-5555-555555555555',?,'github','CaseSensitiveIdentity','oauth@example.com','OAuth','','encrypted-fixture',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, upgradeOAuth)
	upgradeExec(t, db, dialect, `INSERT INTO audit_log(id,event_type,success,created_at)
		VALUES ('audit-record','password_changed',TRUE,CURRENT_TIMESTAMP)`)
	upgradeExec(t, db, dialect, `INSERT INTO audit_outbox(audit_log_id,attempts,next_attempt_at,created_at)
		VALUES ('audit-record',3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	idType, suffix := "TEXT", ""
	if dialect == "postgres" {
		idType = "UUID"
	} else if dialect == "mysql" {
		idType, suffix = "VARCHAR(36)", " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
	}
	upgradeExec(t, db, dialect, fmt.Sprintf(`CREATE TABLE user_profiles (user_id %s PRIMARY KEY, note TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)%s`, idType, suffix))
	upgradeExec(t, db, dialect, `INSERT INTO user_profiles(user_id,note) VALUES (?,'preserved')`, upgradeUser)
	if dialect == "sqlite" {
		for _, query := range []string{
			"CREATE INDEX idx_profiles_note ON user_profiles(note)",
			"CREATE TABLE profile_changes (user_id TEXT)",
			"CREATE TRIGGER profile_changed AFTER UPDATE ON user_profiles BEGIN INSERT INTO profile_changes VALUES (NEW.user_id); END;",
		} {
			upgradeExec(t, db, dialect, query)
		}
	}
	assertUpgradeSessionData(t, db, dialect)
	return hash, password
}

func assertUpgradeSessionData(t *testing.T, db *sql.DB, dialect string) {
	t.Helper()
	store := sqlstore.NewDB(db, dialect)
	session, err := sqlstore.NewSessionRepository(store).GetByTokenHash(t.Context(), fixtureChecksum("session-token"))
	if err != nil || session == nil || !session.IsRevoked || session.RevokedAt == nil ||
		session.RefreshTokenHash != fixtureChecksum("refresh-token") || session.PreviousRefreshHash != fixtureChecksum("previous-refresh-token") ||
		!session.ExpiresAt.Equal(time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)) ||
		!session.RefreshExpiresAt.Equal(time.Date(2030, time.February, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("session lookup, rotation, expiry or revocation state changed", err)
	}
}

func assertUpgradeData(t *testing.T, db *sql.DB, dialect, expectedHash, password string) {
	t.Helper()
	store := sqlstore.NewDB(db, dialect)
	users := sqlstore.NewUserRepository(store)
	user, err := users.GetByEmail(t.Context(), "password@example.com")
	if err != nil || user == nil {
		t.Fatal("password account cannot be queried after upgrade", err)
	}
	if user.PasswordHash == nil || *user.PasswordHash != expectedHash || user.PasswordPepperVersion == nil || *user.PasswordPepperVersion != 2 ||
		user.AppRoleID == nil || *user.AppRoleID != upgradeRole || user.AppRoleAssignmentRevision != 5 {
		t.Fatal("password/pepper pair or role assignment changed")
	}
	if err := hasher.New(bcrypt.MinCost).Compare(password, *user.PasswordHash); err != nil {
		t.Fatal("preserved password no longer verifies", err)
	}
	oauth, err := users.GetByEmail(t.Context(), "oauth@example.com")
	if err != nil || oauth == nil || oauth.PasswordHash != nil {
		t.Fatal("OAuth-only password state changed", err)
	}
	assertUpgradeSessionData(t, db, dialect)
	var valid bool
	if err := db.QueryRowContext(t.Context(), bind(dialect, `SELECT
		(SELECT COUNT(*)=1 FROM verification_tokens WHERE used_at IS NOT NULL AND token_hash=? AND expires_at='2030-01-01 00:00:00')
		AND (SELECT COUNT(*)=1 FROM provider_accounts WHERE provider_user_id='CaseSensitiveIdentity' AND access_token='encrypted-fixture')
		AND (SELECT COUNT(*)=1 FROM audit_log WHERE id='audit-record' AND success=TRUE)
		AND (SELECT COUNT(*)=1 FROM audit_outbox WHERE audit_log_id='audit-record' AND attempts=3)
		AND (SELECT COUNT(*)=1 FROM user_profiles WHERE note='preserved')`), fixtureChecksum("consumed-token")).Scan(&valid); err != nil || !valid {
		t.Fatal("one-time consumption, provider state, audit obligation or host child changed", err)
	}
	if _, err := db.ExecContext(t.Context(), bind(dialect, `INSERT INTO provider_accounts(id,user_id,provider,provider_user_id,provider_email,provider_name,avatar_url,created_at,updated_at)
		VALUES ('77777777-7777-7777-7777-777777777777',?,'github','CaseSensitiveIdentity','','','',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`), upgradeOAuth); err == nil {
		t.Fatal("provider identity uniqueness was lost")
	}
	if dialect == "sqlite" {
		upgradeExec(t, db, dialect, "UPDATE user_profiles SET note='after' WHERE user_id=?", upgradeUser)
		if err := db.QueryRowContext(t.Context(), `SELECT (SELECT COUNT(*) FROM profile_changes)=1
			AND (SELECT COUNT(*) FROM sqlite_schema WHERE name='idx_profiles_note' AND type='index')=1`).Scan(&valid); err != nil || !valid {
			t.Fatal("host trigger or index was lost during rebuild", err)
		}
	}
}

func TestSelectedBackendPopulatedUpgrade(t *testing.T) {
	for _, mode := range []string{"installed", "adopted"} {
		t.Run(mode, func(t *testing.T) {
			db := testdb.OpenSelected(t)
			dialect := testdb.Driver(db)
			options := Options{Driver: dialect}
			if mode == "adopted" {
				testdb.Apply(t, db)
			} else if _, err := Apply(t.Context(), db, options); err != nil {
				t.Fatal(err)
			}
			hash, password := seedUpgradeData(t, db, dialect)
			if mode == "adopted" {
				if _, err := Adopt(t.Context(), db, options, 1); err != nil {
					t.Fatal(err)
				}
			}
			catalog := upgradeCatalog(t, dialect)
			status, err := runCatalog(t.Context(), db, options, catalog, "apply", 0)
			if err != nil || status.Revision != 3 || len(status.History) != 3 || len(status.Pending) != 0 {
				t.Fatalf("skipped release upgrade failed: %+v, %v", status, err)
			}
			assertUpgradeData(t, db, dialect, hash, password)
			if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
				t.Fatal("completed upgrades were replayed", err)
			}
		})
	}
}

func TestSelectedBackendUpgradeFailureRecovery(t *testing.T) {
	db := testdb.OpenSelected(t)
	dialect := testdb.Driver(db)
	options := Options{Driver: dialect}
	if _, err := Apply(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
	hash, password := seedUpgradeData(t, db, dialect)
	broken := upgradeCatalog(t, dialect)
	broken.Migrations[1].statements[1] = "INSERT INTO missing_upgrade_table VALUES (1)"
	if _, err := runCatalog(t.Context(), db, options, broken, "apply", 0); err == nil {
		t.Fatal("injected backfill failure was accepted")
	}
	clean := upgradeCatalog(t, dialect)
	state, err := readHistory(t.Context(), db, clean)
	if err != nil || state.Revision != 1 || state.Dirty != (dialect == "mysql") {
		t.Fatalf("incorrect rollback or dirty outcome: %+v, %v", state, err)
	}
	if dialect == "mysql" {
		if _, err := runCatalog(t.Context(), db, options, clean, "apply", 0); !errors.Is(err, ErrDirty) {
			t.Fatal("partial DDL was automatically replayed", err)
		}
		if _, err := runCatalog(t.Context(), db, options, clean, "repair", 2); err == nil {
			t.Fatal("unpopulated replacement values were marked complete")
		}
		upgradeExec(t, db, dialect, "UPDATE users SET migration_note=email")
		if _, err := runCatalog(t.Context(), db, options, clean, "repair", 2); err != nil {
			t.Fatal("verified backfill repair failed", err)
		}
	}
	if _, err := runCatalog(t.Context(), db, options, clean, "apply", 0); err != nil {
		t.Fatal(err)
	}
	assertUpgradeData(t, db, dialect, hash, password)
}

func TestSQLiteRebuildRejectsHostOrphansAndRestoresSettings(t *testing.T) {
	db := migrationDB(t)
	upgradeExec(t, db, "sqlite", "PRAGMA foreign_keys=ON")
	upgradeExec(t, db, "sqlite", "PRAGMA busy_timeout=321")
	options := Options{Driver: "sqlite"}
	if _, err := Apply(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
	hash, password := seedUpgradeData(t, db, "sqlite")
	catalog := upgradeCatalog(t, "sqlite")
	catalog.Migrations[2].statements = append(catalog.Migrations[2].statements,
		"INSERT INTO user_profiles VALUES ('99999999-9999-9999-9999-999999999999','orphan')")
	if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); !errors.Is(err, ErrDrift) {
		t.Fatal("host-owned orphan was committed", err)
	}
	if err := Verify(t.Context(), db, options); err != nil {
		t.Fatal("failed rebuild did not restore baseline schema", err)
	}
	var foreignKeys, busy int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 || busy != 321 {
		t.Fatalf("borrowed connection settings changed: foreign_keys=%d busy_timeout=%d", foreignKeys, busy)
	}
	assertUpgradeData(t, db, "sqlite", hash, password)
}

func TestFreshUpgradeCatalogRejectsFutureNameCollisionBeforeBootstrap(t *testing.T) {
	db := migrationDB(t)
	upgradeExec(t, db, "sqlite", "CREATE TABLE future_reserved (id TEXT)")
	catalog := upgradeCatalog(t, "sqlite")
	for i := 1; i < len(catalog.Migrations); i++ {
		catalog.Migrations[i].schemaSQL += "\nCREATE TABLE future_reserved (\n    id TEXT PRIMARY KEY\n);\n"
	}
	catalog.Migrations[1].SQL += "-- goauth:statement\nCREATE TABLE future_reserved (id TEXT PRIMARY KEY);\n"
	catalog = validateFixture(t, catalog)
	if _, err := runCatalog(t.Context(), db, Options{Driver: "sqlite"}, catalog, "apply", 0); !errors.Is(err, ErrUntracked) {
		t.Fatal("name reserved by a future upgrade collided after bootstrap", err)
	}
	for _, name := range []string{"users", "goauth_migrations"} {
		exists, err := objectExists(t.Context(), db, "sqlite", name)
		if err != nil || exists {
			t.Fatal("collision initialized auth schema or history", name, err)
		}
	}
}

func TestHistoricalV030MatchesSupportedBaseline(t *testing.T) {
	contents, err := os.ReadFile("testdata/v0.3.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var historical struct {
		Release         string            `json:"release"`
		Commit          string            `json:"commit"`
		SchemaChecksums map[string]string `json:"schemaChecksums"`
	}
	if err := json.Unmarshal(contents, &historical); err != nil {
		t.Fatal(err)
	}
	if historical.Release != "v0.3.0" || historical.Commit != "c289be372e62f84cabe3f3ee74eea1a67ed01db2" {
		t.Fatal("historical fixture provenance changed")
	}
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		catalog, err := Load(dialect)
		if err != nil {
			t.Fatal(err)
		}
		if fixtureChecksum(catalog.Migrations[0].schemaSQL) != historical.SchemaChecksums[dialect] {
			t.Fatal("published v0.3.0 schema no longer matches supported adoption baseline", dialect)
		}
	}
}
