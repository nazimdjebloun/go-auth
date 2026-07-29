# Hardened Organizations / Multi-Tenancy Architecture & Plan

This document outlines the hardened design and implementation specification for adding **Organizations, Teams, and Multi-Tenancy** to `go-auth`.

It is **100% opt-in** and backward-compatible. Existing single-tenant applications using `go-auth` will experience zero breaking changes and zero runtime overhead if organization features are disabled.

---

## 1. Interface Signatures & Core Types

### 1.1 Transaction Port (`port/tx.go`)

To guarantee multi-statement atomicity across service operations (e.g. creating an org and assigning its initial owner), `go-auth` introduces `port.TxManager`:

```go
package port

import "context"

// TxManager executes a function within a database transaction boundary.
// If fn returns an error, the transaction is rolled back; otherwise it is committed.
type TxManager interface {
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}
```

#### Integration with `sqlstore.DB`:
`sqlstore.DB` implements `TxManager`. Inside `WithTx`, `sqlstore.DB` begins a `*sql.Tx` (using `BEGIN IMMEDIATE` on SQLite, or `BeginTx` on Postgres/MySQL) and injects the active transaction into `ctx` via an unexported `txKey{}` context key.

All `sqlstore` repository methods check `ctx` for an active transaction:
```go
func (r *OrgRepository) getExecutor(ctx context.Context) executor {
	if tx, ok := ctx.Value(txKey{}).(executor); ok {
		return tx
	}
	return r.db
}
```
This reuses `go-auth`'s existing standard `database/sql` execution pattern without leaking driver/SQL concepts into the `service` layer.

---

### 1.2 Domain Models & Typed Errors (`domain/org.go` & `domain/errors.go`)

```go
package domain

import "time"

type OrgRole string

const (
	OrgRoleOwner  OrgRole = "owner"
	OrgRoleAdmin  OrgRole = "admin"
	OrgRoleMember OrgRole = "member"
)

func (r OrgRole) IsValid() bool {
	switch r {
	case OrgRoleOwner, OrgRoleAdmin, OrgRoleMember:
		return true
	default:
		return false
	}
}

func (r OrgRole) Weight() int {
	switch r {
	case OrgRoleOwner:
		return 3
	case OrgRoleAdmin:
		return 2
	case OrgRoleMember:
		return 1
	default:
		return 0
	}
}

type Organization struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	CreatedBy   *string                `json:"created_by,omitempty"`
	OwnerCount  int                    `json:"owner_count"`
	MemberCount int                    `json:"member_count"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type OrgMember struct {
	OrgID    string    `json:"org_id"`
	UserID   string    `json:"user_id"`
	Role     OrgRole   `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type OrgMemberDetail struct {
	OrgMember
	User *User `json:"user"`
}

type OrgInvite struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email"`
	Role      OrgRole   `json:"role"`
	CodeHash  string    `json:"-"`
	InvitedBy string    `json:"invited_by"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
```

#### Reserved Slugs Constant (`domain/org.go`)
```go
var ReservedOrgSlugs = map[string]bool{
	"api": true, "admin": true, "auth": true, "www": true, "app": true,
	"static": true, "assets": true, "public": true, "cdn": true, "status": true,
	"billing": true, "settings": true, "support": true, "help": true, "login": true,
	"register": true, "signup": true, "logout": true, "oauth": true, "root": true,
	"system": true, "org": true, "orgs": true, "organization": true, "organizations": true,
}
```

#### Domain Errors (`domain/errors.go`)
```go
var (
	ErrOrgNotFound           = NewError("org_not_found", "Organization not found", 404)
	ErrOrgSlugExists         = NewError("org_slug_exists", "Organization slug already in use", 409)
	ErrOrgSlugReserved       = NewError("org_slug_reserved", "Organization slug is reserved", 400)
	ErrOrgMemberNotFound     = NewError("org_member_not_found", "User is not a member of this organization", 404)
	ErrOrgMemberExists       = NewError("org_member_exists", "User is already a member of this organization", 409)
	ErrCannotRemoveLastOwner = NewError("cannot_remove_last_owner", "Cannot remove or demote the last owner of an organization", 400)
	ErrOrgLimitReached       = NewError("org_limit_reached", "Maximum organization limit reached for user", 400)
	ErrOrgMemberLimitReached = NewError("org_member_limit_reached", "Organization member limit reached", 400)
	ErrOrgForbidden          = NewError("org_forbidden", "Insufficient organization permissions", 403)
	ErrOrgInviteExpired      = NewError("org_invite_expired", "Organization invite link has expired", 400)
	ErrOrgInviteEmailMismatch= NewError("org_invite_email_mismatch", "Authenticated email does not match invite recipient", 400)
	ErrOrgMetadataTooLarge   = NewError("org_metadata_too_large", "Organization metadata exceeds 16KB limit", 400)
)
```

---

### 1.3 Repository Ports (`port/repository.go`)

Scan-based count methods (`CountUserOrgsWithLock`, `CountOrgMembersWithLock`, `CountOrgOwnersWithLock`) are removed to eliminate phantom-read TOCTOU races under READ COMMITTED. Limit and guard assertions are handled via atomic conditional `UPDATE`s on maintained counter columns.

```go
package port

import (
	"context"
	"github.com/nazimdjebloun/go-auth/domain"
)

type OrgRepository interface {
	Create(ctx context.Context, org *domain.Organization) error
	GetByID(ctx context.Context, id string) (*domain.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	Update(ctx context.Context, org *domain.Organization) error
	Delete(ctx context.Context, id string) error

	// Member Management & Atomic Counter Updates
	AddMember(ctx context.Context, member *domain.OrgMember) error
	RemoveMember(ctx context.Context, orgID, userID string) error
	UpdateMemberRole(ctx context.Context, orgID, userID string, role domain.OrgRole) error
	GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error)
	ListMembers(ctx context.Context, orgID string, offset, limit int) ([]domain.OrgMemberDetail, int, error)
	ListUserOrgs(ctx context.Context, userID string) ([]domain.Organization, error)

	// Atomic Conditional Counter Updates
	IncrementUserOrgOwnerCount(ctx context.Context, userID string, maxOrgs int) error
	DecrementUserOrgOwnerCount(ctx context.Context, userID string) error
	IncrementOrgMemberCount(ctx context.Context, orgID string, maxMembers int) error
	DecrementOrgMemberCount(ctx context.Context, orgID string) error
	TryDecrementOrgOwnerCount(ctx context.Context, orgID string) error
	IncrementOrgOwnerCount(ctx context.Context, orgID string) error

	// DecrementOwnerCountForOrgOwners decrements org_owner_count for every
	// user who currently holds the 'owner' role in the given organization.
	// Called as part of DeleteOrg's transaction. No guard condition —
	// the organization is being deleted regardless of resulting counts.
	DecrementOwnerCountForOrgOwners(ctx context.Context, orgID string) error
}

type OrgInviteRepository interface {
	Create(ctx context.Context, invite *domain.OrgInvite) error
	GetByID(ctx context.Context, id string) (*domain.OrgInvite, error)
	GetByCodeHash(ctx context.Context, codeHash string) (*domain.OrgInvite, error)
	ListByOrgID(ctx context.Context, orgID string) ([]domain.OrgInvite, error)
	Delete(ctx context.Context, id string) error
	ClaimInvite(ctx context.Context, id string) (bool, error)
}
```

#### Extended `SessionRepository` (`port/repository.go`)
```go
type SessionRepository interface {
	// ... existing session repo methods ...

	// Invalidation & Active Org Management
	UpdateActiveOrgRoleForUser(ctx context.Context, userID, orgID string, newRole domain.OrgRole) error
	ClearActiveOrgForUser(ctx context.Context, userID, orgID string) error
	ClearActiveOrgForAllMembers(ctx context.Context, orgID string) error
	SetActiveOrg(ctx context.Context, sessionID, orgID string, role domain.OrgRole) error
}
```


---

### 1.4 Organization Configuration (`auth.config.go`)

```go
const absoluteMaxOrgsPerUser = 100

// resolveMaxOrgsPerUser returns the effective cap: 100 if unset (0),
// otherwise the configured value. Callers must validate configured > 100
// at startup separately — this helper does not clamp silently.
func resolveMaxOrgsPerUser(configured int) int {
	if configured == 0 {
		return absoluteMaxOrgsPerUser
	}
	return configured
}
```

`OrgConfig` is added to `go-auth`'s top-level `Config` struct, gated behind `EnableOrganizations`:

```go
type OrgConfig struct {
	// EnableOrganizations turns on organization / multi-tenancy features.
	// When false (default), all org-related tables are never created or queried.
	EnableOrganizations bool `json:"enable_organizations"`

	// MaxOrgsPerUser caps the number of organizations a user may own (role = owner).
	// Membership in orgs owned by others is not counted or limited.
	// Defaults to 100 if unset (0). Must be 0 (defaults to 100) or between 1 and 100.
	// Negative values are rejected at startup.
	MaxOrgsPerUser int `json:"max_orgs_per_user"`
}
```

**Config validation addition** in `Config.validate()`:

```go
if cfg.Organizations.EnableOrganizations {
	if cfg.Organizations.MaxOrgsPerUser < 0 || cfg.Organizations.MaxOrgsPerUser > absoluteMaxOrgsPerUser {
		errs = append(errs, fmt.Errorf(
			"organizations: MaxOrgsPerUser must be between 0 and %d, got %d",
			absoluteMaxOrgsPerUser, cfg.Organizations.MaxOrgsPerUser,
		))
	}
}
```

> **Rationale for 100-ceiling default:** go-auth has no billing/plan tiers or documented abuse surface justifying an opinionated non-zero default below 100; 100 represents a generous safety ceiling that prevents resource-exhaustion errors from operator misconfiguration. Values >100 are rejected at startup because they represent operator misconfiguration, not a user action — failing fast prevents silent misoperation. Both `CreateOrg`'s guarded increment and `UpdateMemberRole`'s promotion guard (§3.1) call `resolveMaxOrgsPerUser(cfg.Organizations.MaxOrgsPerUser)` and use the result as the `$maxOrgs` bound.

---

## 2. Database Schemas

### 2.1 PostgreSQL (`internal/schema/postgres.sql`)

```sql
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    created_by VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
    owner_count INT NOT NULL DEFAULT 0,
    member_count INT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_members (
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS organization_invites (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    code_hash VARCHAR(64) NOT NULL UNIQUE,
    invited_by VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- The existing `users` table gets `org_owner_count INT NOT NULL DEFAULT 0` inline.
-- The existing `sessions` table gets `active_org_id VARCHAR(36) REFERENCES organizations(id) ON DELETE SET NULL`,
-- `active_org_role VARCHAR(50)`, and CHECK ((active_org_id IS NULL AND active_org_role IS NULL) OR (active_org_id IS NOT NULL AND active_org_role IS NOT NULL)) inline.

CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org_role ON organization_members(org_id, role);
CREATE INDEX IF NOT EXISTS idx_org_invites_org ON organization_invites(org_id);
CREATE INDEX IF NOT EXISTS idx_org_invites_email ON organization_invites(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active_org ON sessions(user_id, active_org_id);
```

---

### 2.2 SQLite (`internal/schema/sqlite.sql`)


```sql
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    owner_count INTEGER NOT NULL DEFAULT 0,
    member_count INTEGER NOT NULL DEFAULT 0,
    metadata TEXT DEFAULT '{}',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_members (
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    joined_at DATETIME NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS organization_invites (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    code_hash TEXT NOT NULL UNIQUE,
    invited_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL
);

-- The existing `users` table gets `org_owner_count INTEGER NOT NULL DEFAULT 0` inline.
-- The existing `sessions` table gets `active_org_id TEXT REFERENCES organizations(id) ON DELETE SET NULL`
-- and `active_org_role TEXT` inline.

CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org_role ON organization_members(org_id, role);
CREATE INDEX IF NOT EXISTS idx_org_invites_org ON organization_invites(org_id);
CREATE INDEX IF NOT EXISTS idx_org_invites_email ON organization_invites(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active_org ON sessions(user_id, active_org_id);
```

> **SQLite Paired-Field CHECK Constraint Gap (Option A — Accepted):**
> PostgreSQL (§2.1) and MySQL (§2.3) enforce the invariant that `active_org_id` and `active_org_role` are always null together via a database CHECK constraint. SQLite's `CREATE TABLE` syntax supports CHECK constraints directly, but adding one retrospectively to the existing `sessions` table would require table recreation.
>
> **Decision (Option A):** The paired-field invariant is enforced by application code only (§4.1) on SQLite. This is a known, accepted gap — the SQL updates in §4.1 always set both fields simultaneously as a paired write, and the core system invariant stated in §4.1 must be followed by all read sites regardless of driver.

---

### 2.3 MySQL (`internal/schema/mysql.sql`)

```sql
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    created_by VARCHAR(36),
    owner_count INT NOT NULL DEFAULT 0,
    member_count INT NOT NULL DEFAULT 0,
    metadata JSON NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_org_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS organization_members (
    org_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role VARCHAR(50) NOT NULL,
    joined_at DATETIME(6) NOT NULL,
    PRIMARY KEY (org_id, user_id),
    CONSTRAINT fk_org_mem_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT fk_org_mem_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS organization_invites (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    code_hash VARCHAR(64) NOT NULL UNIQUE,
    invited_by VARCHAR(36) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_org_inv_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT fk_org_inv_user FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The existing `users` table gets `org_owner_count INT NOT NULL DEFAULT 0` inline.
-- The existing `sessions` table gets `active_org_id VARCHAR(36) NULL`, `active_org_role VARCHAR(50) NULL`,
-- `FOREIGN KEY (active_org_id) REFERENCES organizations(id) ON DELETE SET NULL`,
-- and CHECK ((active_org_id IS NULL AND active_org_role IS NULL) OR (active_org_id IS NOT NULL AND active_org_role IS NOT NULL)) inline.

CREATE INDEX idx_org_members_user ON organization_members(user_id);
CREATE INDEX idx_org_members_org_role ON organization_members(org_id, role);
CREATE INDEX idx_org_invites_org ON organization_invites(org_id);
CREATE INDEX idx_org_invites_email ON organization_invites(email);
CREATE INDEX idx_sessions_user_active_org ON sessions(user_id, active_org_id);
```

---

## 3. Concurrency & Consistency

To completely eliminate Time-of-Check to Time-of-Use (TOCTOU) race conditions and phantom-read vulnerabilities under `READ COMMITTED` isolation levels, `go-auth` replaces count-then-act scans with **maintained atomic counter columns** (`users.org_owner_count`, `organizations.owner_count`, `organizations.member_count`).

### 3.1 Atomic Conditional Counter UPDATE Pattern
All limit and guard assertions are executed via single conditional `UPDATE ... WHERE ...` statements inside `txManager.WithTx(...)`. After execution, `sql.Result.RowsAffected()` is checked — if 0 rows were affected, the guard failed, the transaction rolls back, and a typed error is returned.

This pattern is **driver-agnostic** and works identically across PostgreSQL, SQLite, and MySQL via `database/sql`'s standard interface. It removes all dependence on driver-specific features (RETURNING clauses, ROW_COUNT() functions) and driver-specific locking mechanics (FOR UPDATE gap locks vs BEGIN IMMEDIATE).

All SQL examples below use `?` as the parameter placeholder — `sqlstore`'s `DB` wrapper rebinds `$N` to `?` for MySQL/SQLite compatibility at runtime.

To prevent code duplication across the three call sites that guard the same `org_owner_count` increment (CreateOrg, AddMember with owner role, UpdateMemberRole promotion), `service/org_service.go` provides a shared internal helper:

```go
// guardAndIncrementOwnerCount atomically checks and increments a user's
// org_owner_count against the resolved MaxOrgsPerUser cap. Must be called
// inside an active transaction (ctx must carry a tx per TxManager.WithTx).
// Returns domain.ErrOrgLimitReached if the cap is already reached.
func (s *OrgService) guardAndIncrementOwnerCount(ctx context.Context, userID string) error
```

This helper wraps the `UPDATE users SET org_owner_count = org_owner_count + 1 WHERE id = ? AND org_owner_count < ?` pattern with RowsAffected checking. All three call sites use this single helper instead of inlining the same SQL/RowsAffected block.

#### Per-Operation Execution Breakdown:

1. **`CreateOrg` (Max Orgs Guard)**:
   Calls `guardAndIncrementOwnerCount(ctx, userID)` with the owning user's ID. The helper uses `resolveMaxOrgsPerUser(cfg.Organizations.MaxOrgsPerUser)` internally to determine the bound.
   On insertion, `organizations` row is initialized with `owner_count = 1, member_count = 1`.
   `organization_members` row is inserted with role `'owner'`.
   **Invariance:** No code path or database race can ever produce an organization with zero members or bypass `maxOrgs`.

2. **`AddMember` (Max Members Guard)**:
   ```go
   res, err := tx.ExecContext(ctx, `
       UPDATE organizations SET member_count = member_count + 1
       WHERE id = ? AND member_count < ?`, orgID, maxMembers)
   if err != nil {
       return err
   }
   rows, err := res.RowsAffected()
   if err != nil {
       return err
   }
   if rows == 0 {
       return domain.ErrOrgMemberLimitReached
   }
   ```
   If adding an `owner`, the transaction must also call `guardAndIncrementOwnerCount(ctx, member.UserID)` BEFORE incrementing `organizations.owner_count`. This enforces the same cap that guards CreateOrg and UpdateMemberRole promotion, preventing ownership cap bypass via direct member-add:
   ```go
   if member.Role == domain.OrgRoleOwner {
       if err := s.guardAndIncrementOwnerCount(ctx, member.UserID); err != nil {
           return err  // domain.ErrOrgLimitReached
       }
       // proceed to increment organizations.owner_count
   }
   ```

3. **`RemoveMember` & `LeaveOrg` (Last Owner Guard)**:
   - If target member's current role is `'owner'`:
     ```go
     res, err := tx.ExecContext(ctx, `
         UPDATE organizations SET owner_count = owner_count - 1
         WHERE id = ? AND owner_count > 1`, orgID)
     if err != nil {
         return err
     }
     rows, err := res.RowsAffected()
     if err != nil {
         return err
     }
     if rows == 0 {
         return domain.ErrCannotRemoveLastOwner
     }
     ```
     Decrement `users.org_owner_count` for target user.
   - Unconditionally decrement `organizations.member_count`:
     `UPDATE organizations SET member_count = member_count - 1 WHERE id = ?;`
   - Delete `organization_members` row.
   - Clear target user's active session state for this org.

4. **`UpdateMemberRole` (Demotion / Promotion Guard)**:
   - **Demoting Owner to Non-Owner (`owner` → `admin`/`member`):**
     Executes conditional decrement `owner_count = owner_count - 1 WHERE id = ? AND owner_count > 1`.
     RowsAffected == 0 → rollback, return `domain.ErrCannotRemoveLastOwner`.
     Decrement `users.org_owner_count` for target user.
   - **Promoting Non-Owner to Owner (`member`/`admin` → `owner`):**
     Calls `guardAndIncrementOwnerCount(ctx, targetUserID)`. Only after that succeeds does the transaction increment `organizations.owner_count` and update `organization_members.role`.
   - Update target user's active sessions in-place.

5. **`DeleteOrg`**:
   - Inside transaction:
     1. Call `OrgRepository.DecrementOwnerCountForOrgOwners(ctx, orgID)`:
        ```sql
        UPDATE users SET org_owner_count = org_owner_count - 1
        WHERE id IN (
            SELECT user_id FROM organization_members
            WHERE org_id = ? AND role = 'owner'
        );
        ```
     2. Execute `SessionRepository.ClearActiveOrgForAllMembers(ctx, orgID)`.
     3. Delete `organizations` row (cascading deletes handle `organization_members` and `organization_invites`).

---

## 4. Session Invalidation & Active Org Switching

### 4.1 Paired-Field Clearing & Invariant Statement

When an organization membership or role changes, active session state (`active_org_id` and `active_org_role`) must be updated or cleared as a strictly paired atomic write.

#### Active Session Update Queries:
```sql
-- Role Modification (UpdateMemberRole):
UPDATE sessions 
SET active_org_role = $newRole 
WHERE user_id = $userID AND active_org_id = $orgID AND is_revoked = false;

-- Membership Removal (RemoveMember / LeaveOrg):
UPDATE sessions 
SET active_org_id = NULL, active_org_role = NULL 
WHERE user_id = $userID AND active_org_id = $orgID AND is_revoked = false;

-- Organization Deletion (ClearActiveOrgForAllMembers inside DeleteOrg):
UPDATE sessions 
SET active_org_id = NULL, active_org_role = NULL 
WHERE active_org_id = $orgID AND is_revoked = false;
```

#### Core System Invariant:
> **Invariant:** `active_org_role` MUST NEVER be read, checked, or trusted by any code path (middleware, handlers, or services) unless `active_org_id` is simultaneously non-null. All read sites must check both fields together (`s.ActiveOrgID != nil && s.ActiveOrgRole != nil`), never `s.ActiveOrgRole` alone.

#### Driver Cleanup Scope:
`DeleteOrg` executes `ClearActiveOrgForAllMembers(ctx, orgID)` **programmatically inside the transaction for all three drivers** (PostgreSQL, SQLite, MySQL). While foreign key `ON DELETE SET NULL` constraints exist in the schema, `go-auth` does not rely on database FK cascades to clear active session state. The explicit SQL update is the primary source of truth, ensuring both `active_org_id` and `active_org_role` are nulled together across all drivers uniformly.

> **SQLite note:** SQLite does not have a database-level CHECK constraint enforcing the paired-field invariant (see §2.2 — Option A). On SQLite deployments, the paired-field invariant depends entirely on this section's application-level SQL always writing both fields together. All read sites must follow the core system invariant stated above regardless of driver.

---

### 4.2 Interaction Between `SwitchActiveOrg` and Token Rotation

`SwitchActiveOrg` mutates `active_org_id` and `active_org_role` on the active session row.

1. **Non-Rotating Operation:** `SwitchActiveOrg` is a **plain field update**. It does NOT participate in two-token rotation, does NOT alter `token_hash` or `refresh_token_hash`, and does NOT invalidate existing access or refresh tokens.

2. **Race Condition Resolution:**
   - If a token rotation request (`POST /auth/refresh`) and `SwitchActiveOrg` (`POST /auth/orgs/switch`) execute simultaneously on the same session:
     - Token rotation executes `UPDATE sessions SET token_hash = ?, refresh_token_hash = ? WHERE refresh_token_hash = ?`.
     - `SwitchActiveOrg` executes `UPDATE sessions SET active_org_id = ?, active_org_role = ? WHERE id = ?`.
   - Because SQL databases lock the updated row during execution, the database engine cleanly serializes the two updates.
   - If rotation commits first, `SwitchActiveOrg` updates `active_org_id` on the row using `session.ID`.
   - If `SwitchActiveOrg` commits first, rotation reads the updated row and issues new token hashes.
   - Neither order results in corrupted tokens, lost org switches, or failed requests.

---

## 5. Additional Hardening Logic

### 5.1 Invite Acceptance Email Verification
`OrgService.AcceptInvite` explicitly enforces email ownership:

```go
func (s *OrgService) AcceptInvite(ctx context.Context, userID, rawCode string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUnauthorized
	}

	codeHash := hashToken(rawCode)
	invite, err := s.inviteRepo.GetByCodeHash(ctx, codeHash)
	if err != nil || invite == nil {
		return domain.ErrOrgInviteExpired
	}

	if !strings.EqualFold(user.Email, invite.Email) {
		return domain.ErrOrgInviteEmailMismatch
	}

	// ... proceed with transactional claim and membership insert ...
}
```
**Justification:** Strictly enforcing email equality prevents unauthorized users from claiming forwarded or leaked invite codes. Open-invite links (allowing any logged-in user to claim) are explicitly prohibited to prevent unauthorized team takeover.

---

### 5.2 Rate Limiting
Added to `ratelimit/config.go` with per-route sliding window limits:

- `POST /auth/orgs` — default **5 creations / hour per user** (`OrgCreateLimit`)
- `POST /auth/orgs/{orgId}/invites` — default **20 invites / hour per organization** (`OrgInviteLimit`)

---

### 5.3 Reserved Slug Enforcement
`OrgService.CreateOrg` and `OrgService.UpdateOrg` check input slugs against `domain.ReservedOrgSlugs`.
If the input matches a reserved keyword (e.g. `admin`, `api`, `auth`, `login`, `billing`), the service immediately returns `domain.ErrOrgSlugReserved`.

---

### 5.4 Metadata Size Cap
`Organization.Metadata` is capped at **16KB (16,384 bytes)** when serialized as JSON.
If `len(jsonBytes) > 16384`, `CreateOrg` and `UpdateOrg` return `domain.ErrOrgMetadataTooLarge`.

---

### 5.5 Middleware Performance Cost & Trade-off
`RequireOrgMember` middleware validates membership by executing `orgRepo.GetMembership(ctx, orgID, userID)`.

- **Decision:** In-memory caching of memberships is **explicitly deferred** to a future Tier 3 / Redis optimization phase.
- **Justification:** `organization_members` has a composite primary key `(org_id, user_id)`. Lookups execute index-only point scans taking **< 0.5ms** in PostgreSQL, SQLite, and MySQL. Deferring in-memory caching avoids distributed cache-invalidation bugs across multi-instance application deployments.

---

## 6. Route Summary & HTTP Handlers

All org endpoints are mounted in `auth.go` when `EnableOrganizations` is `true`:

| Method | Route Path | Access Level | Handler Description |
|---|---|---|---|
| `POST` | `/auth/orgs` | Authenticated | Create organization (rate limited) |
| `GET` | `/auth/orgs` | Authenticated | List user's organizations |
| `GET` | `/auth/orgs/{orgId}` | Org Member | Get organization detail |
| `PUT` | `/auth/orgs/{orgId}` | Org Admin+ | Update organization name/slug |
| `DELETE` | `/auth/orgs/{orgId}` | Org Owner | Delete organization |
| `POST` | `/auth/orgs/switch` | Authenticated | Switch active organization in session |
| `GET` | `/auth/orgs/{orgId}/members` | Org Member | List organization members |
| `POST` | `/auth/orgs/{orgId}/members` | Org Admin+ | Directly add member by User ID |
| `PATCH` | `/auth/orgs/{orgId}/members/{userId}/role` | Org Admin+ | Update member role |
| `DELETE` | `/auth/orgs/{orgId}/members/{userId}` | Org Admin+ | Remove member |
| `POST` | `/auth/orgs/{orgId}/leave` | Org Member | Leave organization |
| `POST` | `/auth/orgs/{orgId}/invites` | Org Admin+ | Send org invite email (rate limited) |
| `GET` | `/auth/orgs/{orgId}/invites` | Org Admin+ | List pending org invites |
| `DELETE` | `/auth/orgs/{orgId}/invites/{inviteId}` | Org Admin+ | Revoke pending org invite |
| `POST` | `/auth/orgs/invites/accept` | Authenticated | Accept org invite via code |

---

## 7. Complete Summary of Files to Touch / Create

| Action | File Path | Responsibility |
|---|---|---|
| **Create** | `port/tx.go` | Define `TxManager` interface |
| **Create** | `domain/org.go` | `Organization`, `OrgMember`, `OrgRole`, `OrgInvite` types & reserved slugs |
| **Modify** | `domain/errors.go` | Typed organization errors |
| **Modify** | `domain/session.go` | Add `ActiveOrgID` and `ActiveOrgRole` fields |
| **Modify** | `port/repository.go` | `OrgRepository` (atomic counter helpers, `DecrementOwnerCountForOrgOwners`), `OrgInviteRepository`, extended `SessionRepository` (`ClearActiveOrgForAllMembers`) |
| **Create** | `sqlstore/org_repo.go` | SQL repository implementations with transaction awareness, atomic conditional UPDATE queries (RowsAffected-based), `DecrementOwnerCountForOrgOwners` bulk decrement |
| **Modify** | `sqlstore/session_repo.go` | Add active org update & `ClearActiveOrgForAllMembers` paired SQL methods |
| **Create** | `service/org_service.go` | Business logic, `guardAndIncrementOwnerCount` shared helper (used by CreateOrg, AddMember with owner role, UpdateMemberRole promotion), counter-based TOCTOU guards, email validation, metadata check |
| **Create** | `handler/org.go` | HTTP handlers for `/auth/orgs/*` |
| **Create** | `middleware/org.go` | `RequireOrgMember`, `RequireOrgRole` middleware |
| **Modify** | `auth.config.go` | `OrgConfig` struct (`EnableOrganizations`, `MaxOrgsPerUser`), `absoluteMaxOrgsPerUser` constant, `resolveMaxOrgsPerUser` helper, `>100` startup validation in `Config.validate()` |
| **Modify** | `auth.go` | Conditional service wiring and route mounting |
| **Modify** | `ratelimit/config.go` | Per-route limits for org creation and invites |
| **Modify** | `internal/schema/postgres.sql` | Postgres table schemas, counter columns, CHECK constraint |
| **Modify** | `internal/schema/sqlite.sql` | SQLite table schemas & counter columns |
| **Modify** | `internal/schema/mysql.sql` | MySQL table schemas, counter columns, FK & CHECK constraint |
| **Create** | `service/org_test.go` | Unit tests for Organization logic & counter concurrency |
| **Create** | `integration/org_test.go` | SQLite & Postgres integration tests |
