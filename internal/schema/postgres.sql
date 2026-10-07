CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Public recovery requests are queued before any account lookup. Times are
-- UTC Unix seconds; no raw reset token or verification code is stored here.
CREATE TABLE IF NOT EXISTS recovery_requests (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    email TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at BIGINT NOT NULL,
    lease_until BIGINT NOT NULL DEFAULT 0,
    claim_owner TEXT NOT NULL DEFAULT '',
    dead_lettered INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recovery_requests_claim ON recovery_requests(dead_lettered, available_at, lease_until);
CREATE INDEX IF NOT EXISTS idx_recovery_requests_created ON recovery_requests(created_at);

CREATE TABLE IF NOT EXISTS app_roles (
    id UUID PRIMARY KEY,
    slug VARCHAR(80) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    system_key VARCHAR(40) UNIQUE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (system_key IS NULL OR system_key IN ('platform_admin', 'user'))
);

CREATE TABLE IF NOT EXISTS app_permissions (
    id UUID PRIMARY KEY,
    permission_key VARCHAR(160) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_system BOOLEAN NOT NULL DEFAULT false,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (NOT is_system OR is_enabled),
    CONSTRAINT app_permissions_namespace_owner
        CHECK (is_system = (substr(permission_key, 1, 11) = 'goauth.app.'))
);

CREATE TABLE IF NOT EXISTS app_authorization_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    app_role_id UUID,
    app_role_assignment_revision BIGINT NOT NULL DEFAULT 0 CHECK (app_role_assignment_revision >= 0),
    password_pepper_version BIGINT CHECK (password_pepper_version > 0 AND password_pepper_version <= 4294967295),
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    is_verified BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    is_banned BOOLEAN NOT NULL DEFAULT false,
    banned_at TIMESTAMPTZ,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    org_owner_count INT NOT NULL DEFAULT 0,
    last_login_at TIMESTAMPTZ,
    FOREIGN KEY (app_role_id) REFERENCES app_roles(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_users_password_pepper_version ON users(password_pepper_version);

CREATE INDEX IF NOT EXISTS idx_users_app_role ON users(app_role_id, id);

CREATE TABLE IF NOT EXISTS app_role_permissions (
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    granted_by UUID,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES app_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES app_permissions(id) ON DELETE RESTRICT,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_app_role_permissions_permission ON app_role_permissions(permission_id, role_id);


CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    owner_count INT NOT NULL DEFAULT 0,
    member_count INT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organization_members (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS organization_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    code_hash TEXT UNIQUE NOT NULL,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    refresh_token_hash TEXT NOT NULL DEFAULT '',
    prev_refresh_token_hash TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ,
    refresh_rotated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    active_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    active_org_role VARCHAR(50),
    two_factor_verified_at TIMESTAMPTZ,
    CHECK ((active_org_id IS NULL AND active_org_role IS NULL) OR (active_org_id IS NOT NULL AND active_org_role IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('verify_email', 'reset_password', 'set_password', 'invite_verify', 'oauth_state', 'delete_account', '2fa_login')),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    code_verifier TEXT,
    attempts INT NOT NULL DEFAULT 0,
    resend_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS provider_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_email TEXT NOT NULL DEFAULT '',
    provider_name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider, provider_user_id)
);

CREATE TABLE IF NOT EXISTS invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_verification_tokens_token_hash ON verification_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
CREATE INDEX IF NOT EXISTS idx_invites_code ON invites(code);
CREATE INDEX IF NOT EXISTS idx_provider_accounts_user_id ON provider_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_provider_accounts_provider ON provider_accounts(provider, provider_user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_prev_refresh_token_hash ON sessions(prev_refresh_token_hash);

CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org_role ON organization_members(org_id, role);
CREATE INDEX IF NOT EXISTS idx_org_members_org_joined ON organization_members(org_id, joined_at);
CREATE INDEX IF NOT EXISTS idx_org_invites_org ON organization_invites(org_id);
CREATE INDEX IF NOT EXISTS idx_org_invites_email ON organization_invites(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active_org ON sessions(user_id, active_org_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    success BOOLEAN NOT NULL DEFAULT true,
    actor_id UUID,
    target_id UUID,
    session_id UUID,
    org_id UUID,
    ip TEXT,
    user_agent TEXT NOT NULL DEFAULT '',
    parsed_ua JSONB,
    request_id TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_target_id ON audit_log(target_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_session_id ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_org_id ON audit_log(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type_created_at ON audit_log(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_metadata ON audit_log USING GIN (metadata jsonb_path_ops);

-- ── Audit outbox — durable delivery. ──
-- Ephemeral companion to audit_log: a row exists only while the event still
-- must be delivered to an external sink. audit_log is insert-only and
-- immutable; all churn (claim, attempt, retry) lives here so backpressure,
-- dead-lettering and eviction can never touch the record. No foreign key:
-- it would add a check to the credential path and complicate partition
-- drops; orphans are found by the janitor's periodic scan.
CREATE TABLE IF NOT EXISTS audit_outbox (
    audit_log_id UUID PRIMARY KEY,
    org_id UUID,
    priority INT NOT NULL DEFAULT 0,
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ,
    claim_owner TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    dead_lettered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_claim ON audit_outbox(priority, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_audit_outbox_created_at ON audit_outbox(created_at);

-- ── Admin console read paths — large-tenant list / count / filter / sort. ──

-- users: role-scoped listing + sort. The trailing id keeps these usable for
-- keyset pagination later without another schema change.
CREATE INDEX IF NOT EXISTS idx_users_role_created_at ON users (role, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users (updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users (last_login_at);
-- Low-cardinality flag filters: a partial index covers only the rare value
-- that gets queried, so it stays small and the planner actually picks it.
CREATE INDEX IF NOT EXISTS idx_users_banned ON users (created_at DESC) WHERE is_banned;
CREATE INDEX IF NOT EXISTS idx_users_unverified ON users (created_at DESC) WHERE NOT is_verified;
CREATE INDEX IF NOT EXISTS idx_users_two_factor ON users (created_at DESC) WHERE two_factor_enabled;
-- Substring search: `name ILIKE '%x%' OR email ILIKE '%x%'` has a leading
-- wildcard, so a btree is useless. A trigram GIN index makes it an index
-- lookup instead of a full scan (effective for terms of 3+ characters).
CREATE INDEX IF NOT EXISTS idx_users_email_trgm ON users USING gin (email gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_users_name_trgm ON users USING gin (name gin_trgm_ops);

-- sessions: cross-user admin session list, "kill all sessions from this IP",
-- and the expiry sweep.
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_last_active_at ON sessions (last_active_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_ip_address ON sessions (ip_address);

-- invites: status filter, newest-first.
CREATE INDEX IF NOT EXISTS idx_invites_status_created_at ON invites (status, created_at DESC);
-- Default admin list order (no status filter).
CREATE INDEX IF NOT EXISTS idx_invites_created_at ON invites (created_at DESC, id DESC);
-- ORDER BY expires_at, and the pending-and-past-due half of the derived
-- "expired" filter (see InviteRepository.buildInviteWhere).
CREATE INDEX IF NOT EXISTS idx_invites_expires_at ON invites (expires_at);
CREATE INDEX IF NOT EXISTS idx_invites_pending_expires ON invites (expires_at) WHERE status = 'pending';
-- Substring email search: ILIKE '%term%' cannot use the plain btree on email.
CREATE INDEX IF NOT EXISTS idx_invites_email_trgm ON invites USING gin (email gin_trgm_ops);

-- audit_log: per-user trail (as actor or as target) ordered by time.
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_created_at ON audit_log (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_target_created_at ON audit_log (target_id, created_at DESC);
