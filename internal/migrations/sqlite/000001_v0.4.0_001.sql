-- Public recovery requests are queued before any account lookup. Times are
-- UTC Unix seconds; no raw reset token or verification code is stored here.
-- goauth:statement
CREATE TABLE recovery_requests (
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

-- goauth:statement
CREATE INDEX idx_recovery_requests_claim ON recovery_requests(dead_lettered, available_at, lease_until);
-- goauth:statement
CREATE INDEX idx_recovery_requests_created ON recovery_requests(created_at);

-- goauth:statement
CREATE TABLE app_roles (
    id TEXT PRIMARY KEY,
    slug VARCHAR(80) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    system_key VARCHAR(40) UNIQUE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CHECK (system_key IS NULL OR system_key IN ('platform_admin', 'user'))
);

-- goauth:statement
CREATE TABLE app_permissions (
    id TEXT PRIMARY KEY,
    permission_key VARCHAR(160) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_system BOOLEAN NOT NULL DEFAULT false,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CHECK (NOT is_system OR is_enabled),
    CONSTRAINT app_permissions_namespace_owner
        CHECK (is_system = (substr(permission_key, 1, 11) = 'goauth.app.'))
);

-- goauth:statement
CREATE TABLE app_authorization_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at DATETIME NOT NULL
);

-- goauth:statement
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    app_role_id TEXT,
    app_role_assignment_revision BIGINT NOT NULL DEFAULT 0 CHECK (app_role_assignment_revision >= 0),
    password_pepper_version INTEGER CHECK (password_pepper_version > 0 AND password_pepper_version <= 4294967295),
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    is_verified INTEGER NOT NULL DEFAULT 0,
    verified_at DATETIME,
    is_banned INTEGER NOT NULL DEFAULT 0,
    banned_at DATETIME,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    org_owner_count INTEGER NOT NULL DEFAULT 0,
    last_login_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (app_role_id) REFERENCES app_roles(id) ON DELETE RESTRICT
);

-- goauth:statement
CREATE INDEX idx_users_password_pepper_version ON users(password_pepper_version);

-- goauth:statement
CREATE INDEX idx_users_app_role ON users(app_role_id, id);

-- goauth:statement
CREATE TABLE app_role_permissions (
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    granted_by TEXT,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES app_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES app_permissions(id) ON DELETE RESTRICT,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
);

-- goauth:statement
CREATE INDEX idx_app_role_permissions_permission ON app_role_permissions(permission_id, role_id);


-- goauth:statement
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    refresh_token_hash TEXT NOT NULL DEFAULT '',
    prev_refresh_token_hash TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    is_revoked INTEGER NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    refresh_expires_at DATETIME,
    refresh_rotated_at DATETIME,
    created_at DATETIME NOT NULL,
    revoked_at DATETIME,
    last_active_at DATETIME NOT NULL,
    active_org_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    active_org_role TEXT,
    two_factor_verified_at DATETIME
);

-- goauth:statement
CREATE TABLE verification_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    code_verifier TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    resend_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- goauth:statement
CREATE TABLE provider_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_email TEXT NOT NULL DEFAULT '',
    provider_name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE(provider, provider_user_id)
);

-- goauth:statement
CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME,
    created_at DATETIME NOT NULL
);

-- goauth:statement
CREATE TABLE organizations (
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

-- goauth:statement
CREATE TABLE organization_members (
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    joined_at DATETIME NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

-- goauth:statement
CREATE TABLE organization_invites (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    code_hash TEXT NOT NULL UNIQUE,
    invited_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL
);

-- goauth:statement
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
-- goauth:statement
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
-- goauth:statement
CREATE INDEX idx_verification_tokens_token_hash ON verification_tokens(token_hash);
-- goauth:statement
CREATE INDEX idx_invites_email ON invites(email);
-- goauth:statement
CREATE INDEX idx_invites_code ON invites(code);
-- goauth:statement
CREATE INDEX idx_provider_accounts_user_id ON provider_accounts(user_id);
-- goauth:statement
CREATE INDEX idx_provider_accounts_provider ON provider_accounts(provider, provider_user_id);
-- goauth:statement
CREATE INDEX idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
-- goauth:statement
CREATE INDEX idx_sessions_prev_refresh_token_hash ON sessions(prev_refresh_token_hash);

-- goauth:statement
CREATE INDEX idx_org_members_user ON organization_members(user_id);
-- goauth:statement
CREATE INDEX idx_org_members_org_role ON organization_members(org_id, role);
-- goauth:statement
CREATE INDEX idx_org_members_org_joined ON organization_members(org_id, joined_at);
-- goauth:statement
CREATE INDEX idx_org_invites_org ON organization_invites(org_id);
-- goauth:statement
CREATE INDEX idx_org_invites_email ON organization_invites(email);
-- goauth:statement
CREATE INDEX idx_sessions_user_active_org ON sessions(user_id, active_org_id);

-- goauth:statement
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    success INTEGER NOT NULL DEFAULT 1,
    actor_id TEXT,
    target_id TEXT,
    session_id TEXT,
    org_id TEXT,
    ip TEXT,
    user_agent TEXT NOT NULL DEFAULT '',
    parsed_ua TEXT,
    request_id TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    metadata TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- goauth:statement
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
-- goauth:statement
CREATE INDEX idx_audit_log_actor_id ON audit_log(actor_id);
-- goauth:statement
CREATE INDEX idx_audit_log_target_id ON audit_log(target_id);
-- goauth:statement
CREATE INDEX idx_audit_log_session_id ON audit_log(session_id);
-- goauth:statement
CREATE INDEX idx_audit_log_org_id ON audit_log(org_id);
-- goauth:statement
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
-- goauth:statement
CREATE INDEX idx_audit_log_event_type_created_at ON audit_log(event_type, created_at);

-- Audit outbox — durable delivery. Ephemeral
-- companion to audit_log: a row exists only while the event still must be
-- delivered to an external sink. audit_log is insert-only and immutable;
-- all churn (claim, attempt, retry) lives here. No foreign key: orphans
-- are found by the janitor's periodic scan.
-- goauth:statement
CREATE TABLE audit_outbox (
    audit_log_id TEXT PRIMARY KEY,
    org_id TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claimed_at DATETIME,
    claim_owner TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    dead_lettered_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- goauth:statement
CREATE INDEX idx_audit_outbox_claim ON audit_outbox(priority, next_attempt_at);
-- goauth:statement
CREATE INDEX idx_audit_outbox_created_at ON audit_outbox(created_at);

-- Admin console read paths — large-tenant list / count / filter / sort.
-- goauth:statement
CREATE INDEX idx_users_role_created_at ON users (role, created_at, id);
-- goauth:statement
CREATE INDEX idx_users_updated_at ON users (updated_at, id);
-- goauth:statement
CREATE INDEX idx_users_last_login_at ON users (last_login_at);
-- goauth:statement
CREATE INDEX idx_users_banned ON users (created_at) WHERE is_banned;
-- goauth:statement
CREATE INDEX idx_users_unverified ON users (created_at) WHERE NOT is_verified;
-- goauth:statement
CREATE INDEX idx_users_two_factor ON users (created_at) WHERE two_factor_enabled;
-- Prefix search fallback ("term%"): SQLite's LIKE is case-insensitive by
-- default, so it only uses an index declared COLLATE NOCASE.
-- goauth:statement
CREATE INDEX idx_users_name_nocase ON users (name COLLATE NOCASE);
-- goauth:statement
CREATE INDEX idx_users_email_nocase ON users (email COLLATE NOCASE);

-- goauth:statement
CREATE INDEX idx_sessions_created_at ON sessions (created_at);
-- goauth:statement
CREATE INDEX idx_sessions_last_active_at ON sessions (last_active_at);
-- goauth:statement
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
-- goauth:statement
CREATE INDEX idx_sessions_ip_address ON sessions (ip_address);

-- goauth:statement
CREATE INDEX idx_invites_status_created_at ON invites (status, created_at);
-- goauth:statement
CREATE INDEX idx_invites_created_at ON invites (created_at, id);
-- goauth:statement
CREATE INDEX idx_invites_expires_at ON invites (expires_at);
-- goauth:statement
CREATE INDEX idx_invites_pending_expires ON invites (expires_at) WHERE status = 'pending';

-- goauth:statement
CREATE INDEX idx_audit_log_actor_created_at ON audit_log (actor_id, created_at);
-- goauth:statement
CREATE INDEX idx_audit_log_target_created_at ON audit_log (target_id, created_at);
