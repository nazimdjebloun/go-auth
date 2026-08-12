CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    name TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_verified BOOLEAN NOT NULL DEFAULT false,
    verified_at DATETIME,
    is_banned BOOLEAN NOT NULL DEFAULT false,
    banned_at DATETIME,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT false,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    org_owner_count INT NOT NULL DEFAULT 0,
    last_login_at DATETIME
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    created_by VARCHAR(36),
    owner_count INT NOT NULL DEFAULT 0,
    member_count INT NOT NULL DEFAULT 0,
    metadata JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_org_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS organization_members (
    org_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role VARCHAR(50) NOT NULL,
    joined_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
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
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_org_inv_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT fk_org_inv_user FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    refresh_token_hash TEXT NOT NULL DEFAULT '',
    prev_refresh_token_hash TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    parsed_ua TEXT,
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    expires_at DATETIME NOT NULL,
    refresh_expires_at DATETIME,
    refresh_rotated_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active_org_id VARCHAR(36),
    active_org_role VARCHAR(50),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (active_org_id) REFERENCES organizations(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS verification_tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36),
    email TEXT NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    type VARCHAR(30) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    code_verifier TEXT,
    attempts INT NOT NULL DEFAULT 0,
    resend_count INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS provider_accounts (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    avatar_url TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS invites (
    id VARCHAR(36) PRIMARY KEY,
    email TEXT NOT NULL,
    code VARCHAR(255) UNIQUE NOT NULL,
    created_by VARCHAR(36) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_verification_tokens_token_hash ON verification_tokens(token_hash);
CREATE INDEX idx_invites_email ON invites(email(255));
CREATE INDEX idx_invites_code ON invites(code(255));
CREATE INDEX idx_provider_accounts_user_id ON provider_accounts(user_id);
CREATE INDEX idx_provider_accounts_provider ON provider_accounts(provider, provider_user_id);
CREATE INDEX idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_prev_refresh_token_hash ON sessions(prev_refresh_token_hash);

CREATE INDEX idx_org_members_user ON organization_members(user_id);
CREATE INDEX idx_org_members_org_role ON organization_members(org_id, role);
CREATE INDEX idx_org_invites_org ON organization_invites(org_id);
CREATE INDEX idx_org_invites_email ON organization_invites(email);
CREATE INDEX idx_sessions_user_active_org ON sessions(user_id, active_org_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id VARCHAR(64) PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'info',
    success BOOLEAN NOT NULL DEFAULT TRUE,
    actor_id VARCHAR(64),
    target_id VARCHAR(64),
    session_id VARCHAR(64),
    org_id VARCHAR(64),
    ip VARCHAR(45),
    user_agent TEXT NOT NULL,
    parsed_ua JSON,
    request_id VARCHAR(64) NOT NULL DEFAULT '',
    correlation_id VARCHAR(64) NOT NULL DEFAULT '',
    metadata JSON,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX idx_audit_log_target_id ON audit_log(target_id);
CREATE INDEX idx_audit_log_session_id ON audit_log(session_id);
CREATE INDEX idx_audit_log_org_id ON audit_log(org_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
