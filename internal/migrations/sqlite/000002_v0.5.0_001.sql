-- goauth:statement
CREATE TABLE IF NOT EXISTS org_authorization_state (
    org_id TEXT PRIMARY KEY,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at DATETIME NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- goauth:statement
CREATE TABLE IF NOT EXISTS org_roles (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    slug VARCHAR(80) NOT NULL,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    system_key VARCHAR(40),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE (org_id, id),
    UNIQUE (org_id, slug),
    UNIQUE (org_id, system_key),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CHECK (system_key IS NULL OR system_key IN ('owner', 'admin', 'member'))
);

-- goauth:statement
CREATE TABLE IF NOT EXISTS org_permissions (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    permission_key VARCHAR(160) NOT NULL,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_system BOOLEAN NOT NULL DEFAULT false,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE (org_id, id),
    UNIQUE (org_id, permission_key),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CHECK (NOT is_system OR is_enabled),
    CONSTRAINT org_permissions_namespace_owner CHECK (is_system = (substr(permission_key, 1, 11) = 'goauth.org.'))
);

-- goauth:statement
CREATE TABLE IF NOT EXISTS org_role_permissions (
    org_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    granted_by TEXT,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (org_id, role_id, permission_id),
    FOREIGN KEY (org_id, role_id) REFERENCES org_roles(org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, permission_id) REFERENCES org_permissions(org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
);

-- goauth:statement
CREATE INDEX IF NOT EXISTS idx_org_role_permissions_permission ON org_role_permissions(org_id, permission_id, role_id);

-- goauth:statement
CREATE TABLE IF NOT EXISTS org_member_roles (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES organization_members(org_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, role_id) REFERENCES org_roles(org_id, id) ON DELETE RESTRICT
);

-- goauth:statement
CREATE INDEX IF NOT EXISTS idx_org_member_roles_role ON org_member_roles(org_id, role_id);

-- goauth:statement
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_invites_org_id ON organization_invites(org_id, id);

-- goauth:statement
CREATE TABLE IF NOT EXISTS org_invite_roles (
    org_id TEXT NOT NULL,
    invite_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    role_revision BIGINT NOT NULL CHECK (role_revision > 0),
    PRIMARY KEY (org_id, invite_id),
    FOREIGN KEY (org_id, invite_id) REFERENCES organization_invites(org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, role_id) REFERENCES org_roles(org_id, id) ON DELETE RESTRICT
);

-- goauth:statement
CREATE INDEX IF NOT EXISTS idx_org_invite_roles_role ON org_invite_roles(org_id, role_id);

