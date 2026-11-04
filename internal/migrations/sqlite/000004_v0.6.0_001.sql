-- goauth:statement
CREATE TABLE IF NOT EXISTS email_change_requests (
    user_id TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    current_email TEXT NOT NULL,
    new_email TEXT NOT NULL,
    current_code_hash TEXT NOT NULL,
    new_code_hash TEXT NOT NULL,
    identity_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    budget_started_at BIGINT NOT NULL,
    current_sent_at BIGINT NOT NULL,
    new_sent_at BIGINT NOT NULL,
    starts INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    current_resends INTEGER NOT NULL,
    new_resends INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
