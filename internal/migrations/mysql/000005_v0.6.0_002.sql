-- goauth:statement
ALTER TABLE sessions ADD COLUMN cache_version VARCHAR(36) NOT NULL DEFAULT 'legacy';
-- goauth:statement
ALTER TABLE verification_tokens ADD COLUMN cache_version VARCHAR(36) NOT NULL DEFAULT 'legacy';
