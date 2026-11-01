-- goauth:statement
ALTER TABLE `verification_tokens` ADD COLUMN `context_hash` text NOT NULL DEFAULT '';

-- goauth:statement
ALTER TABLE `verification_tokens` ADD COLUMN `encrypted_payload` text NOT NULL DEFAULT '';

