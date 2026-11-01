-- goauth:statement
ALTER TABLE `verification_tokens` ADD COLUMN `context_hash` varchar(64) NOT NULL DEFAULT "", ADD COLUMN `encrypted_payload` text NOT NULL DEFAULT (_utf8mb4'');

