-- goauth:statement
ALTER TABLE "verification_tokens" DROP CONSTRAINT "verification_tokens_type_check", ADD CONSTRAINT "verification_tokens_type_check" CHECK (type = ANY (ARRAY['verify_email'::text, 'reset_password'::text, 'set_password'::text, 'invite_verify'::text, 'oauth_state'::text, 'delete_account'::text, '2fa_login'::text, '2fa_enable'::text, '2fa_disable'::text])), ADD COLUMN "context_hash" character varying(64) NOT NULL DEFAULT '', ADD COLUMN "encrypted_payload" text NOT NULL DEFAULT '';

