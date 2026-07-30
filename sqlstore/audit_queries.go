package sqlstore

const (
	auditLogCols = `id, event_type, severity, success, actor_id, target_id,
		session_id, org_id, ip, user_agent, parsed_ua, request_id, correlation_id, metadata, created_at`

	auditLogListQuery = `SELECT ` + auditLogCols + ` FROM audit_log`

	auditLogCountQuery = `SELECT COUNT(*) FROM audit_log`

	auditLogByIDQuery = `SELECT ` + auditLogCols + ` FROM audit_log WHERE id = $1`
)
