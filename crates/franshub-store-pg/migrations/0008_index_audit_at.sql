-- no-transaction
create index concurrently if not exists platform_audit_at on platform_audit (at);
