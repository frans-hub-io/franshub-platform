-- no-transaction
create index concurrently if not exists platform_audit_action on platform_audit (action text_pattern_ops, id);
