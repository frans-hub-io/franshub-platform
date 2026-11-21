-- no-transaction
create index concurrently if not exists platform_audit_principal on platform_audit (principal, id);
