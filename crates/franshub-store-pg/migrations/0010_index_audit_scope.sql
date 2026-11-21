-- no-transaction
create index concurrently if not exists platform_audit_scope on platform_audit (scope, id) where scope is not null;
