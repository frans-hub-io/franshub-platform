-- no-transaction
create index concurrently if not exists platform_pending_logins_expires on platform_pending_logins (expires_at);
