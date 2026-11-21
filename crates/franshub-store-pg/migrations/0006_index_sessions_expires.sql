-- no-transaction
create index concurrently if not exists platform_sessions_expires on platform_sessions (expires_at);
