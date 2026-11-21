-- no-transaction
create index concurrently if not exists platform_api_tokens_expires on platform_api_tokens (expires_at);
