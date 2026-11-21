-- no-transaction
create index concurrently if not exists platform_api_tokens_parent on platform_api_tokens (parent_id) where parent_id is not null;
