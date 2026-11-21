create table if not exists platform_api_tokens (
    id uuid primary key,
    name text not null,
    sha256 text not null,
    role text not null,
    scopes text[] not null default '{}',
    global boolean not null,
    description text,
    created_by text not null,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revoked boolean not null default false,
    parent_id uuid
);

create unique index if not exists platform_api_tokens_sha256 on platform_api_tokens (sha256);
create unique index if not exists platform_api_tokens_active_name on platform_api_tokens (name) where revoked_at is null;
