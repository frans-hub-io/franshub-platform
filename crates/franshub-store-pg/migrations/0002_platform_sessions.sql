create table if not exists platform_sessions (
    key text primary key,
    name text not null,
    groups text[] not null default '{}',
    created_at timestamptz not null,
    last_seen timestamptz not null,
    expires_at timestamptz not null,
    id_token text
);

create table if not exists platform_pending_logins (
    key text primary key,
    nonce text not null,
    verifier text not null,
    return_to text not null,
    browser text not null,
    expires_at timestamptz not null
);
