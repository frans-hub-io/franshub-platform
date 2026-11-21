create table if not exists platform_audit (
    id bigint generated always as identity primary key,
    at timestamptz not null,
    principal text not null,
    principal_kind text,
    roles text not null,
    scope text,
    action text not null,
    detail jsonb not null
);
