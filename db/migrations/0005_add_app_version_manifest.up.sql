-- Self-update manifests served by GET /v1/app/version. Each row describes
-- one published APK release. Exactly one row may be active at a time; the
-- device endpoint returns the active row's document. Older rows stay for
-- rollback (the activate path just flips the flag).
--
-- The full JSON document lives in `document`. Hot-path columns are
-- denormalized so the admin list view doesn't parse JSONB per row.
create table app_version_manifest (
    latest_version_code        integer     primary key,
    latest_version_name        text        not null,
    min_required_version_code  integer     not null check (min_required_version_code <= latest_version_code),
    published_at               timestamptz,
    document                   jsonb       not null,
    is_active                  boolean     not null default false,
    created_at                 timestamptz not null default now()
);

-- Exactly one active row at a time, same trick as cert_config_active.
create unique index app_version_manifest_active
    on app_version_manifest ((true)) where is_active;
