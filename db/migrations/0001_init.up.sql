create table cert_config (
    config_version  text        primary key,
    schema_version  int         not null,
    document        jsonb       not null,
    is_active       bool        not null default false,
    created_at      timestamptz not null default now()
);

-- exactly one active row at a time
create unique index cert_config_active on cert_config ((true)) where is_active;

create table certifications (
    certification_id     uuid        primary key,
    device_id            uuid        not null,
    hsn                  text,
    hardware_serial      text,
    ethernet_mac         text,
    schema_version       int         not null,
    config_version       text        references cert_config(config_version),
    started_at           timestamptz not null,
    completed_at         timestamptz not null,
    achieved_tier        text        not null,
    marginal_metric      text,
    transport            text        not null,
    widevine_level       text,
    hdr_types            text[],
    display_max_height   int,
    thermal_status       text,
    download_steady_mbps numeric,
    upload_steady_mbps   numeric,
    latency_median_ms    int,
    payload              jsonb       not null,
    payload_hash         text        not null,
    received_at          timestamptz not null default now()
);

create index on certifications (device_id, completed_at desc);
create index on certifications (hsn, completed_at desc);
create index on certifications (achieved_tier, completed_at desc);
