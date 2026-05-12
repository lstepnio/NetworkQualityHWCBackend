-- Per-device cert-config targeting (contract v2.2.0, issue #26).
--
-- All three columns are nullable. NULL means "no constraint on this
-- dimension"; an all-null row is the default that catches devices no
-- more-specific row matches. The Get-active-for-device resolver picks
-- the most-specific match per the algorithm in contract SPEC §4.1.1.
--
-- The selectors are sized to fit Android's Build.FINGERPRINT, which
-- typically runs ~70-120 chars; 255 is comfortable headroom.

alter table cert_config add column target_manufacturer       text;
alter table cert_config add column target_model              text;
alter table cert_config add column target_build_fingerprint  text;

-- Replace the global "exactly one active row" constraint with a
-- per-target-group one: at most one active row for each unique
-- (manufacturer, model, fingerprint) tuple. NULLS NOT DISTINCT (PG15+)
-- treats two all-null rows as a unique violation — which is what we
-- want for the default-config slot.
drop index cert_config_active;

create unique index cert_config_active_per_target
    on cert_config (target_manufacturer, target_model, target_build_fingerprint)
    nulls not distinct
    where is_active;
