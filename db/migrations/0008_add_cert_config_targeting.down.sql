-- Restore the global "exactly one active row" constraint, then drop the
-- targeting columns. The unique index on (target_*) must go first
-- because a single active row that happens to carry non-null targets
-- would otherwise survive the column drop and silently become an
-- all-null active row colliding with another default. Reverting
-- through this down migration ASSUMES the operator has already
-- de-duplicated such rows.

drop index if exists cert_config_active_per_target;

create unique index cert_config_active on cert_config ((true)) where is_active;

alter table cert_config drop column if exists target_build_fingerprint;
alter table cert_config drop column if exists target_model;
alter table cert_config drop column if exists target_manufacturer;
