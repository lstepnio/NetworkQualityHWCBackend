-- Re-add the FK. Will fail if any certifications row references a
-- config_version that doesn't exist in cert_config; clean up orphans first.
alter table certifications
    add constraint certifications_config_version_fkey
    foreign key (config_version) references cert_config(config_version);
