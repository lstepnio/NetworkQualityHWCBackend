drop index if exists certifications_dns_flagged_idx;
alter table certifications drop column if exists dns_preferred;
