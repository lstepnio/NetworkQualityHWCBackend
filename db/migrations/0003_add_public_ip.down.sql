drop index if exists certifications_public_ip_idx;
alter table certifications drop column public_ip;
