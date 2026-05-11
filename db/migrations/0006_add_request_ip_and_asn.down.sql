drop index if exists certifications_isp_asn_idx;
drop index if exists certifications_request_ip_hash_idx;
alter table certifications drop column if exists isp_name;
alter table certifications drop column if exists isp_asn;
alter table certifications drop column if exists request_ip_hash;
