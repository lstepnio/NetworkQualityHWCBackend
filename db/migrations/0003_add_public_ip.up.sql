-- Promote network.publicIp to a hot-path column so support can filter on
-- it. The stored value is the peppered SHA-256 (PII redaction stays in
-- effect for IPs); the admin API hashes the query input before SQL
-- compares. Index is single-column, btree, supports exact-match search.
alter table certifications
    add column public_ip text;

create index certifications_public_ip_idx
    on certifications (public_ip);
