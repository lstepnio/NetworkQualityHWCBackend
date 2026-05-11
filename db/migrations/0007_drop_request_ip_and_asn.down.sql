-- Re-add the columns that 0007 dropped, mirroring 0006's forward shape.
-- The Go code at the reverted state doesn't read these columns, so a
-- down-migrate alone won't restore the populate-on-ingest behavior;
-- you'd need to also revert the revert.

alter table certifications
    add column request_ip_hash text,
    add column isp_asn         int,
    add column isp_name        text;

create index certifications_request_ip_hash_idx
    on certifications (request_ip_hash)
    where request_ip_hash is not null;

create index certifications_isp_asn_idx
    on certifications (isp_asn, completed_at desc)
    where isp_asn is not null;
